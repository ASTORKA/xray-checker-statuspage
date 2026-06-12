#!/usr/bin/env python3
"""
xray-checker-statuspage probe agent (xray-core)

Что делает:
  1. Раз в INTERVAL секунд проверяет свою геолокацию (ifconfig.co/country-iso).
     Если geo != EXPECT_COUNTRY → на устройстве включён VPN, пробы через туннель
     бессмысленны — шлёт серверу {vpn:true,results:[]} и пропускает цикл.
  2. Иначе тянет список таргетов с сервера (GET /api/probe/targets под
     X-Probe-Token) — сервер сам парсит подписку и отдаёт разобранные
     {name, host, port, sni, uuid, security, pbk, sid, fp, flow, type, ...}.
  3. Для каждого таргета поднимает xray-core с outbound из этого таргета и
     локальным HTTP-inbound. Через прокси дёргает http://cp.cloudflare.com/
     cdn-cgi/trace. Если в ответе есть cloudflare-маркер «fl=» — туннель работает.
     После каждого теста xray-core тушится.
  4. Отправляет результаты на STATUSPAGE_URL/api/probe/report.

Почему именно xray-core, а не «свой» TLS-handshake:
- REALITY-сервер при невалидном клиенте делает fallback на легитимный dest
  (microsoft.com и т.п.). TLS handshake пройдёт успешно — UI покажет «ok»,
  хотя реального туннеля нет.
- Python `ssl` использует свой fingerprint, не тот, что указан в `fp=` строки
  подписки. DPI, рубящий конкретный fingerprint, пропустит наши пакеты.
- xray-core применяет ровно тот fp/pbk/sid/flow, что в подписке, и проверяет
  туннель целиком — это единственный честный probe.

Почему агент НЕ тянет подписку напрямую: подписка обычно лежит за VPN, агенту
в зоне блокировки она не доступна. Сервер в облаке тянет её и отдаёт уже
распарсенной. Бонус — секретный URL подписки не светится на устройстве.

Конфиг — через переменные окружения:
  STATUSPAGE_URL     обязательно   куда репортить (https://status.example.com)
  PROBE_TOKEN        обязательно   токен пробника (выдаётся при регистрации)
  INTERVAL           60            секунды между циклами
  TIMEOUT            10            таймаут одного теста (старт xray + HTTP)
  EXPECT_COUNTRY     RU            ожидаемая страна пробника
  GEO_CHECK_URL      https://ifconfig.co/country-iso
  XRAY_BIN           — явный путь к бинарю xray-core; если пусто, ищет в
                     ~/.xrs-probe/xray[.exe], потом в PATH.
  PROBE_TEST_URL     http://cp.cloudflare.com/cdn-cgi/trace
  PROBE_TEST_MARKER  fl=            подстрока, которая должна быть в ответе

Запуск:
  STATUSPAGE_URL=https://... PROBE_TOKEN=... python3 agent.py
"""
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

STATUSPAGE_URL = os.environ.get("STATUSPAGE_URL", "").rstrip("/")
PROBE_TOKEN = os.environ.get("PROBE_TOKEN", "").strip()
INTERVAL = int(os.environ.get("INTERVAL", "60"))
TIMEOUT = float(os.environ.get("TIMEOUT", "10"))
EXPECT_COUNTRY = os.environ.get("EXPECT_COUNTRY", "RU").strip().upper()
GEO_CHECK_URL = os.environ.get("GEO_CHECK_URL", "https://ifconfig.co/country-iso")
XRAY_BIN_ENV = os.environ.get("XRAY_BIN", "").strip()
PROBE_TEST_URL = os.environ.get("PROBE_TEST_URL",
                                "http://cp.cloudflare.com/cdn-cgi/trace")
PROBE_TEST_MARKER = os.environ.get("PROBE_TEST_MARKER", "fl=")
USER_AGENT = "xrs-probe/0.2"


def log(*a):
    print("[probe]", *a, file=sys.stdout, flush=True)


def err(*a):
    print("[probe:err]", *a, file=sys.stderr, flush=True)


def http_get(url, timeout=10, insecure=False):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    ctx = None
    if insecure and url.startswith("https://"):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return r.read()


def fetch_geo():
    """Возвращает двухбуквенный код страны нашего IP (e.g. 'RU') или '' если не удалось.
    На macOS без установленных CA-сертификатов системный TLS-verify падает —
    делаем fallback на unverified context (для geo-check это безопасно, нам не
    нужна гарантия подлинности этого ответа)."""
    for insecure in (False, True):
        try:
            data = http_get(GEO_CHECK_URL, timeout=8,
                            insecure=insecure).decode("utf-8", "ignore").strip().upper()
            return data[:2] if data else ""
        except Exception as e:
            if insecure:
                err("geo check failed:", e)
                return ""


def fetch_targets():
    """GET /api/probe/targets с X-Probe-Token. Возвращает список {name,host,port,sni}."""
    url = STATUSPAGE_URL + "/api/probe/targets"
    req = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "X-Probe-Token": PROBE_TOKEN})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read().decode("utf-8", "ignore"))
        return data.get("targets") or []
    except urllib.error.HTTPError as e:
        if e.code == 503:
            raise RuntimeError(
                "сервер: PROBE_SUBSCRIPTION_URL не задан (или пуст). "
                "Добавь его в docker-compose.yml в env statuspage и перезапусти.")
        if e.code == 401:
            raise RuntimeError(
                "сервер: токен пробника отвергнут. Возможно, пробника удалили — "
                "переустанови через install-macos.sh.")
        raise RuntimeError("сервер ответил HTTP %d" % e.code)
    except urllib.error.URLError as e:
        raise RuntimeError(
            "сеть: не достучаться до %s — %s. Проверь, что STATUSPAGE_URL "
            "правильный (открой в браузере — должна быть видна статус-страница)."
            % (STATUSPAGE_URL, e.reason))


def _find_xray():
    """Бинарь xray-core: явный XRAY_BIN > ~/.xrs-probe/xray[.exe] > PATH."""
    if XRAY_BIN_ENV and os.path.isfile(XRAY_BIN_ENV):
        return XRAY_BIN_ENV
    home = os.path.expanduser("~")
    name = "xray.exe" if os.name == "nt" else "xray"
    local = os.path.join(home, ".xrs-probe", name)
    if os.path.isfile(local) and os.access(local, os.X_OK):
        return local
    return shutil.which("xray") or shutil.which(name) or ""


def _free_port():
    """Случайный свободный TCP-порт на 127.0.0.1."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _wait_port(port, timeout):
    """Ждёт пока порт начнёт принимать соединения. True/False."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.3)
            s.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def _stream_settings(t):
    """streamSettings для outbound — собираем по полям таргета."""
    net = (t.get("type") or "tcp").lower()
    sec = (t.get("security") or "").lower() or "none"
    ss = {"network": net, "security": sec}
    sni = t.get("sni") or t.get("host")
    fp = t.get("fp") or "chrome"
    if sec == "reality":
        ss["realitySettings"] = {
            "serverName": sni,
            "fingerprint": fp,
            "publicKey": t.get("pbk") or "",
            "shortId": t.get("sid") or "",
            "spiderX": "/",
        }
    elif sec == "tls":
        tls_cfg = {"serverName": sni, "fingerprint": fp,
                   "allowInsecure": False}
        alpn = (t.get("alpn") or "").strip()
        if alpn:
            tls_cfg["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()]
        ss["tlsSettings"] = tls_cfg
    if net == "ws":
        ss["wsSettings"] = {
            "path": t.get("path") or "/",
            "headers": {"Host": t.get("host_header") or sni},
        }
    elif net == "grpc":
        ss["grpcSettings"] = {"serviceName": t.get("service_name") or ""}
    elif net == "tcp" and (t.get("header_type") or "") == "http":
        ss["tcpSettings"] = {"header": {
            "type": "http",
            "request": {
                "path": [t.get("path") or "/"],
                "headers": {"Host": [t.get("host_header") or sni]},
            },
        }}
    return ss


def _build_xray_config(t, http_port):
    """xray-конфиг: один HTTP-inbound на 127.0.0.1:http_port + один outbound
    из таргета. Через этот inbound HTTP-клиент попадает в туннель.
    Пустые опциональные поля выкидываем — xray-core строгий и часто отвергает
    конфиг с явно пустыми строками вместо отсутствующего ключа."""
    user = {"id": t["uuid"], "encryption": "none"}
    flow = (t.get("flow") or "").strip()
    if flow:
        user["flow"] = flow
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "in",
            "listen": "127.0.0.1",
            "port": http_port,
            "protocol": "http",
            "settings": {"timeout": 60},
        }],
        "outbounds": [{
            "tag": "out",
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": t["host"],
                "port": int(t["port"]),
                "users": [user],
            }]},
            "streamSettings": _stream_settings(t),
        }],
    }


def xray_probe(xray_bin, t):
    """Запускает xray-core с конфигом одного таргета, дёргает PROBE_TEST_URL
    через локальный HTTP-proxy. ok=True если в ответе есть PROBE_TEST_MARKER.
    После теста процесс гасится."""
    if not (t.get("uuid") and t.get("host")):
        return False, 0, "bad target"
    port = _free_port()
    cfg = _build_xray_config(t, port)
    tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    # stderr xray-core → отдельный файл: PIPE+read блокирует, а нам нужно
    # уметь читать stderr в любой момент (для диагностики).
    err_log = tempfile.NamedTemporaryFile("w+b", suffix=".log", delete=False)
    proc = None

    def _read_stderr():
        try:
            err_log.flush(); err_log.seek(0)
            return err_log.read().decode("utf-8", "ignore").strip()
        except Exception:
            return ""

    try:
        json.dump(cfg, tmp); tmp.close()
        t0 = time.monotonic()
        try:
            proc = subprocess.Popen(
                [xray_bin, "run", "-c", tmp.name],
                stdout=subprocess.DEVNULL,
                stderr=err_log)
        except (FileNotFoundError, PermissionError) as e:
            return False, 0, "xray run failed: " + str(e)[:120]
        if not _wait_port(port, timeout=min(TIMEOUT, 3.0)):
            # xray не поднялся (или упал). Читаем stderr — там реальная
            # причина (битый конфиг, отсутствующий ключ REALITY, etc.).
            try:
                proc.terminate(); proc.wait(timeout=1.5)
            except Exception:
                pass
            time.sleep(0.2)  # дать xray дописать сообщения об ошибке
            stderr_text = _read_stderr()
            # В лог агента — полный stderr, в err отчёта — последняя строка.
            if stderr_text:
                err("xray stderr (target=%s): %s"
                    % (t.get("name") or t.get("host"), stderr_text[:800]))
                last_line = stderr_text.strip().splitlines()[-1].strip()
                return False, 0, last_line[:200] or "xray exited без сообщения"
            return False, 0, ("xray не открыл прокси-порт за 3с "
                              "(stderr пуст; проверь права/Gatekeeper)")
        try:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({
                    "http": "http://127.0.0.1:%d" % port,
                    "https": "http://127.0.0.1:%d" % port,
                }))
            req = urllib.request.Request(
                PROBE_TEST_URL, headers={"User-Agent": USER_AGENT})
            r = opener.open(req, timeout=min(TIMEOUT, 8.0))
            body = r.read(2048).decode("utf-8", "ignore")
            rtt = int((time.monotonic() - t0) * 1000)
            if PROBE_TEST_MARKER in body:
                return True, rtt, ""
            return False, 0, "ответ есть, но без маркера '%s'" % PROBE_TEST_MARKER
        except urllib.error.URLError as e:
            # Если туннель не открылся — внутри xray может быть лог почему.
            stderr_text = _read_stderr()
            if stderr_text:
                err("xray stderr во время probe (target=%s): %s"
                    % (t.get("name") or t.get("host"), stderr_text[-400:]))
            return False, 0, "туннель: " + str(e.reason)[:140]
        except (socket.timeout, OSError) as e:
            return False, 0, type(e).__name__ + ": " + str(e)[:140]
    finally:
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                try: proc.kill()
                except Exception: pass
        try:
            err_log.close()
        except Exception:
            pass
        for fp in (tmp.name, err_log.name):
            try: os.unlink(fp)
            except Exception: pass


def report(geo, results, vpn=False):
    payload = {"geo": geo.lower(), "results": results}
    if vpn:
        # Серверу сигналим, что цикл пропущен из-за активного VPN — он
        # запишет VPN-период, а на графике эти минуты будут отмечены серым.
        payload["vpn"] = True
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        STATUSPAGE_URL + "/api/probe/report",
        data=body, method="POST",
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "X-Probe-Token": PROBE_TOKEN,
            "User-Agent": USER_AGENT,
        })
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode("utf-8", "ignore"))


def one_cycle():
    geo = fetch_geo()
    # VPN-страж: если geo определилось и НЕ совпадает с EXPECT_COUNTRY — на
    # устройстве включён VPN. Пробы через туннель бессмысленны (получим
    # ложное «всё работает»), поэтому НЕ запускаем их. Но отчёт всё равно
    # шлём — с пометкой vpn=true: сервер запишет это как VPN-период и на
    # графике эти минуты будут серыми, а не «нет данных».
    if EXPECT_COUNTRY and geo and geo != EXPECT_COUNTRY:
        log("VPN detected: geo=%s, ожидалось %s — отмечаем VPN-период, пробы пропущены"
            % (geo, EXPECT_COUNTRY))
        try:
            report(geo, [], vpn=True)
        except Exception as e:
            err("vpn-mark report failed:", e)
        return
    try:
        targets = fetch_targets()
    except Exception as e:
        err("targets fetch failed:", e)
        return
    if not targets:
        err("сервер вернул пустой список таргетов")
        return
    xray_bin = _find_xray()
    if not xray_bin:
        err("xray-core не найден. Поставь бинарь в ~/.xrs-probe/xray "
            "(на Windows xray.exe) или укажи XRAY_BIN=/path/to/xray. "
            "Без него агент не может валидировать конфиги.")
        # Шлём пустой отчёт с явной ошибкой по каждому таргету, чтобы UI
        # не молчал, а админ увидел проблему.
        results = [{"name": t.get("name") or t.get("host") or "?", "ok": False,
                    "rtt": 0, "err": "xray-core not found on probe device"}
                   for t in targets]
        try:
            report(geo, results)
        except Exception as e:
            err("report failed:", e)
        return
    results = []
    n_ok = 0
    for t in targets:
        name = t.get("name") or t.get("host") or "?"
        try:
            ok, rtt, errmsg = xray_probe(xray_bin, t)
        except Exception as e:
            ok, rtt, errmsg = False, 0, "probe crash: " + str(e)[:140]
        if ok:
            n_ok += 1
        results.append({"name": name, "ok": ok, "rtt": rtt, "err": errmsg})
    try:
        resp = report(geo, results)
        log("cycle: %d тестов, %d ok, geo=%s, saved=%s"
            % (len(results), n_ok, geo, resp.get("saved")))
    except Exception as e:
        err("report failed:", e)


def main():
    missing = [n for n, v in [
        ("STATUSPAGE_URL", STATUSPAGE_URL),
        ("PROBE_TOKEN", PROBE_TOKEN),
    ] if not v]
    if missing:
        err("обязательные env пусты:", ", ".join(missing))
        sys.exit(2)
    log("start: interval=%ds, target=%s, geo-expected=%s"
        % (INTERVAL, STATUSPAGE_URL, EXPECT_COUNTRY))
    while True:
        try:
            one_cycle()
        except Exception as e:
            err("unexpected:", e)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
