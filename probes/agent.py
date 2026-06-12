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
# Этап 2: после короткого fl=-теста качаем чуть больше PROBE_BULK_MIN_BYTES
# через тот же прокси. У ряда российских провайдеров DPI пропускает
# первые ~16KB через cloudflare-сервера, а потом рвёт соединение — короткий
# trace через chrome-fp проходит, реальный трафик нет. Big-download ловит это.
PROBE_BULK_URL = os.environ.get(
    "PROBE_BULK_URL", "http://speed.cloudflare.com/__down?bytes=65536")
PROBE_BULK_MIN_BYTES = int(os.environ.get("PROBE_BULK_MIN_BYTES", "65000"))
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


def _parse_trace_ip(body):
    """Парсит поле 'ip=' из ответа cloudflare /cdn-cgi/trace."""
    for line in body.splitlines():
        if line.startswith("ip="):
            return line[3:].strip()
    return ""


def fetch_direct_ip():
    """Прямой IP без туннеля — baseline для сравнения с probe-ip.
    Если probe через xray вернёт тот же ip — туннель не использовался
    (xray мог упасть в direct fallback, или DPI пропустил голый запрос)."""
    try:
        req = urllib.request.Request(PROBE_TEST_URL,
                                     headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=8) as r:
            body = r.read(2048).decode("utf-8", "ignore")
        return _parse_trace_ip(body)
    except Exception as e:
        err("direct-ip probe failed: %s" % str(e)[:120])
        return ""


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


_xray_checked = {"bin": "", "ok": False, "ver": ""}


def _check_xray_health(xray_bin):
    """Один раз за процесс проверяем что бинарь действительно запускается.
    Если упадёт здесь — никаких proba не делаем (всё равно ничего не выйдет)."""
    if _xray_checked["bin"] == xray_bin:
        return _xray_checked["ok"]
    _xray_checked["bin"] = xray_bin
    _xray_checked["ok"] = False
    _xray_checked["ver"] = ""
    log("xray check: bin=%s, exists=%s, executable=%s"
        % (xray_bin, os.path.isfile(xray_bin), os.access(xray_bin, os.X_OK)))
    try:
        r = subprocess.run([xray_bin, "version"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=5)
        out = (r.stdout or b"").decode("utf-8", "ignore").strip()
        errtxt = (r.stderr or b"").decode("utf-8", "ignore").strip()
        log("xray version rc=%d stdout=%r stderr=%r"
            % (r.returncode, out[:200], errtxt[:200]))
        if r.returncode == 0 and out:
            _xray_checked["ok"] = True
            _xray_checked["ver"] = out.splitlines()[0][:120]
            return True
        err("xray version exited with rc=%d (см. лог выше)" % r.returncode)
    except subprocess.TimeoutExpired:
        err("xray version timeout — бинарь подвис")
    except FileNotFoundError as e:
        err("xray бинарь не найден при запуске: %s" % e)
    except PermissionError as e:
        err("xray бинарь не исполняемый: %s" % e)
    except OSError as e:
        # macOS: Errno 86 «Bad CPU type in executable» = не та архитектура.
        # Errno 13 = permission. Errno 8 = Exec format error.
        err("xray бинарь не запускается (OSError %s): %s" % (e.errno, e))
    return False


def _free_port():
    """Случайный свободный TCP-порт на 127.0.0.1."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _wait_port_or_exit(proc, port, timeout):
    """Ждёт пока порт начнёт принимать соединения ИЛИ пока процесс не завершится
    (что бывает раньше). Возвращает ('ok'|'exited'|'timeout', elapsed_ms).
    Если процесс exited — _wait не тратит время впустую."""
    t0 = time.monotonic()
    deadline = t0 + timeout
    while time.monotonic() < deadline:
        rc = proc.poll() if proc is not None else None
        if rc is not None:
            return "exited", int((time.monotonic() - t0) * 1000)
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.3)
            s.close()
            return "ok", int((time.monotonic() - t0) * 1000)
        except OSError:
            time.sleep(0.1)
    return "timeout", int((time.monotonic() - t0) * 1000)


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


def xray_probe(xray_bin, t, direct_ip=""):
    """Запускает xray-core с конфигом одного таргета, дёргает PROBE_TEST_URL
    через локальный HTTP-proxy. ok=True если в ответе есть PROBE_TEST_MARKER
    И поле ip= отличается от direct_ip (т.е. трафик реально пошёл через VPN,
    а не через direct fallback). После теста процесс гасится."""
    if not (t.get("uuid") and t.get("host")):
        return False, 0, "bad target"
    port = _free_port()
    cfg = _build_xray_config(t, port)
    cfg_tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    # stdout/stderr xray-core → отдельные файлы (PIPE.read блокирует
    # неконтролируемо, а нам надо читать в любой момент).
    out_log = tempfile.NamedTemporaryFile("w+b", suffix=".out", delete=False)
    err_log = tempfile.NamedTemporaryFile("w+b", suffix=".err", delete=False)
    proc = None
    tname = (t.get("name") or t.get("host") or "?")[:60]

    def _read_log(f):
        try:
            f.flush(); f.seek(0)
            return f.read().decode("utf-8", "ignore").strip()
        except Exception:
            return ""

    def _dump_xray_io(prefix):
        out_text = _read_log(out_log)
        err_text = _read_log(err_log)
        if out_text:
            err("%s [stdout/%s]: %s" % (prefix, tname, out_text[:800]))
        if err_text:
            err("%s [stderr/%s]: %s" % (prefix, tname, err_text[:800]))
        if not out_text and not err_text:
            err("%s [silent/%s]: xray не написал НИЧЕГО в stdout/stderr"
                % (prefix, tname))
        return out_text, err_text

    try:
        json.dump(cfg, cfg_tmp); cfg_tmp.close()
        if os.environ.get("XRAY_DEBUG") == "1":
            # Сохраняем конфиг в HOME, чтобы можно было запустить xray вручную.
            dbg_path = os.path.expanduser("~/.xrs-probe/last-xray-config.json")
            try:
                with open(dbg_path, "w") as f:
                    json.dump(cfg, f, indent=2)
                err("debug: конфиг сохранён в %s" % dbg_path)
            except Exception:
                pass
        t0 = time.monotonic()
        try:
            proc = subprocess.Popen(
                [xray_bin, "run", "-c", cfg_tmp.name],
                stdout=out_log,
                stderr=err_log)
        except (FileNotFoundError, PermissionError, OSError) as e:
            err("xray Popen failed (%s/%s): %s"
                % (type(e).__name__, getattr(e, "errno", "?"), e))
            return False, 0, "xray run failed: " + str(e)[:120]
        status, elapsed = _wait_port_or_exit(proc, port, timeout=min(TIMEOUT, 3.0))
        if status != "ok":
            rc = proc.poll() if proc else None
            # Подождём ещё чуть-чуть, чтобы xray дописал ошибку.
            try:
                proc.terminate(); proc.wait(timeout=1.5)
            except Exception:
                pass
            time.sleep(0.25)
            out_text, err_text = _dump_xray_io(
                "xray probe FAIL status=%s elapsed=%dms rc=%s" % (status, elapsed, rc))
            # Берём первую информативную строку для err отчёта.
            tail = (err_text or out_text or "").strip().splitlines()
            last_line = next((s.strip() for s in reversed(tail)
                              if s.strip() and not s.strip().startswith("{")), "")
            if last_line:
                return False, 0, last_line[:200]
            return False, 0, ("xray %s (rc=%s, %dms, без вывода — Gatekeeper? "
                              "права? XRAY_DEBUG=1 для конфига)"
                              % (status, rc, elapsed))
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
            if PROBE_TEST_MARKER not in body:
                return False, 0, "ответ есть, но без маркера '%s'" % PROBE_TEST_MARKER
            # Проверка 1: ip из ответа должен отличаться от прямого. Если
            # совпадает — xray молча упал в direct (или DPI пропустил голый).
            tunnel_ip = _parse_trace_ip(body)
            if direct_ip and tunnel_ip and tunnel_ip == direct_ip:
                return False, 0, ("туннель не использовался: ip совпадает "
                                  "с прямым (%s)" % tunnel_ip)
            # Проверка 2: скачиваем PROBE_BULK_MIN_BYTES+ байт через тот же
            # прокси. Многие DPI пропускают первые ~16KB к cloudflare и
            # рвут поток позже. Если читаем меньше — туннель «вроде живой,
            # но реально нерабочий».
            try:
                req2 = urllib.request.Request(
                    PROBE_BULK_URL, headers={"User-Agent": USER_AGENT})
                with opener.open(req2, timeout=min(TIMEOUT, 10.0)) as r2:
                    received = 0
                    while True:
                        chunk = r2.read(16384)
                        if not chunk:
                            break
                        received += len(chunk)
                        if received >= PROBE_BULK_MIN_BYTES * 2:
                            break  # достаточно
                if received < PROBE_BULK_MIN_BYTES:
                    return False, 0, ("обрыв туннеля (DPI?): получено "
                                      "%d/%d байт" % (received, PROBE_BULK_MIN_BYTES))
            except urllib.error.URLError as e:
                return False, 0, "обрыв при bulk: " + str(e.reason)[:120]
            except (socket.timeout, OSError) as e:
                return False, 0, "обрыв при bulk: " + type(e).__name__
            return True, rtt, ""
        except urllib.error.URLError as e:
            # Туннель не открылся — внутри xray может быть лог почему.
            _dump_xray_io("xray probe URLError")
            return False, 0, "туннель: " + str(e.reason)[:140]
        except (socket.timeout, OSError) as e:
            _dump_xray_io("xray probe %s" % type(e).__name__)
            return False, 0, type(e).__name__ + ": " + str(e)[:140]
    finally:
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                try: proc.kill()
                except Exception: pass
        for f in (out_log, err_log):
            try: f.close()
            except Exception: pass
        if os.environ.get("XRAY_DEBUG") != "1":
            for fp in (cfg_tmp.name, out_log.name, err_log.name):
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
        results = [{"name": t.get("name") or t.get("host") or "?", "ok": False,
                    "rtt": 0, "err": "xray-core not found on probe device"}
                   for t in targets]
        try:
            report(geo, results)
        except Exception as e:
            err("report failed:", e)
        return
    if not _check_xray_health(xray_bin):
        # Бинарь есть, но не запускается. Гасим цикл с явной ошибкой —
        # дальнейшие probe всё равно упадут. Реальная причина в логе выше.
        results = [{"name": t.get("name") or t.get("host") or "?", "ok": False,
                    "rtt": 0,
                    "err": "xray бинарь не запускается на устройстве (см. agent.log)"}
                   for t in targets]
        try:
            report(geo, results)
        except Exception as e:
            err("report failed:", e)
        return
    direct_ip = fetch_direct_ip()
    log("targets=%d, xray=%s, direct_ip=%s"
        % (len(targets), _xray_checked["ver"] or "?", direct_ip or "?"))
    results = []
    n_ok = 0
    for t in targets:
        name = t.get("name") or t.get("host") or "?"
        try:
            ok, rtt, errmsg = xray_probe(xray_bin, t, direct_ip)
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
