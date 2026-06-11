#!/usr/bin/env python3
"""
xray-checker-statuspage probe agent (TLS handshake, MVP)

Что делает:
  1. Раз в INTERVAL секунд тянет подписку (SUBSCRIPTION_URL),
  2. Парсит из неё все vless:// конфиги (поддержка REALITY/TLS),
  3. Для каждого делает TCP+TLS handshake к host:port с правильным SNI,
  4. Отправляет результаты на STATUSPAGE_URL/api/probe/report.

При каждом цикле сначала проверяет, в какой стране сейчас сидит агент
(ifconfig.co/country-iso) — если страна не совпадает с EXPECT_COUNTRY,
репорт уходит с пометкой и сервер его рисует серым «нет данных» (зависит
от настройки сервера; на MVP — просто помечаем в поле geo).

Конфиг — через переменные окружения:
  STATUSPAGE_URL     обязательно   куда репортить (https://status.example.com)
  PROBE_TOKEN        обязательно   токен пробника (выдаётся при регистрации)
  SUBSCRIPTION_URL   обязательно   откуда тянуть конфиги для теста
  INTERVAL           60            секунды между циклами
  TIMEOUT            10            таймаут TCP+TLS handshake (сек)
  EXPECT_COUNTRY     RU            ожидаемая страна пробника
  GEO_CHECK_URL      https://ifconfig.co/country-iso

Запуск:
  STATUSPAGE_URL=https://... PROBE_TOKEN=... SUBSCRIPTION_URL=... \\
    python3 agent.py

При нормальной работе пишет одну строку в stdout на цикл: «cycle: N тестов,
M ok». Ошибки уходят в stderr. Запускать через launchd на macOS — см.
install-macos.sh.
"""
import base64
import json
import os
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.request

STATUSPAGE_URL = os.environ.get("STATUSPAGE_URL", "").rstrip("/")
PROBE_TOKEN = os.environ.get("PROBE_TOKEN", "").strip()
SUBSCRIPTION_URL = os.environ.get("SUBSCRIPTION_URL", "").strip()
INTERVAL = int(os.environ.get("INTERVAL", "60"))
TIMEOUT = float(os.environ.get("TIMEOUT", "10"))
EXPECT_COUNTRY = os.environ.get("EXPECT_COUNTRY", "RU").strip().upper()
GEO_CHECK_URL = os.environ.get("GEO_CHECK_URL", "https://ifconfig.co/country-iso")
USER_AGENT = "xrs-probe/0.1 (+macos)"


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


def fetch_subscription():
    raw = http_get(SUBSCRIPTION_URL, timeout=20)
    text = raw.decode("utf-8", "ignore").strip()
    # Подписки обычно — base64-encoded список строк-URL. Пробуем декодировать.
    if "vless://" not in text and "vmess://" not in text and "trojan://" not in text:
        try:
            padded = text + "=" * (-len(text) % 4)
            decoded = base64.b64decode(padded).decode("utf-8", "ignore")
            if "vless://" in decoded or "vmess://" in decoded:
                text = decoded
        except Exception:
            pass
    return [line.strip() for line in text.splitlines() if line.strip()]


def parse_vless(url):
    """Парсит vless://uuid@host:port?...#name → dict с host/port/sni/name или None."""
    if not url.startswith("vless://"):
        return None
    try:
        p = urllib.parse.urlparse(url)
        host = p.hostname
        port = p.port or 443
        if not host:
            return None
        q = urllib.parse.parse_qs(p.query)
        sni = (q.get("sni") or q.get("peer") or [host])[0]
        # fragment = name; URL-encoded UTF-8
        name = urllib.parse.unquote(p.fragment or "").strip()
        security = (q.get("security") or [""])[0]
        return {
            "host": host, "port": int(port),
            "sni": sni, "name": name or host,
            "security": security,
        }
    except Exception as e:
        err("parse fail:", url[:60], e)
        return None


def tls_probe(host, port, sni):
    """TCP+TLS handshake. Сертификат не верифицируем (REALITY/самоподписи).
    Возвращает (ok, rtt_ms, err_str)."""
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # ALPN h2/http1.1 — как у chrome, чтобы выглядеть стандартно
        try:
            ctx.set_alpn_protocols(["h2", "http/1.1"])
        except (NotImplementedError, AttributeError):
            pass
        tls = ctx.wrap_socket(sock, server_hostname=sni)
        rtt = int((time.monotonic() - t0) * 1000)
        try:
            tls.close()
        except Exception:
            pass
        return True, rtt, ""
    except (socket.timeout, ssl.SSLError, ConnectionResetError,
            ConnectionRefusedError, OSError) as e:
        try:
            if sock:
                sock.close()
        except Exception:
            pass
        return False, 0, type(e).__name__ + ": " + str(e)[:160]
    except Exception as e:
        try:
            if sock:
                sock.close()
        except Exception:
            pass
        return False, 0, "Exception: " + str(e)[:160]


def report(geo, results):
    body = json.dumps({"geo": geo.lower(), "results": results},
                      ensure_ascii=False).encode("utf-8")
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
    if EXPECT_COUNTRY and geo and geo != EXPECT_COUNTRY:
        log("warn: geo=%s, ожидалось %s — возможно включён VPN на этом устройстве"
            % (geo, EXPECT_COUNTRY))
    try:
        lines = fetch_subscription()
    except Exception as e:
        err("subscription fetch failed:", e)
        return
    targets = []
    for line in lines:
        v = parse_vless(line)
        if v:
            targets.append(v)
    if not targets:
        err("в подписке не найдено vless-конфигов (для MVP поддерживается только vless)")
        return
    results = []
    n_ok = 0
    for t in targets:
        ok, rtt, errmsg = tls_probe(t["host"], t["port"], t["sni"])
        if ok:
            n_ok += 1
        results.append({"name": t["name"], "ok": ok, "rtt": rtt, "err": errmsg})
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
        ("SUBSCRIPTION_URL", SUBSCRIPTION_URL),
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
