#!/usr/bin/env python3
"""
xray-checker-statuspage probe agent (TLS handshake, MVP)

Что делает:
  1. Раз в INTERVAL секунд тянет список таргетов с сервера статус-страницы
     (GET /api/probe/targets под X-Probe-Token) — сервер сам парсит
     подписку и отдаёт уже разобранные {name, host, port, sni}.
  2. Для каждого таргета делает TCP+TLS handshake к host:port с правильным SNI.
  3. Отправляет результаты на STATUSPAGE_URL/api/probe/report.

Почему агент НЕ тянет подписку напрямую: подписка обычно лежит за VPN,
агенту в зоне блокировки она не доступна без туннеля. Сервер в облаке
тянет её и отдаёт уже распарсенной. Бонусом — секретный URL подписки не
светится на устройстве пользователя.

В начале каждого цикла проверяет свою геолокацию (ifconfig.co/country-iso).
Если страна не совпадает с EXPECT_COUNTRY, в лог пишется warning — но
репорт всё равно уходит (только с пометкой `geo` для UI).

Конфиг — через переменные окружения:
  STATUSPAGE_URL     обязательно   куда репортить (https://status.example.com)
  PROBE_TOKEN        обязательно   токен пробника (выдаётся при регистрации)
  INTERVAL           60            секунды между циклами
  TIMEOUT            10            таймаут TCP+TLS handshake (сек)
  EXPECT_COUNTRY     RU            ожидаемая страна пробника
  GEO_CHECK_URL      https://ifconfig.co/country-iso

Запуск:
  STATUSPAGE_URL=https://... PROBE_TOKEN=... python3 agent.py
"""
import json
import os
import socket
import ssl
import sys
import time
import urllib.request

STATUSPAGE_URL = os.environ.get("STATUSPAGE_URL", "").rstrip("/")
PROBE_TOKEN = os.environ.get("PROBE_TOKEN", "").strip()
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


def fetch_targets():
    """GET /api/probe/targets с X-Probe-Token. Возвращает список {name,host,port,sni}."""
    req = urllib.request.Request(
        STATUSPAGE_URL + "/api/probe/targets",
        headers={"User-Agent": USER_AGENT, "X-Probe-Token": PROBE_TOKEN})
    with urllib.request.urlopen(req, timeout=20) as r:
        data = json.loads(r.read().decode("utf-8", "ignore"))
    return data.get("targets") or []


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
        targets = fetch_targets()
    except Exception as e:
        err("targets fetch failed:", e,
            "(возможно PROBE_SUBSCRIPTION_URL не задан на сервере?)")
        return
    if not targets:
        err("сервер вернул пустой список таргетов")
        return
    results = []
    n_ok = 0
    for t in targets:
        host = t.get("host"); port = int(t.get("port") or 443)
        sni = t.get("sni") or host; name = t.get("name") or host
        if not host:
            continue
        ok, rtt, errmsg = tls_probe(host, port, sni)
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
