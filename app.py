import gzip
import json
import os
import re
import sqlite3
import threading
import time
import urllib.request
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None

CHECKER_URL = os.environ.get("CHECKER_URL", "http://xray-checker:2112").rstrip("/")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "60"))
DAYS = int(os.environ.get("DAYS", "30"))
SAMPLE_RETAIN_DAYS = int(os.environ.get("SAMPLE_RETAIN_DAYS", str(DAYS + 1)))
DB_PATH = os.environ.get("DB_PATH", "/data/status.db")
PORT = int(os.environ.get("PORT", "8080"))
TITLE = os.environ.get("TITLE", "Статус серверов")
SUBTITLE = os.environ.get("SUBTITLE", "Доступность серверов в реальном времени")
TZ_NAME = os.environ.get("TZ", "Europe/Moscow")
SERVER_HEADER = os.environ.get("SERVER_HEADER", "nginx")
STATIC_CACHE = "public, max-age=31536000, immutable"
NO_CACHE = "no-cache, no-store, must-revalidate"

RU_MONTHS = ["", "янв", "фев", "мар", "апр", "май", "июн",
             "июл", "авг", "сен", "окт", "ноя", "дек"]

FONT_DIR = os.path.join(os.path.dirname(DB_PATH) or ".", "fonts")
FONT_BASE = "https://cdn.jsdelivr.net/npm/@fontsource/inter@5/files/"
FONT_FILES = [
    "inter-latin-400-normal.woff2", "inter-latin-500-normal.woff2",
    "inter-latin-600-normal.woff2", "inter-cyrillic-400-normal.woff2",
    "inter-cyrillic-500-normal.woff2", "inter-cyrillic-600-normal.woff2",
]


def ensure_fonts():
    try:
        os.makedirs(FONT_DIR, exist_ok=True)
    except Exception:
        return
    for fn in FONT_FILES:
        fp = os.path.join(FONT_DIR, fn)
        try:
            if os.path.isfile(fp) and os.path.getsize(fp) > 0:
                continue
            req = urllib.request.Request(FONT_BASE + fn, headers={"User-Agent": "xray-status"})
            with urllib.request.urlopen(req, timeout=20) as r:
                data = r.read()
            with open(fp, "wb") as f:
                f.write(data)
            print("font ok:", fn, flush=True)
        except Exception as e:
            print("font fail:", fn, e, flush=True)

BRAND_DIRS = [d for d in [os.environ.get("ASSETS_DIR"),
                          os.path.dirname(DB_PATH) or ".", "/data", "/app", "."] if d]
IMG_EXT = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
           ".webp": "image/webp", ".ico": "image/x-icon", ".svg": "image/svg+xml",
           ".gif": "image/gif"}
DEFAULT_LOGO_SVG = ('<svg width="21" height="21" viewBox="0 0 24 24" fill="none" '
    'stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M12 3l7 4v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V7z"/><path d="M9 12l2 2 4-4"/></svg>')


def find_brand_image():
    for d in BRAND_DIRS:
        try:
            for fn in sorted(os.listdir(d)):
                low = fn.lower()
                if low.startswith("favicon") and os.path.splitext(low)[1] in IMG_EXT:
                    return os.path.join(d, fn)
        except Exception:
            pass
    return None

COUNTRY_KEYWORDS = [
    ("netherland", "nl"), ("нидерланд", "nl"), ("holland", "nl"), ("amsterdam", "nl"),
    ("germany", "de"), ("герман", "de"), ("frankfurt", "de"), ("deutsch", "de"),
    ("finland", "fi"), ("финлянд", "fi"), ("helsinki", "fi"),
    ("united states", "us"), ("usa", "us"), ("сша", "us"), ("america", "us"),
    ("new york", "us"), ("los angeles", "us"), ("miami", "us"), ("dallas", "us"), ("seattle", "us"),
    ("united kingdom", "gb"), ("britain", "gb"), ("england", "gb"), ("london", "gb"),
    ("великобритан", "gb"), ("англия", "gb"),
    ("france", "fr"), ("франц", "fr"), ("paris", "fr"), ("marseille", "fr"),
    ("japan", "jp"), ("япон", "jp"), ("tokyo", "jp"), ("osaka", "jp"),
    ("singapore", "sg"), ("сингапур", "sg"),
    ("turkey", "tr"), ("турц", "tr"), ("istanbul", "tr"), ("стамбул", "tr"),
    ("russia", "ru"), ("росси", "ru"), ("moscow", "ru"), ("москва", "ru"), ("питер", "ru"),
    ("poland", "pl"), ("польш", "pl"), ("warsaw", "pl"),
    ("sweden", "se"), ("швец", "se"), ("stockholm", "se"),
    ("switzerland", "ch"), ("швейцар", "ch"), ("zurich", "ch"),
    ("canada", "ca"), ("канад", "ca"), ("toronto", "ca"),
    ("italy", "it"), ("italia", "it"), ("итал", "it"), ("milan", "it"), ("milano", "it"),
    ("rome", "it"), ("roma", "it"), ("naples", "it"), ("napoli", "it"), ("неапол", "it"),
    ("turin", "it"), ("torino", "it"), ("турин", "it"), ("venice", "it"), ("venezia", "it"), ("венеци", "it"),
    ("spain", "es"), ("испан", "es"), ("madrid", "es"),
    ("hong kong", "hk"), ("гонконг", "hk"),
    ("korea", "kr"), ("корея", "kr"), ("seoul", "kr"),
    ("india", "in"), ("инди", "in"), ("mumbai", "in"),
    ("austria", "at"), ("австри", "at"), ("vienna", "at"),
    ("norway", "no"), ("норвег", "no"), ("oslo", "no"),
    ("denmark", "dk"), ("дани", "dk"),
    ("ireland", "ie"), ("ирланд", "ie"), ("dublin", "ie"),
    ("czech", "cz"), ("чех", "cz"), ("prague", "cz"),
    ("ukraine", "ua"), ("украин", "ua"), ("kyiv", "ua"), ("kiev", "ua"),
    ("emirates", "ae"), ("dubai", "ae"), ("оаэ", "ae"), ("uae", "ae"),
    ("israel", "il"), ("израил", "il"),
    ("brazil", "br"), ("бразил", "br"),
    ("australia", "au"), ("австрал", "au"), ("sydney", "au"),
    ("china", "cn"), ("китай", "cn"),
    ("hungary", "hu"), ("венгр", "hu"),
    ("romania", "ro"), ("румын", "ro"),
    ("bulgaria", "bg"), ("болгар", "bg"),
    ("latvia", "lv"), ("латви", "lv"), ("riga", "lv"),
    ("lithuania", "lt"), ("литва", "lt"),
    ("estonia", "ee"), ("эстони", "ee"),
    ("kazakhstan", "kz"), ("казахстан", "kz"),
    ("georgia", "ge"), ("груз", "ge"),
    ("armenia", "am"), ("армени", "am"),
    ("serbia", "rs"), ("серб", "rs"),
    ("greece", "gr"), ("греци", "gr"),
    ("portugal", "pt"), ("португал", "pt"),
    ("belgium", "be"), ("бельги", "be"),
    ("mexico", "mx"), ("мексик", "mx"),
    ("argentina", "ar"), ("аргентин", "ar"),
]

_lock = threading.Lock()


def detect_country(name):
    n = (name or "").lower()
    for kw, cc in COUNTRY_KEYWORDS:
        if kw in n:
            return cc
    return ""


def display_name(name, cc):
    if not name:
        return name
    s = re.sub("[\U0001F1E6-\U0001F1FF]", "", name).strip()
    if cc:
        m = re.match(r'^[A-Za-zА-Яа-яЁё]{2,3}[\s\-_|.]+(.+)$', s)
        if m:
            s = m.group(1).strip()
    return s or name


def tz():
    if ZoneInfo is not None:
        try:
            return ZoneInfo(TZ_NAME)
        except Exception:
            pass
    return timezone.utc


def conn():
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.execute("PRAGMA journal_mode=WAL")
    return c


def init_db():
    with _lock, conn() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS current(
            sid TEXT PRIMARY KEY, name TEXT, online INTEGER,
            latency INTEGER, ts INTEGER, seq INTEGER)""")
        c.execute("""CREATE TABLE IF NOT EXISTS daily(
            day TEXT, sid TEXT, up INTEGER DEFAULT 0, down INTEGER DEFAULT 0,
            lat_sum INTEGER DEFAULT 0, lat_cnt INTEGER DEFAULT 0,
            PRIMARY KEY(day, sid))""")
        try:
            c.execute("ALTER TABLE daily ADD COLUMN down_conf INTEGER DEFAULT 0")
        except Exception:
            pass
        c.execute("""CREATE TABLE IF NOT EXISTS samples(
            ts INTEGER, sid TEXT, online INTEGER, latency INTEGER)""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_samples ON samples(sid, ts)")


def fetch_proxies():
    req = urllib.request.Request(
        CHECKER_URL + "/api/v1/public/proxies",
        headers={"User-Agent": "xray-status/1.0"})
    with urllib.request.urlopen(req, timeout=15) as r:
        payload = json.loads(r.read().decode("utf-8"))
    data = payload.get("data") if isinstance(payload, dict) else payload
    return data or []


def poll_once():
    proxies = fetch_proxies()
    now = int(time.time())
    today = datetime.now(tz()).strftime("%Y-%m-%d")
    with _lock, conn() as c:
        for seq, p in enumerate(proxies):
            sid = p.get("stableId") or ""
            if not sid:
                continue
            name = p.get("name") or sid
            online = 1 if p.get("online") else 0
            latency = int(p.get("latencyMs") or 0)
            prev = c.execute("SELECT online, ts FROM current WHERE sid=?", (sid,)).fetchone()
            consecutive = (online == 0 and prev is not None and prev[0] == 0
                           and prev[1] is not None and (now - prev[1]) <= POLL_INTERVAL * 2)
            down_conf = 1 if consecutive else 0
            c.execute("""INSERT INTO current(sid,name,online,latency,ts,seq)
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(sid) DO UPDATE SET
                  name=excluded.name, online=excluded.online,
                  latency=excluded.latency, ts=excluded.ts, seq=excluded.seq""",
                      (sid, name, online, latency, now, seq))
            up = online
            down = 1 - online
            lat_sum = latency if (online and latency > 0) else 0
            lat_cnt = 1 if (online and latency > 0) else 0
            c.execute("""INSERT INTO daily(day,sid,up,down,lat_sum,lat_cnt,down_conf)
                VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(day,sid) DO UPDATE SET
                  up=up+excluded.up, down=down+excluded.down,
                  lat_sum=lat_sum+excluded.lat_sum, lat_cnt=lat_cnt+excluded.lat_cnt,
                  down_conf=down_conf+excluded.down_conf""",
                      (today, sid, up, down, lat_sum, lat_cnt, down_conf))
            c.execute("INSERT INTO samples(ts,sid,online,latency) VALUES(?,?,?,?)",
                      (now, sid, online, latency))
        cutoff = (datetime.now(tz()) - timedelta(days=DAYS + 1)).strftime("%Y-%m-%d")
        c.execute("DELETE FROM daily WHERE day < ?", (cutoff,))
        c.execute("DELETE FROM samples WHERE ts < ?", (now - SAMPLE_RETAIN_DAYS * 86400,))


def poller():
    first = True
    while True:
        try:
            poll_once()
            first = False
        except Exception as e:
            print("poll error:", e, flush=True)
            if first:
                time.sleep(5)
                continue
        time.sleep(POLL_INTERVAL)


def build_summary():
    t = tz()
    now_local = datetime.now(t)
    day_list = [(now_local - timedelta(days=i)).strftime("%Y-%m-%d")
                for i in range(DAYS - 1, -1, -1)]
    min_per_sample = POLL_INTERVAL / 60.0

    with _lock, conn() as c:
        servers = c.execute(
            "SELECT sid,name,online,latency,ts,seq FROM current ORDER BY seq").fetchall()
        daily_rows = c.execute(
            "SELECT sid,day,up,down,lat_sum,lat_cnt,down_conf FROM daily").fetchall()

    by_sid = {}
    for sid, day, up, down, lat_sum, lat_cnt, down_conf in daily_rows:
        by_sid.setdefault(sid, {})[day] = (up, down, lat_sum, lat_cnt, down_conf or 0)

    out_servers = []
    tot_up = tot_total = 0
    tot_down_min = 0
    online_count = 0
    lat_vals = []
    last_ts = 0

    for sid, name, online, latency, ts, seq in servers:
        days = []
        s_up = s_total = 0
        s_down_min = 0
        for d in day_list:
            rec = by_sid.get(sid, {}).get(d)
            if rec:
                up, down, lat_sum, lat_cnt, down_conf = rec
                total = up + down
                pct = round(up / total * 100, 2) if total else None
                down_min = round(down_conf * min_per_sample)
            else:
                total = 0
                pct = None
                down_min = 0
            s_up += rec[0] if rec else 0
            s_total += (rec[0] + rec[1]) if rec else 0
            s_down_min += down_min
            y, m, dd = d.split("-")
            label = dd + " " + RU_MONTHS[int(m)]
            days.append({"date": d, "label": label, "uptime": pct,
                         "downMin": down_min, "hasData": total > 0})
        up30 = round(s_up / s_total * 100, 2) if s_total else None
        if ts and ts > last_ts:
            last_ts = ts
        if online:
            online_count += 1
            if latency > 0:
                lat_vals.append(latency)
        cc = detect_country(name)
        out_servers.append({
            "sid": sid, "name": display_name(name, cc), "cc": cc,
            "online": bool(online), "latencyMs": latency,
            "uptime30": up30, "downMin30": s_down_min, "days": days,
        })
        tot_up += s_up
        tot_total += s_total
        tot_down_min += s_down_min

    avg_lat = round(sum(lat_vals) / len(lat_vals)) if lat_vals else 0
    totals = {
        "online": online_count,
        "total": len(servers),
        "uptime30": round(tot_up / tot_total * 100, 2) if tot_total else None,
        "avgLatency": avg_lat,
        "downMin30": tot_down_min,
    }
    last_check = datetime.fromtimestamp(last_ts, t).strftime("%Y-%m-%d %H:%M") if last_ts else None
    return {
        "title": TITLE, "subtitle": SUBTITLE, "days": DAYS,
        "pollInterval": POLL_INTERVAL,
        "generatedAt": now_local.strftime("%Y-%m-%d %H:%M"),
        "lastCheck": last_check,
        "servers": out_servers, "totals": totals,
    }


def _day_payload(sid, ds, is_today):
    end = ds + 86400
    upper = int(time.time()) if is_today else end
    with _lock, conn() as c:
        rows = c.execute(
            "SELECT ts,online,latency FROM samples WHERE sid=? AND ts>=? AND ts<? ORDER BY ts",
            (sid, ds, end)).fetchall()
    samples = [{"ts": r[0], "online": bool(r[1]), "latency": r[2]} for r in rows]
    pings = [r[2] for r in rows if r[1] and r[2] > 0]
    stats = {
        "checks": len(rows),
        "errors": sum(1 for r in rows if not r[1]),
        "pmin": min(pings) if pings else 0,
        "pavg": round(sum(pings) / len(pings)) if pings else 0,
        "pmax": max(pings) if pings else 0,
    }
    dt = datetime.fromtimestamp(ds, tz())
    label = "Сегодня" if is_today else (dt.strftime("%d ") + RU_MONTHS[dt.month])
    return {"dayStart": ds, "now": upper, "isToday": is_today, "dayLabel": label,
            "pollInterval": POLL_INTERVAL, "samples": samples, "stats": stats}


def _midnight_ts(dt_local):
    m = dt_local.replace(hour=0, minute=0, second=0, microsecond=0)
    return int(m.timestamp())


def build_today(sid):
    return _day_payload(sid, _midnight_ts(datetime.now(tz())), True)


def build_day(sid, date_str):
    t = tz()
    try:
        d = datetime.strptime(date_str, "%Y-%m-%d")
    except Exception:
        return build_today(sid)
    ds = int(datetime(d.year, d.month, d.day, tzinfo=t).timestamp())
    today0 = _midnight_ts(datetime.now(t))
    return _day_payload(sid, ds, ds == today0)


INDEX_HTML = r"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>__TITLE__</title>
__FAVICON__
<style>
@font-face{font-family:'Inter';font-style:normal;font-weight:400;font-display:swap;src:url('fonts/inter-cyrillic-400-normal.woff2') format('woff2');unicode-range:U+0301,U+0400-045F,U+0490-0491,U+04B0-04B1,U+2116;}
@font-face{font-family:'Inter';font-style:normal;font-weight:500;font-display:swap;src:url('fonts/inter-cyrillic-500-normal.woff2') format('woff2');unicode-range:U+0301,U+0400-045F,U+0490-0491,U+04B0-04B1,U+2116;}
@font-face{font-family:'Inter';font-style:normal;font-weight:600;font-display:swap;src:url('fonts/inter-cyrillic-600-normal.woff2') format('woff2');unicode-range:U+0301,U+0400-045F,U+0490-0491,U+04B0-04B1,U+2116;}
@font-face{font-family:'Inter';font-style:normal;font-weight:400;font-display:swap;src:url('fonts/inter-latin-400-normal.woff2') format('woff2');unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+2000-206F,U+2074,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD;}
@font-face{font-family:'Inter';font-style:normal;font-weight:500;font-display:swap;src:url('fonts/inter-latin-500-normal.woff2') format('woff2');unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+2000-206F,U+2074,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD;}
@font-face{font-family:'Inter';font-style:normal;font-weight:600;font-display:swap;src:url('fonts/inter-latin-600-normal.woff2') format('woff2');unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+2000-206F,U+2074,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD;}
:root,html[data-theme="light"]{
  --bg:#fbfcfe; --card:#ffffff; --soft:#f1f5fb; --line:#e4e9f0; --hover:#f3f7fd;
  --tx:#13171d; --tx2:#46505f; --tx3:#69727f;
  --ok:#13a06f; --warn:#e0951a; --orange:#dc5b25; --bad:#e23f3d; --info:#2f6bff;
  --shadow:0 1px 2px rgba(18,28,45,.06),0 1px 3px rgba(18,28,45,.05);
}
@media (prefers-color-scheme: dark){
  :root{--bg:#16181d; --card:#1f232a; --soft:#23272f; --line:#333a45; --hover:#262b33;
    --tx:#f1f4f9; --tx2:#b2bbc8; --tx3:#8d97a5;
    --ok:#26c089; --warn:#f2b13e; --orange:#ec7242; --bad:#f25c5a; --info:#5b8cff; --shadow:none;}
}
html[data-theme="dark"]{--bg:#16181d; --card:#1f232a; --soft:#23272f; --line:#333a45; --hover:#262b33;
  --tx:#f1f4f9; --tx2:#b2bbc8; --tx3:#8d97a5;
  --ok:#26c089; --warn:#f2b13e; --orange:#ec7242; --bad:#f25c5a; --info:#5b8cff; --shadow:none;}
*{box-sizing:border-box}
html{overflow-y:scroll;scrollbar-gutter:stable;}
body{margin:0;background:var(--bg);color:var(--tx);
  font-family:'Inter',-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;}
@keyframes fadeUp{from{opacity:0;transform:translateY(7px);}to{opacity:1;transform:none;}}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(22,176,122,.45);}70%{box-shadow:0 0 0 6px rgba(22,176,122,0);}100%{box-shadow:0 0 0 0 rgba(22,176,122,0);}}
@media (prefers-reduced-motion: reduce){*{animation:none !important;transition:none !important;}}
.wrap{max-width:940px;margin:0 auto;padding:30px 18px 52px;}
.top{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:20px;}
.brand{display:flex;align-items:center;gap:12px;}
.logo{width:38px;height:38px;border-radius:10px;background:rgba(47,107,255,.12);color:var(--info);
  display:flex;align-items:center;justify-content:center;}
.brand h1{font-size:20px;font-weight:600;margin:0;line-height:1.2;}
.brand p{font-size:13px;color:var(--tx2);margin:3px 0 0;}
.pill{display:flex;align-items:center;gap:8px;padding:8px 15px;border-radius:999px;
  font-size:13.5px;font-weight:500;}
.pill .dot{width:8px;height:8px;border-radius:50%;display:inline-block;}
.pill.ok{background:rgba(22,176,122,.13);color:var(--ok);}
.pill.bad{background:rgba(232,80,78,.13);color:var(--bad);}
.pill.ok .dot{animation:pulse 2.4s ease-out infinite;}
.topr{display:flex;align-items:center;gap:10px;}
.tbtn{display:flex;align-items:center;justify-content:center;width:36px;height:36px;flex:none;
  border-radius:10px;border:1px solid var(--line);background:var(--card);color:var(--tx2);cursor:pointer;
  transition:background .15s,border-color .15s,color .15s;}
.tbtn:hover{background:var(--hover);color:var(--tx);border-color:var(--tx3);}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:18px;}
.stat{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px 18px;box-shadow:var(--shadow);}
.stat .l{font-size:13px;color:var(--tx2);}
.stat .v{font-size:25px;font-weight:600;margin-top:3px;letter-spacing:-.3px;}
.item{background:var(--card);border:1px solid var(--line);border-radius:14px;margin-bottom:9px;
  box-shadow:var(--shadow);overflow:hidden;animation:fadeUp .34s ease both;
  transition:border-color .15s, box-shadow .15s;}
.item:hover{border-color:rgba(127,140,158,.42);box-shadow:0 2px 10px rgba(18,28,45,.07);}
.row{display:flex;align-items:center;gap:14px;padding:12px 15px;cursor:pointer;transition:background .14s;}
.row:hover{background:var(--hover);}
.label{width:214px;flex:none;display:flex;align-items:center;gap:9px;min-width:0;}
.flag{width:23px;height:16px;border-radius:3px;object-fit:cover;border:1px solid rgba(0,0,0,.12);flex:none;
  background:var(--soft);}
.nm{min-width:0;}
.name{display:flex;align-items:center;gap:8px;font-size:15px;font-weight:500;}
.name .sdot{width:9px;height:9px;border-radius:50%;flex:none;transition:background-color .3s;}
.name span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.bars{flex:1;display:block;height:26px;min-width:0;}
.bars rect{transition:fill .3s, opacity .12s;cursor:pointer;}
.bars rect:hover{opacity:.55;}
.stat2{width:124px;flex:none;text-align:right;}
.stat2 .p{font-size:15px;font-weight:600;}
.stat2 .s{font-size:12px;color:var(--tx3);}
.chev{color:var(--tx3);margin-left:2px;flex:none;display:flex;align-items:center;justify-content:center;
  width:26px;height:26px;border-radius:50%;transition:transform .22s ease, background-color .15s, color .15s;}
.row:hover .chev{background:rgba(127,140,158,.14);color:var(--tx2);}
.item.open .chev{transform:rotate(180deg);}
.panel{max-height:0;overflow:hidden;opacity:0;background:var(--soft);border-top:1px solid transparent;
  padding:0 20px;transition:max-height .3s ease, opacity .24s ease, padding .28s ease, border-color .28s ease;}
.item.open .panel{opacity:1;padding:20px 20px 22px;border-top-color:var(--line);}
.phead{font-size:13px;color:var(--tx2);margin-bottom:16px;line-height:1.5;}
.tstats{display:flex;flex-wrap:wrap;gap:16px 34px;margin-bottom:4px;}
.tstats div{display:flex;flex-direction:column;gap:3px;}
.tstats span{font-size:12.5px;color:var(--tx2);}
.tstats b{font-size:18px;font-weight:600;letter-spacing:-.2px;}
.tcaption{font-size:12.5px;color:var(--tx3);margin:20px 0 9px;}
.tchartwrap{width:100%;position:relative;}
.tscroll{overflow-x:auto;overflow-y:hidden;scrollbar-width:thin;scrollbar-color:var(--line) transparent;}
.tscroll::-webkit-scrollbar{height:9px;}
.tscroll::-webkit-scrollbar-track{background:transparent;}
.tscroll::-webkit-scrollbar-thumb{background:var(--line);border-radius:9px;border:2px solid transparent;background-clip:content-box;}
.tscroll:hover::-webkit-scrollbar-thumb{background:var(--tx3);background-clip:content-box;}
.tcanvas{position:relative;padding-bottom:10px;}
.tchart{display:block;width:100%;height:150px;}
.tyaxis{position:absolute;right:6px;z-index:2;transform:translateY(-50%);font-size:12px;color:var(--tx3);
  background:var(--soft);padding:0 4px;pointer-events:none;border-radius:3px;}
.taxis{display:flex;justify-content:space-between;font-size:12px;color:var(--tx3);margin-top:9px;}
.empty{color:var(--tx2);font-size:13px;padding:6px 0;}
.legend{display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin-top:16px;font-size:13px;color:var(--tx2);}
.legend i{width:12px;height:12px;border-radius:3px;display:inline-block;margin-right:6px;vertical-align:-1px;}
.legend .right{margin-left:auto;}
.foot{margin-top:22px;font-size:13px;color:var(--tx3);text-align:center;}
#tip{position:fixed;pointer-events:none;opacity:0;transition:opacity .08s;z-index:60;
  background:var(--card);border:1px solid var(--line);border-radius:10px;padding:9px 11px;
  font-size:13px;min-width:140px;box-shadow:0 8px 28px rgba(18,28,45,.16);}
#tip .d{font-weight:600;margin-bottom:4px;}
#tip .k{color:var(--tx2);line-height:1.5;}
.skel{color:var(--tx2);font-size:14px;padding:30px 0;text-align:center;}
@media (max-width:560px){
  .wrap{padding:22px 14px 40px;}
  .brand h1{font-size:18px;} .brand p{font-size:12px;}
  .stats{grid-template-columns:1fr 1fr;gap:10px;}
  .stat{padding:12px 14px;border-radius:12px;} .stat .v{font-size:22px;}
  .row{flex-wrap:wrap;gap:9px 12px;padding:12px 14px;}
  .label{width:auto;flex:1 1 auto;min-width:0;}
  .stat2{width:auto;text-align:right;}
  .chev{order:4;}
  .bars{order:5;flex-basis:100%;height:26px;}
  .legend{gap:9px 14px;margin-top:14px;} .legend .right{display:none;}
  .tstats{gap:12px 22px;} .panel{padding:0 14px;}
  .item.open .panel{padding:16px 14px 18px;}
}
</style>
<script>try{var _t=localStorage.getItem("sp-theme");if(_t)document.documentElement.setAttribute("data-theme",_t);}catch(e){}</script>
</head>
<body>
<div class="wrap">
  <div class="top">
    <div class="brand">
      <div class="logo">__LOGO__</div>
      <div><h1 id="title">__TITLE__</h1><p id="subtitle">__SUBTITLE__</p></div>
    </div>
    <div class="topr">
      <div id="overall" class="pill ok"><span class="dot"></span><span>Загрузка…</span></div>
      <button id="theme-btn" class="tbtn" aria-label="Сменить тему" title="Сменить тему"></button>
    </div>
  </div>
  <div class="stats">
    <div class="stat"><div class="l">Серверов онлайн</div><div class="v" id="s-online">—</div></div>
    <div class="stat"><div class="l">Аптайм за __DAYS__ дн</div><div class="v" id="s-uptime">—</div></div>
    <div class="stat"><div class="l">Средний пинг</div><div class="v" id="s-ping">—</div></div>
  </div>
  <div id="list"><div class="skel">Загрузка данных…</div></div>
  <div class="legend">
    <span><i style="background:#16b07a"></i>норма</span>
    <span><i style="background:#f0a82a"></i>до 30 мин</span>
    <span><i style="background:#e3692f"></i>30 мин – 2 ч</span>
    <span><i style="background:#e8504e"></i>от 2 ч</span>
    <span><i style="background:#cfd6df"></i>нет данных</span>
    <span class="right">← __DAYS__ дней назад · сегодня →</span>
  </div>
  <div class="foot" id="foot"></div>
</div>
<div id="tip"></div>
<script>
var GREY="#cfd6df";
var SVGNS="http://www.w3.org/2000/svg";
function colorFor(d){
  if(!d.hasData) return GREY;
  if(d.downMin<=0) return "#16b07a";
  if(d.downMin<=30) return "#f0a82a";
  if(d.downMin<120) return "#e3692f";
  return "#e8504e";
}
function fmtDur(m){
  if(m<=0) return "0 мин";
  if(m>=1440){var dd=Math.floor(m/1440),h=Math.round((m%1440)/60);return dd+" дн"+(h?" "+h+" ч":"");}
  if(m>=60){var h=Math.floor(m/60),mm=m%60;return h+" ч"+(mm?" "+mm+" мин":"");}
  return m+" мин";
}
function fmtTime(ts,ds){
  var off=ts-ds,h=Math.floor(off/3600),m=Math.floor((off%3600)/60);
  return ("0"+h).slice(-2)+":"+("0"+m).slice(-2);
}
function escapeHtml(s){var d=document.createElement("div");d.textContent=s;return d.innerHTML;}
var tip=document.getElementById("tip");
function evXY(e){var t=e.touches&&e.touches[0];return t||e;}
function moveTip(e){
  e=evXY(e);
  var w=tip.offsetWidth,x=e.clientX+14,y=e.clientY-10;
  if(x+w>window.innerWidth-8)x=e.clientX-w-14;
  tip.style.left=x+"px";tip.style.top=Math.max(8,y)+"px";
}
function hideTip(){tip.style.opacity="0";}
function showTipDay(e,d){
  var u=d.uptime;
  var uc=(u===null)?"var(--tx2)":(u>=99.99?"var(--ok)":(u>=95?"var(--warn)":"var(--bad)"));
  var ut=(u===null)?"нет данных":u.toFixed(2)+"%";
  var down=!d.hasData?''
    :d.downMin>0?'<div class="k">простой: <b style="color:var(--bad)">'+fmtDur(d.downMin)+'</b></div>'
    :((d.uptime!==null&&d.uptime<100)?'<div class="k">кратковременный сбой</div>':'<div class="k">сбоев нет</div>');
  tip.innerHTML='<div class="d">'+d.label+'</div><div class="k">аптайм: <b style="color:'+uc+'">'+ut+'</b></div>'+down;
  tip.style.opacity="1";moveTip(e);
}
function showTipServer(e,s){
  var u=s.uptime30;
  var uc=(u===null)?"var(--tx2)":(u>=99.9?"var(--ok)":(u>=99?"var(--warn)":"var(--bad)"));
  var ut=(u===null)?"нет данных":u.toFixed(2)+"%";
  var dm=(s.downMin30>0)?'<b style="color:var(--bad)">'+fmtDur(s.downMin30)+'</b>':'<b style="color:var(--ok)">0 мин</b>';
  tip.innerHTML='<div class="d">'+escapeHtml(s.name)+'</div>'+
    '<div class="k">статус: '+(s.online?'<b style="color:var(--ok)">онлайн</b>':'<b style="color:var(--bad)">офлайн</b>')+'</div>'+
    '<div class="k">аптайм 30 дн: <b style="color:'+uc+'">'+ut+'</b></div>'+
    '<div class="k">общий простой: '+dm+'</div>';
  tip.style.opacity="1";moveTip(e);
}
function renderToday(panel,data){
  var head=data.dayLabel||"Сегодня";
  if(!data.samples.length){
    panel.innerHTML='<div class="phead">'+head+'</div><div class="empty">Данных за этот день нет.</div>';
    panelH(panel);return;
  }
  var ds=data.dayStart,span=86400,W=1000;
  var chartTop=10,base=150,H=150,chartH=base-chartTop,mid=(chartTop+base)/2;
  var sw=Math.max(1.5,data.pollInterval/span*W);
  var bands="",runStart=null,runEnd=null,ptsRaw=[];
  function flush(){if(runStart!==null){bands+='<rect x="'+runStart.toFixed(1)+'" y="0" width="'+Math.max(1.5,runEnd-runStart).toFixed(1)+'" height="'+H+'" fill="rgba(232,80,80,.18)"/>';runStart=null;}}
  data.samples.forEach(function(s){
    var x=(s.ts-ds)/span*W;
    if(s.online){flush();if(s.latency>0)ptsRaw.push([x,s.latency]);}
    else{if(runStart===null)runStart=x;runEnd=x+sw;}
  });
  flush();
  function niceLo(v){var e=Math.pow(10,Math.floor(Math.log(v)/Math.LN10+1e-9)),m=v/e;return (m>=5?5:(m>=2?2:1))*e;}
  function niceHi(v){var e=Math.pow(10,Math.floor(Math.log(v)/Math.LN10+1e-9)),m=v/e;return (m<=1.0001?1:(m<=2.0001?2:(m<=5.0001?5:10)))*e;}
  var pmin=data.stats.pmin||50,pmax=data.stats.pmax||100;
  var lo=niceLo(Math.max(10,pmin)),hi=niceHi(Math.max(pmax,lo*4));
  var L0=Math.log(lo),LR=(Math.log(hi)-L0)||1;
  function yOf(v){var vv=v<lo?lo:(v>hi?hi:v);return base-(Math.log(vv)-L0)/LR*chartH;}
  var pts=ptsRaw.map(function(p){return [p[0],yOf(p[1])];});
  var ticks=[],t=lo,tg=0;
  while(t<=hi*1.0001&&tg++<40){ticks.push(t);var te=Math.pow(10,Math.floor(Math.log(t)/Math.LN10+1e-9)),tm=t/te;t=(tm<1.5?2:(tm<3.5?5:10))*te;}
  var grid="",yl="";
  ticks.forEach(function(tk){var ty=yOf(tk);grid+='<line x1="0" y1="'+ty.toFixed(1)+'" x2="1000" y2="'+ty.toFixed(1)+'" stroke="var(--line)" stroke-width="1"/>';yl+='<div class="tyaxis" style="top:'+ty.toFixed(1)+'px">'+tk+'</div>';});
  var poly=pts.map(function(p){return p[0].toFixed(1)+","+p[1].toFixed(1);});
  var line=pts.length?'<polyline points="'+poly.join(" ")+'" fill="none" stroke="#2f6bff" stroke-width="1.6" stroke-linejoin="round" stroke-linecap="round"/>':"";
  var area=pts.length?'<path d="M'+pts[0][0].toFixed(1)+','+base+' L'+poly.join(" L")+' L'+pts[pts.length-1][0].toFixed(1)+','+base+' Z" fill="url(#pgrad)"/>':"";
  var nowLine="";
  if(data.isToday){var nowX=((data.now-ds)/span*W);nowLine='<line x1="'+nowX.toFixed(1)+'" y1="0" x2="'+nowX.toFixed(1)+'" y2="'+base+'" stroke="var(--tx3)" stroke-width="1" stroke-dasharray="4 4"/>';}
  var svg='<svg viewBox="0 0 1000 '+H+'" preserveAspectRatio="none" class="tchart">'+
    '<defs><linearGradient id="pgrad" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#2f6bff" stop-opacity="0.20"/><stop offset="1" stop-color="#2f6bff" stop-opacity="0"/></linearGradient></defs>'+
    grid+area+bands+line+nowLine+
    '<line class="cursor" x1="0" y1="0" x2="0" y2="'+base+'" stroke="var(--tx2)" stroke-width="1" opacity="0"/>'+
    '</svg>';
  var zoom=2;
  var axis="";for(var h2=0;h2<=24;h2+=3){axis+='<span>'+("0"+h2).slice(-2)+':00</span>';}
  var st=data.stats,last=data.samples[data.samples.length-1];
  var stats='<div class="tstats">'+
    '<div><span>'+(data.isToday?"Проверок сегодня":"Проверок за день")+'</span><b>'+st.checks+'</b></div>'+
    '<div><span>Ошибок опроса</span><b style="color:'+(st.errors?"var(--bad)":"var(--ok)")+'">'+st.errors+'</b></div>'+
    '<div><span>'+(data.isToday?"Пинг сейчас":"Последний пинг")+'</span><b>'+(last.online?last.latency+" мс":"—")+'</b></div>'+
    '<div><span>Пинг мин / сред / макс</span><b>'+(st.pavg?st.pmin+" / "+st.pavg+" / "+st.pmax+" мс":"—")+'</b></div>'+
    '</div>';
  var cap='Пинг, мс · логарифмическая шкала · макс '+(data.stats.pmax||0)+' мс';
  panel.innerHTML='<div class="phead">'+head+' · синяя линия — пинг, красные полосы — периоды сбоев</div>'+
    stats+
    '<div class="tcaption">'+cap+'</div>'+
    '<div class="tchartwrap">'+
      '<div class="tscroll"><div class="tcanvas" style="width:'+(zoom*100)+'%">'+svg+'<div class="taxis">'+axis+'</div></div></div>'+
      yl+
    '</div>';
  var sc=panel.querySelector(".tscroll");
  if(sc){
    if(data.isToday){
      var nf=(data.now-ds)/span,tgt=nf*sc.scrollWidth-sc.clientWidth/2;
      sc.scrollLeft=Math.max(0,Math.min(tgt,sc.scrollWidth-sc.clientWidth));
    }else{sc.scrollLeft=0;}
  }
  var svgEl=panel.querySelector("svg"),cursor=svgEl.querySelector(".cursor"),samples=data.samples;
  function scrub(cx,ev){
    var r=svgEl.getBoundingClientRect();
    var frac=(cx-r.left)/r.width;if(frac<0)frac=0;if(frac>1)frac=1;
    var ts=ds+frac*span,best=null,bd=1e15;
    for(var i=0;i<samples.length;i++){var dd=Math.abs(samples[i].ts-ts);if(dd<bd){bd=dd;best=samples[i];}}
    if(!best)return;
    var x=(best.ts-ds)/span*1000;
    cursor.setAttribute("x1",x);cursor.setAttribute("x2",x);cursor.setAttribute("opacity","1");
    tip.innerHTML='<div class="d">'+fmtTime(best.ts,ds)+'</div>'+
      (best.online?'<div class="k">опрос: <b style="color:var(--ok)">успешно</b></div><div class="k">пинг: <b>'+best.latency+' мс</b></div>'
                  :'<div class="k"><b style="color:var(--bad)">ошибка опроса</b></div>');
    tip.style.opacity="1";moveTip(ev);
  }
  svgEl.addEventListener("mousemove",function(e){scrub(e.clientX,e);});
  svgEl.addEventListener("mouseleave",function(){cursor.setAttribute("opacity","0");hideTip();});
  var td=null;
  svgEl.addEventListener("touchstart",function(e){var t=e.touches[0];if(!t)return;td={x:t.clientX,y:t.clientY,m:false};scrub(t.clientX,t);},{passive:true});
  svgEl.addEventListener("touchmove",function(e){if(!td)return;var t=e.touches[0];if(!t)return;if(!td.m&&(Math.abs(t.clientX-td.x)>8||Math.abs(t.clientY-td.y)>8)){td.m=true;cursor.setAttribute("opacity","0");hideTip();}},{passive:true});
  svgEl.addEventListener("touchend",function(){td=null;},{passive:true});
  panelH(panel);
}
var built=false,order=[],nodes={};
function srvUpColor(u){return (u===null)?"var(--tx2)":(u>=99.9?"var(--ok)":(u>=99?"var(--warn)":"var(--bad)"));}
function updateTop(data){
  document.getElementById("title").textContent=data.title;
  document.getElementById("subtitle").textContent=data.subtitle;
  var t=data.totals;
  document.getElementById("s-online").textContent=t.online+" / "+t.total;
  document.getElementById("s-uptime").textContent=(t.uptime30===null?"—":t.uptime30.toFixed(2)+"%");
  document.getElementById("s-ping").textContent=(t.avgLatency?t.avgLatency+" ms":"—");
  var allUp=t.online===t.total&&t.total>0;
  var ov=document.getElementById("overall");
  ov.className="pill "+(allUp?"ok":"bad");
  ov.innerHTML='<span class="dot" style="background:currentColor"></span><span>'+
    (allUp?"Все системы в норме":(t.total-t.online)+" сервер(ов) недоступно")+'</span>';
  document.getElementById("foot").textContent=
    (data.lastCheck?"последняя проверка "+data.lastCheck:"ожидание первой проверки")+
    " · интервал "+Math.round(data.pollInterval/60*10)/10+" мин";
}
function panelH(panel){
  var it=panel.parentElement;
  if(it&&it.classList.contains("open"))panel.style.maxHeight=(panel.scrollHeight+40)+"px";
}
function openPanel(panel,sid){
  hideTip();
  if(!panel.innerHTML.trim()||panel.querySelector(".empty"))panel.innerHTML='<div class="empty">Загрузка…</div>';
  fetch("api/today?sid="+encodeURIComponent(sid))
    .then(function(r){return r.json();})
    .then(function(td){renderToday(panel,td);})
    .catch(function(){panel.innerHTML='<div class="empty">Не удалось загрузить.</div>';panelH(panel);});
}
function refreshPanel(panel,sid){
  var sc=panel.querySelector(".tscroll");
  var keep=sc?sc.scrollLeft:null;
  fetch("api/today?sid="+encodeURIComponent(sid))
    .then(function(r){return r.json();})
    .then(function(td){
      renderToday(panel,td);
      if(keep!==null){var s2=panel.querySelector(".tscroll");if(s2)s2.scrollLeft=keep;}
    })
    .catch(function(){});
}
function loadDay(panel,sid,date){
  hideTip();
  if(!panel.innerHTML.trim()||panel.querySelector(".empty"))panel.innerHTML='<div class="empty">Загрузка…</div>';
  fetch("api/day?sid="+encodeURIComponent(sid)+"&date="+encodeURIComponent(date))
    .then(function(r){return r.json();})
    .then(function(td){renderToday(panel,td);})
    .catch(function(){panel.innerHTML='<div class="empty">Не удалось загрузить.</div>';panelH(panel);});
}
function applyServer(item,s,days){
  item._label._s=s;
  item._dot.style.background=s.online?"#16b07a":"#e8504e";
  for(var i=0;i<item._bars.length;i++){var d=s.days[i];if(d){item._bars[i]._d=d;item._bars[i].setAttribute("fill",colorFor(d));}}
  item._p.textContent=(s.uptime30===null)?"—":s.uptime30.toFixed(2)+"%";
  item._p.style.color=srvUpColor(s.uptime30);
  item._s2.textContent=(s.latencyMs?s.latencyMs+" ms · ":"")+days+" дн";
}
function buildList(data){
  var list=document.getElementById("list");
  list.innerHTML="";nodes={};order=[];
  data.servers.forEach(function(s,idx){
    var item=document.createElement("div");item.className="item";item._sid=s.sid;
    item.style.animationDelay=Math.min(idx*0.04,0.5)+"s";
    var row=document.createElement("div");row.className="row";
    var flag=s.cc?'<img class="flag" src="https://flagcdn.com/'+s.cc+'.svg" alt="" loading="lazy">':'<span class="flag"></span>';
    var label=document.createElement("div");label.className="label";
    label.innerHTML=flag+'<div class="nm"><div class="name"><span class="sdot"></span><span>'+escapeHtml(s.name)+'</span></div></div>';
    label._s=s;
    label.addEventListener("mouseenter",function(e){showTipServer(e,this._s);});
    label.addEventListener("mousemove",moveTip);
    label.addEventListener("mouseleave",hideTip);
    var N=s.days.length||1;
    var bars=document.createElementNS(SVGNS,"svg");bars.setAttribute("class","bars");
    bars.setAttribute("viewBox","0 0 1000 100");bars.setAttribute("preserveAspectRatio","none");
    var slot=1000/N,gap=Math.min(7,slot*0.32),barArr=[];
    s.days.forEach(function(d,i){
      var r=document.createElementNS(SVGNS,"rect");
      r.setAttribute("x",(i*slot+gap/2).toFixed(2));r.setAttribute("y","0");
      r.setAttribute("width",(slot-gap).toFixed(2));r.setAttribute("height","100");
      r.setAttribute("rx","7");r.setAttribute("fill",colorFor(d));r._d=d;
      r.addEventListener("mouseenter",function(e){showTipDay(e,this._d);});
      r.addEventListener("mousemove",moveTip);
      r.addEventListener("mouseleave",hideTip);
      r.addEventListener("click",function(e){e.stopPropagation();item._day=this._d.date;item.classList.add("open");loadDay(item._panel,item._sid,this._d.date);});
      bars.appendChild(r);barArr.push(r);
    });
    var st2=document.createElement("div");st2.className="stat2";
    var pEl=document.createElement("div");pEl.className="p";
    var sEl=document.createElement("div");sEl.className="s";
    st2.appendChild(pEl);st2.appendChild(sEl);
    var chev=document.createElement("div");chev.className="chev";
    chev.innerHTML='<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>';
    row.appendChild(label);row.appendChild(bars);row.appendChild(st2);row.appendChild(chev);
    var panel=document.createElement("div");panel.className="panel";panel.innerHTML='<div class="empty">Загрузка…</div>';
    row.addEventListener("click",function(){
      if(item.classList.contains("open")){
        panel.style.maxHeight=panel.scrollHeight+"px";
        requestAnimationFrame(function(){item.classList.remove("open");panel.style.maxHeight="0px";});
      }else{
        item._day=null;item.classList.add("open");openPanel(panel,item._sid);
      }
    });
    item.appendChild(row);item.appendChild(panel);
    item._dot=label.querySelector(".sdot");item._bars=barArr;item._p=pEl;item._s2=sEl;item._label=label;item._panel=panel;
    applyServer(item,s,data.days);
    list.appendChild(item);order.push(s.sid);nodes[s.sid]=item;
  });
  built=true;
}
function sameOrder(data){
  if(!built||order.length!==data.servers.length)return false;
  for(var i=0;i<order.length;i++)if(order[i]!==data.servers[i].sid)return false;
  return true;
}
var lastSeen=null;
function render(data){
  updateTop(data);
  var fresh=data.lastCheck!==lastSeen;lastSeen=data.lastCheck;
  if(sameOrder(data)){
    data.servers.forEach(function(s){var item=nodes[s.sid];if(item)applyServer(item,s,data.days);});
    if(fresh)for(var sid in nodes){var it=nodes[sid];if(it.classList.contains("open")&&(it._day===null||it._day===undefined))refreshPanel(it._panel,it._sid);}
  }else{
    buildList(data);
  }
}
function load(){
  fetch("api/summary").then(function(r){return r.json();}).then(render)
  .catch(function(){document.getElementById("list").innerHTML='<div class="skel">Не удалось загрузить данные</div>';});
}
(function(){
  var SUN='<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>';
  var MOON='<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>';
  var btn=document.getElementById("theme-btn");if(!btn)return;
  function cur(){return document.documentElement.getAttribute("data-theme")||((window.matchMedia&&matchMedia("(prefers-color-scheme: dark)").matches)?"dark":"light");}
  function setIcon(){btn.innerHTML=cur()==="dark"?SUN:MOON;}
  function apply(t){document.documentElement.setAttribute("data-theme",t);try{localStorage.setItem("sp-theme",t);}catch(e){}setIcon();}
  setIcon();
  btn.addEventListener("click",function(){apply(cur()==="dark"?"light":"dark");});
})();
window.addEventListener("resize",function(){
  var ps=document.querySelectorAll(".item.open .panel");
  for(var i=0;i<ps.length;i++)ps[i].style.maxHeight=ps[i].scrollHeight+"px";
});
load();
setInterval(function(){if(!document.hidden)load();},60000);
document.addEventListener("visibilitychange",function(){if(!document.hidden)load();});
</script>
</body>
</html>"""


_UNIQ_TOKENS = ["tchartwrap", "tcaption", "tchart", "tcanvas", "tscroll",
                "tyaxis", "tstats", "taxis", "phead", "sdot",
                "overall", "pgrad"]
_UNIQ_PREFIX = "c" + os.urandom(3).hex()


def _uniquify(s):
    for t in sorted(_UNIQ_TOKENS, key=len, reverse=True):
        s = re.sub(r'(?<![\w-])' + re.escape(t) + r'(?![\w-])', _UNIQ_PREFIX + t, s)
    return s


_TPL = _uniquify(INDEX_HTML)


def page_html():
    img = find_brand_image()
    if img:
        v = int(os.path.getmtime(img))
        fav = '<link rel="icon" href="/favicon.png?v=%d">' % v
        logo = ('<img src="/logo?v=%d" alt="" '
                'style="width:100%%;height:100%%;object-fit:cover;border-radius:inherit">' % v)
    else:
        fav = ""
        logo = DEFAULT_LOGO_SVG
    return (_TPL
            .replace("__TITLE__", TITLE)
            .replace("__SUBTITLE__", SUBTITLE)
            .replace("__DAYS__", str(DAYS))
            .replace("__FAVICON__", fav)
            .replace("__LOGO__", logo))


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def version_string(self):
        return SERVER_HEADER

    def _send(self, code, body, ctype, cache=NO_CACHE):
        data = body.encode("utf-8") if isinstance(body, str) else body
        gz = False
        ae = self.headers.get("Accept-Encoding", "")
        compressible = ("text/" in ctype or "json" in ctype
                        or "javascript" in ctype or "svg" in ctype)
        if compressible and "gzip" in ae and len(data) >= 256:
            data = gzip.compress(data, 6)
            gz = True
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Robots-Tag", "noindex, nofollow")
        self.send_header("Cache-Control", cache)
        if gz:
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Vary", "Accept-Encoding")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path in ("/", "/index.html"):
            self._send(200, page_html(), "text/html; charset=utf-8")
        elif path == "/api/summary":
            self._send(200, json.dumps(build_summary(), ensure_ascii=False),
                       "application/json; charset=utf-8")
        elif path == "/api/today":
            qs = parse_qs(parsed.query)
            sid = (qs.get("sid") or [""])[0]
            self._send(200, json.dumps(build_today(sid), ensure_ascii=False),
                       "application/json; charset=utf-8")
        elif path == "/api/day":
            qs = parse_qs(parsed.query)
            sid = (qs.get("sid") or [""])[0]
            date = (qs.get("date") or [""])[0]
            self._send(200, json.dumps(build_day(sid, date), ensure_ascii=False),
                       "application/json; charset=utf-8")
        elif path in ("/favicon.ico", "/favicon.png", "/logo"):
            img = find_brand_image()
            if not img:
                self._send(404, "Not Found", "text/plain; charset=utf-8")
                return
            ext = os.path.splitext(img)[1].lower()
            try:
                with open(img, "rb") as f:
                    blob = f.read()
                self._send(200, blob, IMG_EXT.get(ext, "application/octet-stream"), STATIC_CACHE)
            except Exception:
                self._send(404, "Not Found", "text/plain; charset=utf-8")
        elif path.startswith("/fonts/"):
            fn = os.path.basename(path)
            fp = os.path.join(FONT_DIR, fn)
            if fn.endswith(".woff2") and os.path.isfile(fp):
                with open(fp, "rb") as f:
                    blob = f.read()
                self._send(200, blob, "font/woff2", STATIC_CACHE)
            else:
                self._send(404, "Not Found", "text/plain; charset=utf-8")
        elif path == "/health":
            self._send(200, "OK", "text/plain; charset=utf-8")
        else:
            self._send(404, "Not Found", "text/plain; charset=utf-8")


def main():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    init_db()
    threading.Thread(target=ensure_fonts, daemon=True).start()
    threading.Thread(target=poller, daemon=True).start()
    print("xray-status on :%d, checker=%s, tz=%s" % (PORT, CHECKER_URL, TZ_NAME), flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
