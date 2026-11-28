"""gnoc_site.py - the user's OWN website (your-site.example) as something `gnoc chat` can answer about.

The site already measures itself: /healthz, /api/server-status and the ops console's /api/dashboard/overview
carry its security posture (a weighted scorecard with remediation), live users, store/database health, HTTP
and process stats, and the open alerts. Nothing here computes any of that - this is a reader.

WHAT IT DELIBERATELY DROPS. The overview payload also carries `sessions`, `security.events`, `bans`,
`watchlist`, `presence` and inbox message bodies: visitor IP addresses and private messages. Those must never
reach a model - a transcript is saved to disk, read by the distillation pipeline and shown in the office. So
every one of them is reduced to a COUNT on arrival, the same rule the office follows, and the raw rows are
dropped before this module returns. The ops tokens are read from the site's own .env (chmod 600, same user)
and only ever travel in a request header to 127.0.0.1.

The target is fixed: the loopback port from the site's .env, plus its own PUBLIC_URL for the edge check. No
argument reaches a URL, so this tool cannot be pointed at anything else.
"""
import json
import os
import re
import time
import urllib.error
import urllib.request

SITE_DIR = os.environ.get("GNOC_SITE_DIR", os.path.expanduser("~/gnoc-site"))
SITE_ENV = os.path.join(SITE_DIR, ".env")
SECTIONS = ("overview", "security", "users", "database", "traffic", "alerts")
_CACHE = {"ts": 0.0, "data": None}
CACHE_S = 10.0   # the console's own rate limit is 120/min; a chat turn may ask several times
# The last site_redteam drill, kept so this summary can say what the origin score cannot see (the edge) and so a
# second identical drill can say it changed nothing. 2026-11-27: site_status said "posture 100/100, every check
# passes" beside a drill that had just failed edge HSTS, and the lead reconciled the two by inventing "the edge
# must have been updated".
DRILL_SHOWN_S = 24 * 3600


def drill_path():
    return os.environ.get("GNOC_REDTEAM_LAST") or os.path.expanduser("~/.local/share/gnoc-chat/redteam-last.json")


def last_drill():
    try:
        with open(drill_path(), encoding="utf-8") as fh:
            rec = json.load(fh)
        return rec if isinstance(rec, dict) and rec.get("ts") else None
    except (OSError, ValueError):
        return None


def save_drill(rec):
    p = drill_path()
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(rec, fh)
        os.replace(tmp, p)
    except OSError:
        pass   # a drill that cannot be remembered is still a drill


def _mins(ts):
    m = max(0, int((time.time() - float(ts)) // 60))
    return "just now" if m < 1 else (f"{m} min ago" if m < 120 else f"{m // 60} h ago")


def _env():
    env = {}
    try:
        with open(SITE_ENV) as fh:
            for ln in fh:
                m = re.match(r"^\s*([A-Z_]+)\s*=\s*(.*)$", ln)
                if m:
                    env[m.group(1)] = m.group(2).strip().strip("\"'")
    except OSError:
        pass
    return env


def _get(url, headers, timeout=6):
    req = urllib.request.Request(url, headers=headers)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read(4_000_000)), (time.time() - t0) * 1000
    except urllib.error.HTTPError as e:
        with e:  # the error response is a live socket: close it, or every failed call leaks one
            return e.code, None, (time.time() - t0) * 1000
    except (OSError, ValueError):
        return 0, None, (time.time() - t0) * 1000


def _n(v, default=None):
    return v if isinstance(v, (int, float)) else default


def _mb(b):
    return round(b / 1e6, 1) if isinstance(b, (int, float)) else None


def _r(v, nd=1):
    return round(v, nd) if isinstance(v, (int, float)) else v


def _ago(ms):
    """'3m ago' from the site's epoch-millisecond timestamps (it reports instants, we answer in ages)."""
    if not isinstance(ms, (int, float)) or ms <= 0:
        return "never"
    secs = time.time() - (ms / 1000 if ms > 1e11 else ms)
    if secs < 0:
        return "just now"
    return _dur(secs) + " ago" if secs >= 60 else f"{int(secs)}s ago"


def _count(v):
    """How many, whatever shape it came in - and never WHAT. sessionsSnapshot() carries one row per live
    connection with its address; the size is the only part of it that may reach a model."""
    if isinstance(v, (list, tuple)):
        return len(v)
    if isinstance(v, dict):
        return v.get("total") if isinstance(v.get("total"), int) else len(v)
    return None


def read(force=False):
    """Everything the site reports about itself, already stripped of addresses, sessions and message bodies.
    Returns {"ok": bool, ...} and never raises: a site that is down is an answer, not an error."""
    now = time.time()
    if not force and _CACHE["data"] and now - _CACHE["ts"] < CACHE_S:
        return _CACHE["data"]
    env = _env()
    port = env.get("PORT") or "6969"
    pub = (env.get("PUBLIC_URL") or "").rstrip("/")
    host = re.sub(r"^https?://", "", pub).split("/")[0]
    base = f"http://127.0.0.1:{port}"
    out = {"ok": False, "host": host or None, "ts": now, "reached": False}

    code, j, ms = _get(base + "/healthz", {"x-healthz-token": env.get("HEALTHZ_DETAIL_TOKEN", "")})
    out["health"] = {"code": code, "ok": bool(j and j.get("ok")), "ms": round(ms), "version": (j or {}).get("version"),
                     "uptime_s": _n((j or {}).get("uptime")), "reason": (j or {}).get("reason")}
    out["reached"] = code != 0
    if not out["reached"]:
        out["why"] = f"nothing answered on {base} (the site process is not running, or PORT in its .env moved)"
        _CACHE.update(ts=now, data=out)
        return out

    token = env.get("OPS_ADMIN_TOKEN")
    if not token:
        out["why"] = "OPS_ADMIN_TOKEN is not in the site's .env: only /healthz is readable from here"
        _CACHE.update(ts=now, data=out)
        return out
    hdrs = {"x-ops-token": token}
    if host:  # loopback as the tunnel delivers it, or host validation refuses the read
        hdrs.update({"Host": host, "X-Forwarded-Proto": "https"})
    code, j, _ = _get(base + "/api/dashboard/overview?n=1", hdrs, 8)
    if not (j and j.get("ok")):
        out["why"] = f"the ops console answered HTTP {code}"
        _CACHE.update(ts=now, data=out)
        return out

    m = j.get("metrics") or {}
    sec = j.get("security") or {}
    pos = sec.get("posture") or {}
    com = j.get("community") or {}
    srv = j.get("server") or {}
    ctr = j.get("controls") or {}
    http_, proc, store = m.get("http") or {}, m.get("process") or {}, m.get("store") or {}
    one, five = http_.get("oneMinute") or {}, http_.get("fiveMinutes") or {}
    out.update({
        "ok": True,
        "server": {"version": srv.get("version"), "build": srv.get("build"), "uptime_s": _n(srv.get("uptime")),
                   "runtime": srv.get("runtime"), "last_wipe": srv.get("lastWipe"),
                   "mode": "maintenance" if ctr.get("maintenance") else "operational"},
        # the scorecard the site computes for itself: score, grade, and the checks that are not passing
        "security": {"watch_enabled": bool(sec.get("enabled")), "score": _n(pos.get("score")),
                     "grade": pos.get("grade"), "failing": _n(pos.get("failing"), 0),
                     "warnings": _n(pos.get("warnings"), 0),
                     "checks_bad": [{"label": c.get("label"), "status": c.get("status"),
                                     "detail": str(c.get("detail") or "")[:160],
                                     "fix": str(c.get("remediation") or "")[:160]}
                                    for c in (pos.get("checks") or []) if c.get("status") != "pass"],
                     "checks_passing": sum(1 for c in (pos.get("checks") or []) if c.get("status") == "pass"),
                     # COUNTS only: securityWatch.summary() windows, and how many addresses are banned
                     "probes": {k: (sec.get("summary") or {}).get(k) or {} for k in ("last15m", "last1h", "last24h")},
                     "active_bans": _n((sec.get("stats") or {}).get("activeBans"), 0),
                     "watchlist": len(sec.get("watchlist") or [])},
        "users": {"online": _n(com.get("onlineVisible")), "sockets": _n(com.get("socketsConnected")),
                  "public_rooms": _n(com.get("publicRooms")), "p2p_rooms": _n(com.get("p2pRooms")),
                  "pro_total": _n((com.get("pro") or {}).get("total")),
                  "pro_stripe_active": _n((com.get("pro") or {}).get("stripeActive")),
                  "pro_today": _n((com.get("pro") or {}).get("stripeToday")),
                  "certs_issued": _n(com.get("certsIssued")), "course_vaults": _n(com.get("courseVaults")),
                  "sessions": _count(j.get("sessions"))},
        # "database" = the persistent store: this site keeps its state in an encrypted file, not an engine
        "database": {"kind": "encrypted JSON store" if store.get("encrypted") else "plaintext JSON store",
                     "encrypted": bool(store.get("encrypted")), "read_only": bool(store.get("readOnly")),
                     "write_pending": bool(store.get("writePending")), "size_mb": _mb(store.get("fileBytes")),
                     "disk_free_mb": _mb(store.get("diskFreeBytes")), "disk_total_mb": _mb(store.get("diskTotalBytes")),
                     "last_write_ms": _r(_n(store.get("lastPersistDurationMs"))),
                     "last_write_at": store.get("lastPersistAt"),
                     "last_error": str(store.get("lastPersistError") or "")[:200] or None,
                     "last_error_at": store.get("lastPersistErrorAt")},
        "traffic": {"req_1m": _n(one.get("requests"), 0), "req_5m": _n(five.get("requests"), 0),
                    "lifetime": _n(http_.get("lifetime"), 0),
                    "err4xx_1m": _n(one.get("status4xx"), 0), "err5xx_1m": _n(one.get("status5xx"), 0),
                    "realtime_1m": _n((m.get("realtime") or {}).get("events1m"), 0),
                    "cpu_pct": _r(_n(proc.get("cpuPercent"))), "rss_mb": _mb(proc.get("rssBytes")),
                    "heap_used_mb": _mb(proc.get("heapUsedBytes")), "heap_limit_mb": _mb(proc.get("heapLimitBytes")),
                    "loop_lag_avg_ms": _r(_n(proc.get("eventLoopLagAvgMs")), 2),
                    "loop_lag_peak_ms": _r(_n(proc.get("eventLoopLagPeakMs")), 2),
                    "load_1m": _r(_n(proc.get("loadAverage1m"), 2))},
        "inbox": {"open": _n((j.get("inbox") or {}).get("open"), 0),
                  "emergencies": _n((j.get("inbox") or {}).get("emergencies"), 0)},
        # level + title + detail are the site's own words; no address or message body is in them
        "alerts": [{"level": a.get("level"), "title": str(a.get("title") or "")[:80],
                    "detail": str(a.get("detail") or "")[:160]} for a in (j.get("alerts") or [])][:8],
    })
    if pub:
        code, jj, ms = _get(pub + "/healthz", {"User-Agent": "gnoc-chat"}, 8)
        out["edge"] = {"code": code, "ok": bool(jj and jj.get("ok")), "ms": round(ms),
                       "note": "the real public path: Cloudflare edge -> tunnel -> this machine"}
    _CACHE.update(ts=now, data=out)
    return out


def _dur(s):
    if not isinstance(s, (int, float)) or s <= 0:
        return "?"
    d, h, m = int(s // 86400), int(s % 86400 // 3600), int(s % 3600 // 60)
    return f"{d}d{h:02d}h" if d else (f"{h}h{m:02d}m" if h else f"{m}m")


def summary(section="overview", force=False):
    """One plain-text report for the model to answer from. Sections: overview (everything, short), security,
    users, database, traffic, alerts."""
    section = (section or "overview").strip().lower()
    if section in ("db", "store"):
        section = "database"
    if section in ("stats", "performance", "perf"):
        section = "traffic"
    if section in ("posture", "sec"):
        section = "security"
    if section not in SECTIONS:
        return f"unknown section {section!r}: use one of {', '.join(SECTIONS)}"
    d = read(force=force)
    host = d.get("host") or "the site"
    if not d.get("reached"):
        return f"{host} IS NOT ANSWERING on loopback. {d.get('why', '')}\nThis is the site being down, not a read error."
    if not d.get("ok"):
        h = d.get("health") or {}
        return (f"{host}: /healthz says {'ok' if h.get('ok') else 'NOT ok'} (HTTP {h.get('code')}, {h.get('ms')} ms, "
                f"version {h.get('version')}). The rest is unreadable: {d.get('why', '')}")
    L = []
    srv, sec, usr, db, tr = d["server"], d["security"], d["users"], d["database"], d["traffic"]
    head = (f"{host} — {srv['mode']}, version {srv.get('version')} (build {srv.get('build')}), "
            f"up {_dur(srv.get('uptime_s'))}, health {'ok' if (d.get('health') or {}).get('ok') else 'FAILING'}")
    edge = d.get("edge")
    if edge:
        head += f"; public edge {'ok' if edge.get('ok') else 'HTTP ' + str(edge.get('code'))} ({edge.get('ms')} ms)"
    L.append(head)

    if section in ("overview", "security"):
        L.append(f"SECURITY: posture {sec.get('score')}/100 ({sec.get('grade')}), {sec.get('checks_passing')} checks "
                 f"passing, {sec.get('failing')} failing, {sec.get('warnings')} warning; GreyWatch "
                 f"{'on' if sec.get('watch_enabled') else 'OFF'}, {sec.get('active_bans')} active bans, "
                 f"{sec.get('watchlist')} on the watchlist")
        for w in ("last15m", "last1h", "last24h"):
            p = (sec.get("probes") or {}).get(w) or {}
            if p:
                L.append(f"  probes {w}: " + ", ".join(f"{k} {v}" for k, v in list(p.items())[:6]))
        for c in sec.get("checks_bad") or []:
            L.append(f"  {c['status'].upper()}: {c['label']} — {c['detail']} FIX: {c['fix']}")
        if not sec.get("checks_bad"):
            L.append("  every ORIGIN posture check passes (the site's own checklist: it cannot see what the "
                     "Cloudflare edge rewrites)")
        rec = last_drill()
        if rec and time.time() - float(rec["ts"]) < DRILL_SHOWN_S:
            failed = rec.get("failed") or []
            if failed:
                L.append(f"  LAST DRILL {rec.get('rid')} ({_mins(rec['ts'])}) FAILED {len(failed)}: "
                         + "; ".join(f"[{f.get('severity')}] {f.get('title')}" + (f" FIX: {f['fix']}" if f.get("fix")
                                                                                  else "") for f in failed)
                         + ". The posture score does not include these: the score and the drill are both true, "
                           "nothing has changed unless a NEW drill passes.")
            else:
                L.append(f"  LAST DRILL {rec.get('rid')} ({_mins(rec['ts'])}): nothing failed")
    if section in ("overview", "users"):
        L.append(f"USERS: {usr.get('online')} visible online, {usr.get('sockets')} live sockets, "
                 f"{usr.get('sessions')} tracked connections; {usr.get('pro_total')} active Pro "
                 f"({usr.get('pro_stripe_active')} on Stripe, {usr.get('pro_today')} today); "
                 f"{usr.get('public_rooms')} public rooms, {usr.get('p2p_rooms')} P2P rooms, "
                 f"{usr.get('certs_issued')} certs issued")
    if section in ("overview", "database"):
        L.append(f"DATABASE ({db['kind']}): {'READ-ONLY' if db.get('read_only') else 'writable'}, "
                 f"{db.get('size_mb')} MB, last write took {db.get('last_write_ms')} ms "
                 f"({_ago(db.get('last_write_at'))}), "
                 f"{'write pending' if db.get('write_pending') else 'no write pending'}; disk "
                 f"{db.get('disk_free_mb')} MB free of {db.get('disk_total_mb')} MB"
                 + (f"; LAST WRITE FAILED: {db['last_error']}" if db.get("last_error") else ""))
        if not db.get("encrypted"):
            L.append("  the store is PLAINTEXT on disk (STORE_ENCRYPTION_KEY_FILE is not set)")
    if section in ("overview", "traffic"):
        L.append(f"TRAFFIC: {tr.get('req_1m')} req/min ({tr.get('req_5m')} in 5 min, {tr.get('lifetime')} lifetime), "
                 f"{tr.get('err4xx_1m')} 4xx and {tr.get('err5xx_1m')} 5xx this minute, "
                 f"{tr.get('realtime_1m')} realtime events/min")
        L.append(f"PROCESS: cpu {tr.get('cpu_pct')}%, rss {tr.get('rss_mb')} MB, heap {tr.get('heap_used_mb')}/"
                 f"{tr.get('heap_limit_mb')} MB, event-loop lag {tr.get('loop_lag_avg_ms')} ms avg / "
                 f"{tr.get('loop_lag_peak_ms')} ms peak, load {tr.get('load_1m')}")
    if section in ("overview", "alerts"):
        inbox = d.get("inbox") or {}
        if d.get("alerts"):
            L.append("ALERTS: " + "; ".join(f"[{a['level']}] {a['title']}: {a['detail']}" for a in d["alerts"]))
        else:
            L.append("ALERTS: none open")
        L.append(f"INBOX: {inbox.get('open')} open ({inbox.get('emergencies')} emergency)")
    L.append("(read live from the site's own /healthz and ops console; visitor addresses, sessions and message "
             "bodies are counted, never read)")
    return "\n".join(L)
