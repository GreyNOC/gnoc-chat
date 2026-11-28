"""gnoc_alerts.py - the defender's alert queue: deduplicated, persistent, and reviewable.

A finding is a fact. An alert is a finding the user should see, with an owner and a life cycle.
This module is deliberately small and local: one append-only JSONL file plus a replay in memory.
Nothing is sent off the machine.

Life cycle: open -> ack -> resolved, or open -> suppressed (for a bounded time), or open -> reopened
when a repeat is more severe than the alert the user already acknowledged. A repeated finding does not
create a second alert: it increments the same alert's count and last_seen.

The renderer is used by `defend action=alerts`, `/defender alerts` and the watcher. It is plain text so
it reads the same in the chat panel, a log file, or a terminal without colour.
"""
import contextlib
import json
import os
import re
import threading
import time

# shared helpers (consolidated from the per-module copies)
from gnoc_core.util import _now_local as _now

_WS = os.environ.get("GNOC_WS") or (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
STATE = os.environ.get("GNOC_ALERT_STATE") or os.path.join(_WS, ".claude/state/defender")
STORE = os.path.join(STATE, "alerts.jsonl")
LOCK_FILE = os.path.join(STATE, ".alerts.lock")
_LOCK = threading.RLock()

SEVERITIES = ("critical", "high", "medium", "low", "info")
RANK = {s: i for i, s in enumerate(SEVERITIES)}
_ALIASES = {"crit": "critical", "critical": "critical", "high": "high", "warn": "medium",
            "warning": "medium", "medium": "medium", "moderate": "medium", "low": "low", "info": "info",
            "informational": "info"}
STATUSES = ("open", "ack", "resolved", "suppressed")
OPEN_STATES = ("open", "ack")


def severity(value):
    """Normalise a defender severity (crit/warn/high/info) to the alert vocabulary."""
    return _ALIASES.get(str(value or "").strip().lower(), "info")


def rank(value):
    return RANK.get(severity(value), len(SEVERITIES) - 1)


def at_least(value, minimum):
    return rank(value) <= rank(minimum)




_CTRL = re.compile("\x1b\\[[0-?]*[ -/]*[@-~]|[\x00-\x08\x0b-\x1f\x7f\u202a-\u202e\u2066-\u2069]")


def _clean(text, limit=600):
    """One line for a table cell, with ANSI escapes, bidi overrides and control characters removed."""
    s = _CTRL.sub("", str(text or ""))
    s = re.sub(r"\s+", " ", s).strip()
    return s[:limit]


def _items(value, limit=24):
    if isinstance(value, (list, tuple)):
        return [_clean(x, 400) for x in value if _clean(x, 400)][:limit]
    s = _clean(value, 400)
    return [s] if s else []


def _int(value, default=0, low=None, high=None):
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    if low is not None:
        n = max(low, n)
    if high is not None:
        n = min(high, n)
    return n


def _host_key(host):
    return re.sub(r"[^A-Za-z0-9_.:@-]", "_", str(host or "local"))[:80]


def _path():
    return STORE


@contextlib.contextmanager
def _file_lock():
    """Serialise writers between two chats. The lock file is separate from the data file so a
    crash can never leave the JSONL half-locked."""
    d = os.path.dirname(_path()) or "."
    os.makedirs(d, mode=0o700, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    lock = os.path.join(d, ".alerts.lock")
    with open(lock, "a+") as fh:
        try:
            os.chmod(lock, 0o600)
        except OSError:
            pass
        try:
            import fcntl
            fcntl.flock(fh, fcntl.LOCK_EX)
        except (ImportError, OSError):
            pass
        try:
            yield
        finally:
            try:
                import fcntl
                fcntl.flock(fh, fcntl.LOCK_UN)
            except (ImportError, OSError):
                pass


def _read_events():
    rows = []
    try:
        with open(_path(), encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if isinstance(row, dict) and row.get("id"):
                    rows.append(row)
    except OSError:
        pass
    return rows


def _replay():
    """{id: alert} rebuilt from the append-only event file. Every event is a full snapshot of the
    alert at that moment, so replay is last-write-wins and needs no schema migration."""
    alerts = {}
    for row in _read_events():
        aid = _clean(row.get("id"), 40)
        if not aid:
            continue
        current = alerts.get(aid)
        history = list(current.get("history") or []) if current else []
        event = row.get("event") or "update"
        if event != "compact" and (row.get("ts") or row.get("note") or row.get("by")):
            history.append({"ts": row.get("ts") or "", "event": event,
                            "by": row.get("by") or "", "note": _clean(row.get("note"), 300)})
        if not current and isinstance(row.get("history"), list):
            history = [h for h in row["history"] if isinstance(h, dict)][-40:]   # a compacted snapshot
        snapshot = {k: v for k, v in row.items() if k not in ("event", "note", "by")}
        snapshot["history"] = history[-40:]
        alerts[aid] = snapshot
    return alerts


def _ends_clean(path):
    """False when the file's last byte is not a newline: a crash mid-write left a torn line, and the next
    event appended to it would be glued onto the garbage and lost on replay."""
    try:
        with open(path, "rb") as fh:
            fh.seek(-1, os.SEEK_END)
            return fh.read(1) == b"\n"
    except OSError:
        return True   # missing or empty


def _append(row):
    d = os.path.dirname(_path()) or "."
    os.makedirs(d, mode=0o700, exist_ok=True)
    row = {k: v for k, v in row.items() if k != "history"}  # history is rebuilt from events
    lead = "" if _ends_clean(_path()) else "\n"
    fd = os.open(_path(), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        fh.write(lead + json.dumps(row, sort_keys=True, default=str) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    try:
        os.chmod(_path(), 0o600)
    except OSError:
        pass


COMPACT_BYTES = 4 * 1024 * 1024
RESOLVED_KEEP_DAYS = 30


def _maybe_compact(alerts):
    """Every repeat appends a full snapshot, so a noisy finding grows the file without bound and every write
    replays all of it. Past COMPACT_BYTES, rewrite it as one snapshot per alert (history carried inside),
    dropping resolved/expired-suppressed alerts older than RESOLVED_KEEP_DAYS. Caller holds the locks."""
    try:
        if os.path.getsize(_path()) < COMPACT_BYTES:
            return alerts
    except OSError:
        return alerts
    cutoff = time.time() - RESOLVED_KEEP_DAYS * 86400
    keep = {}
    for aid, a in alerts.items():
        st = a.get("status")
        stale = (st == "resolved" or (st == "suppressed" and _int(a.get("suppress_until"), 0) <= time.time()))
        if stale and _epoch(a.get("last_seen")) < cutoff:
            continue
        keep[aid] = a
    tmp = f"{_path()}.{os.getpid()}.{threading.get_ident()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        for a in keep.values():
            fh.write(json.dumps(dict(a, event="compact"), sort_keys=True, default=str) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, _path())
    return keep


def _new_id(alerts):
    day = time.strftime("%Y%m%d")
    prefix = f"A-{day}-"
    nums = [int(a.split("-")[-1]) for a in alerts if a.startswith(prefix) and a.split("-")[-1].isdigit()]
    return f"{prefix}{(max(nums) + 1) if nums else 1:04d}"


def _find_dedup(alerts, host, dedup):
    """The LIVE alert for host+dedup, newest first. A suppressed alert whose window has expired is not live:
    returning it (the oldest match) made every later repeat open yet another new alert, forever."""
    now = time.time()
    best = None
    for a in alerts.values():
        if a.get("host") != host or a.get("dedup") != dedup:
            continue
        st = a.get("status")
        if st not in ("open", "ack", "suppressed"):
            continue
        if st == "suppressed" and _int(a.get("suppress_until"), 0) <= now:
            continue
        if best is None or str(a.get("last_seen") or "") >= str(best.get("last_seen") or ""):
            best = a
    return best


def raise_alert(host="local", severity_="high", category="defender", title="", summary="", asset="",
                evidence=None, dedup="", source="defender", confidence=None, mitre="", note="",
                by="defender"):
    """Raise or repeat an alert. -> (alert snapshot, created: bool).

    `dedup` is the finding's stable key. The same host + dedup while an alert is open/ack/suppressed
    updates that alert instead of adding one. A suppressed alert whose window has expired is allowed
    to become a new alert.
    """
    sev = severity(severity_)
    host = _clean(host, 80) or "local"
    category = _clean(category, 60) or "defender"
    source = _clean(source, 60) or "defender"
    by = _clean(by, 60) or "defender"
    mitre = _clean(mitre, 120)
    title = _clean(title, 180) or _clean(summary, 180) or "defender finding"
    dedup = _clean(dedup or f"{category}|{asset}|{title}", 240)
    evidence = _items(evidence)
    with _LOCK, _file_lock():
        alerts = _maybe_compact(_replay())
        old = _find_dedup(alerts, host, dedup)
        if old:
            prev = old.get("severity")
            old["count"] = _int(old.get("count"), 1, 1) + 1
            old["last_seen"] = _now()
            old["severity"] = sev if rank(sev) < rank(prev) else prev
            old["summary"] = _clean(summary or old.get("summary"), 1200)
            old["evidence"] = list(dict.fromkeys(_items(old.get("evidence"), 24) + evidence))[-24:]
            # An acknowledged alert reopens only when the repeat is WORSE than what was acknowledged; a steady
            # critical repeat of the same evidence is what the operator already acked.
            if old.get("status") == "ack" and rank(sev) < rank(prev):
                old["status"] = "open"
                old["event"] = "reopened"
            else:
                old["event"] = "repeat"
            if note:
                old["note"] = _clean(note, 600)
            old["by"] = by
            old["ts"] = _now()
            _append(old)
            return old, False
        aid = _new_id(alerts)
        row = {"id": aid, "ts": _now(), "event": "open", "status": "open", "host": host, "severity": sev,
               "category": category, "title": title, "summary": _clean(summary, 1200), "asset": _clean(asset, 160),
               "evidence": evidence, "dedup": dedup, "source": source, "confidence": confidence, "mitre": mitre,
               "count": 1, "first_seen": _now(), "last_seen": _now(), "by": by, "note": _clean(note, 600)}
        _append(row)
        return dict(row, history=[{"ts": row["ts"], "event": "open", "by": by, "note": ""}]), True


def get(alert_id):
    return _replay().get(str(alert_id or "").strip().upper())


def ack(alert_id, by="The user", note=""):
    return _set_status(alert_id, "ack", by, note, "ack")


def resolve(alert_id, note="", by="The user"):
    return _set_status(alert_id, "resolved", by, note, "resolve")


def reopen(alert_id, note="", by="The user"):
    return _set_status(alert_id, "open", by, note, "reopen")


def suppress(alert_id_or_dedup, reason="", ttl=3600, by="The user"):
    """Suppress an alert by id, or every open alert with this dedup, for ttl seconds (60..2592000)."""
    ttl = _int(ttl, 3600, 60, 30 * 86400)
    key = _clean(alert_id_or_dedup, 240)
    with _LOCK, _file_lock():
        alerts = _replay()
        hit = alerts.get(key.upper()) or _find_dedup(alerts, alerts.get(key.upper(), {}).get("host", ""), key)
        if not hit:
            for a in alerts.values():
                if a.get("dedup") == key and a.get("status") in ("open", "ack"):
                    hit = a
                    break
        if not hit:
            return None
        hit["status"] = "suppressed"
        hit["suppress_until"] = time.time() + ttl
        hit["ts"] = _now()
        hit["event"] = "suppress"
        hit["by"] = _clean(by, 60) or "The user"
        hit["note"] = _clean(reason, 600)
        _append(hit)
        return hit


def _set_status(alert_id, status, by, note, event):
    with _LOCK, _file_lock():
        alerts = _replay()
        hit = alerts.get(str(alert_id or "").strip().upper())
        if not hit:
            return None
        hit["status"] = status
        hit["ts"] = _now()
        hit["event"] = event
        hit["by"] = _clean(by, 60) or "The user"
        hit["note"] = _clean(note, 600)
        _append(hit)
        return hit


def listing(status="open", minimum="info", limit=50):
    alerts = _replay()
    want = set(OPEN_STATES) if status in (None, "", "open") else {str(status).lower()}
    rows = [a for a in alerts.values() if a.get("status") in want and at_least(a.get("severity"), minimum)]
    rows.sort(key=lambda a: (rank(a.get("severity")), -_epoch(a.get("last_seen"))))
    return rows[:max(1, _int(limit, 50))]


def counts():
    alerts = _replay()
    out = {"open": 0, "ack": 0, "resolved": 0, "suppressed": 0, "critical": 0, "high": 0, "medium": 0}
    for a in alerts.values():
        out[a.get("status", "open")] = out.get(a.get("status", "open"), 0) + 1
        if a.get("status") in OPEN_STATES:
            sev = severity(a.get("severity"))
            out[sev] = out.get(sev, 0) + 1
    return out


def _epoch(ts):
    try:
        return time.mktime(time.strptime(str(ts), "%Y-%m-%dT%H:%M:%S"))
    except (ValueError, OverflowError):
        return 0.0


def age(ts):
    secs = max(0, int(time.time() - _epoch(ts)))
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m"
    if secs < 86400:
        return f"{secs // 3600}h"
    return f"{secs // 86400}d"


def render(limit=30, status="open", minimum="info"):
    rows = listing(status=status, minimum=minimum, limit=limit)
    c = counts()
    head = (f"ALERT QUEUE  {time.strftime('%Y-%m-%d %H:%M:%S')}  "
            f"open {c['open'] + c['ack']} (critical {c['critical']}, high {c['high']}, medium {c['medium']})")
    if not rows:
        return head + "\n  no alerts match (status " + str(status) + ", minimum " + str(minimum) + ")"
    lines = [head, "  " + "-" * 120,
             f"  {'ID':<18} {'SEVERITY':<9} {'AGE':<5} {'COUNT':<5} {'HOST':<18} {'ASSET':<18} SIGNAL",
             "  " + "-" * 120]
    for a in rows:
        lines.append(f"  {a.get('id', '?'):<18} {severity(a.get('severity')).upper():<9} "
                     f"{age(a.get('last_seen')):<5} {int(a.get('count') or 1):<5} "
                     f"{_clean(a.get('host'), 18):<18} {_clean(a.get('asset'), 18):<18} "
                     f"{_clean(a.get('title'), 80)}")
    if any(a.get("status") == "ack" for a in rows):
        lines.append("  " + "-" * 120 + "\n  (ACK = acknowledged; it stays in the queue until resolved)")
    lines.append("  use defend(action=alerts, id=<ID>) for evidence, or /defender alerts ack|resolve <ID>")
    return "\n".join(lines)


def render_detail(alert):
    if not alert or not isinstance(alert, dict):
        return "no such alert"
    c = severity(alert.get("severity")).upper()
    lines = [f"{_clean(alert.get('id'), 24)}  [{c}]  {_clean(alert.get('status'), 20).upper()}",
             f"  host:     {_clean(alert.get('host'), 80)}",
             f"  asset:    {_clean(alert.get('asset'), 80) or '-'}",
             f"  title:    {_clean(alert.get('title'), 200)}",
             f"  summary:  {_clean(alert.get('summary'), 1200) or '-'}",
             f"  first:    {_clean(alert.get('first_seen'), 30)}   last: {_clean(alert.get('last_seen'), 30)}   "
             f"count: {_int(alert.get('count'), 1, 1)}"]
    if alert.get("confidence") is not None:
        lines.append(f"  confidence: {_int(alert.get('confidence'), 0, 0)}%")
    if alert.get("mitre"):
        lines.append(f"  technique: {_clean(alert.get('mitre'), 120)}")
    evidence = _items(alert.get("evidence"), 24)
    if evidence:
        lines.append("  evidence:")
        lines += [f"    - {x}" for x in evidence]
    if alert.get("note"):
        lines.append(f"  note:     {_clean(alert.get('note'), 600)}")
    history = [h for h in (alert.get("history") or []) if isinstance(h, dict)]
    if history:
        lines.append("  history:")
        lines += [f"    {_clean(h.get('ts'), 30)} {_clean(h.get('event'), 30)} {_clean(h.get('by'), 40)} "
                  f"{_clean(h.get('note'), 300)}".rstrip() for h in history[-10:]]
    return "\n".join(lines)
