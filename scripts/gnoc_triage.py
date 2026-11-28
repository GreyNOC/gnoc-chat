"""gnoc_triage.py - incident triage for the defender.

A finding says what is true on a host. Triage decides whether the evidence adds up to an intruder who is
ACTIVE right now, and if so opens a numbered incident with a priority, a response clock, a playbook and a
timeline. The scoring is deterministic and local: the same findings produce the same verdict, and every
point is attached to the finding that earned it. Nothing here contacts a gateway, an API or the internet.

An active intrusion is deliberately hard to declare:
  - malware/reverse-shell execution needs a corroborating network or persistence signal,
  - a gateway MAC change is treated as impersonation (MITM) and is active on its own,
  - an ARP conflict or a rogue DHCP server is active on its own,
  - an exposed dangerous port, a port scan or a new device is NEVER enough on its own.
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
STATE = os.environ.get("GNOC_TRIAGE_STATE") or os.path.join(_WS, ".claude/state/defender")
STORE = os.path.join(STATE, "triage.jsonl")
_LOCK = threading.RLock()

PRIORITIES = ("P1", "P2", "P3", "P4")
SLA_MINUTES = {"P1": 15, "P2": 60, "P3": 240, "P4": 1440}
OPEN_STATES = ("open", "triage", "contained", "eradicated", "recovered")
CLOSED_STATES = ("closed", "false_positive")
_SEV_RANK = {"crit": 0, "critical": 0, "high": 1, "warn": 2, "medium": 2, "low": 3, "info": 4}




_CTRL = re.compile("\x1b\\[[0-?]*[ -/]*[@-~]|[\x00-\x08\x0b-\x1f\x7f\u202a-\u202e\u2066-\u2069]")


def _clean(text, limit=800):
    s = _CTRL.sub("", str(text or ""))
    s = re.sub(r"\s+", " ", s).strip()
    return s[:limit]


def _sev_rank(value):
    return _SEV_RANK.get(str(value or "").lower(), 4)


def _prio(value):
    return value if value in PRIORITIES else "P4"


def _int(value, default=0, low=0):
    try:
        return max(low, int(value))
    except (TypeError, ValueError):
        return default


def _items(value, limit=60):
    if isinstance(value, (list, tuple)):
        return [_clean(x, 400) for x in value if _clean(x, 400)][:limit]
    s = _clean(value, 400)
    return [s] if s else []


def _path():
    return STORE


@contextlib.contextmanager
def _file_lock():
    """Serialise incident writes between two chat processes and keep the store private."""
    d = os.path.dirname(_path()) or "."
    os.makedirs(d, mode=0o700, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    with open(os.path.join(d, ".triage.lock"), "a+") as fh:
        try:
            os.chmod(fh.name, 0o600)
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


def _append(row):
    d = os.path.dirname(_path()) or "."
    os.makedirs(d, mode=0o700, exist_ok=True)
    row = {k: v for k, v in row.items() if k != "timeline"}  # timeline is rebuilt from events
    fd = os.open(_path(), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, sort_keys=True, default=str) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    try:
        os.chmod(_path(), 0o600)
    except OSError:
        pass


def _replay():
    cases = {}
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
                if not isinstance(row, dict) or not row.get("id"):
                    continue
                cid = str(row["id"])
                old = cases.get(cid)
                timeline = list(old.get("timeline") or []) if old else []
                if row.get("event") and row.get("event") != "update":
                    timeline.append({"ts": row.get("ts") or "", "event": row["event"],
                                     "by": row.get("by") or "", "note": _clean(row.get("note"), 400)})
                snapshot = {k: v for k, v in row.items() if k not in ("event", "by", "note")}
                snapshot["timeline"] = timeline[-80:]
                cases[cid] = snapshot
    except OSError:
        pass
    return cases


def _new_id(cases):
    day = time.strftime("%Y%m%d")
    prefix = f"IR-{day}-"
    nums = [int(c.split("-")[-1]) for c in cases if c.startswith(prefix) and c.split("-")[-1].isdigit()]
    return f"{prefix}{(max(nums) + 1) if nums else 1:03d}"


def _extract_assets(findings):
    assets = []
    for f in findings:
        text = f"{f.get('fact', '')} {f.get('id', '')} {f.get('asset', '')}"
        for m in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
            assets.append(m)
        for m in re.findall(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b", text):
            assets.append(m.lower())
    return sorted(set(assets))[:30]


def _signal(key, points, why, finding, active=False):
    return {"key": key, "points": int(points), "why": why, "finding": finding.get("id", ""),
            "active": bool(active)}


def _signals(findings):
    out = []
    for f in findings:
        fid = str(f.get("id") or "")
        area = str(f.get("area") or "").lower()
        fact = str(f.get("fact") or "")
        low = (fid + " " + fact).lower()
        sev = _sev_rank(f.get("sev"))
        if area == "process" or fid.startswith("proc:"):
            if sev == 0:
                points = 45 if ("talks to" in low or "public" in low or "->" in low) else 30
                out.append(_signal("process-exec", points,
                                   "code with a malware/reverse-shell signature is running", f,
                                   active=points >= 45))
            elif sev == 1:
                out.append(_signal("process-suspicious", 12, "a suspicious process is running", f))
        if area == "connection" or fid.startswith("conn:"):
            if "public" in low or "suspect" in low or "mining" in low or "c2" in low or "rat" in low:
                out.append(_signal("c2-connection", 20,
                                   "a process holds a connection to a suspicious public service", f, active=True))
        if area == "gateway" or fid.startswith("net:gw:"):
            if "mac changed" in low or "changed mac" in low or "spoof" in low or "mitm" in low:
                out.append(_signal("gateway-impersonation", 60,
                                   "the default gateway's MAC address changed (ARP spoof / MITM)", f, active=True))
            elif re.search(r"\b(unreachable|down)\b", low):
                out.append(_signal("gateway-down", 20, "the default gateway is unreachable", f))
            elif re.search(r"\b(telnet|tr-?069|upnp|admin)\b", low):
                out.append(_signal("gateway-exposure", 8, "the gateway exposes a risky admin surface", f))
        if area == "arp" or fid.startswith("net:arp:"):
            if "mac changed" in low or "different mac" in low:
                out.append(_signal("arp-spoof", 50,
                                   "an IP changed its MAC address (ARP spoof / IP conflict)", f, active=True))
            elif "duplicate" in low or "same mac" in low or "one mac" in low:
                out.append(_signal("arp-duplicate", 45,
                                   "one MAC is claiming several IP addresses (ARP spoof)", f, active=True))
            elif "new device" in low:
                out.append(_signal("new-device", 3, "a new device appeared on the LAN", f))
        if area == "dhcp" or fid.startswith("net:dhcp:"):
            if "rogue" in low:
                out.append(_signal("rogue-dhcp", 55,
                                   "a DHCP server other than the known gateway answered", f, active=True))
        if area == "wlan" or fid.startswith("net:wlan:"):
            if any(x in low for x in ("evil twin", "open twin", "security downgrade", "security changed",
                                      "open/none")):
                out.append(_signal("evil-twin", 40,
                                   "the Wi-Fi access point changed security or a twin is present", f, active=True))
            elif "bssid" in low or "ssid" in low:
                out.append(_signal("wlan-change", 15, "the Wi-Fi association changed", f))
        if area == "logins" or fid.startswith("brute:"):
            if "success" in low or "accepted" in low or "logged in" in low:
                out.append(_signal("success-after-failure", 55,
                                   "a login succeeded after failures (possible brute-force success)", f, active=True))
            elif "failed" in low:
                out.append(_signal("brute-force", 8, "a source is failing logins (recon)", f))
        if area == "persistence" or fid.startswith("persist:"):
            # Code installed to run AGAIN (a reverse shell in a unit or cron line, a preload outside the
            # library dirs) is evidence someone already ran code here: an intrusion, not an exposure.
            if sev == 0:
                points = 50 if "ld.so.preload" in low else 45
                out.append(_signal("persistence-implant", points,
                                   "a persistence entry runs a reverse shell, miner or rootkit hook", f, active=True))
            elif sev == 1:
                out.append(_signal("persistence-suspicious", 12,
                                   "a persistence entry runs code from a temp dir or hooks credentials", f))
        if area == "drift" or fid.startswith("drift:"):
            if fid.startswith("drift:key:"):
                out.append(_signal("new-ssh-key", 20, "a new SSH key can log in since the baseline", f))
            elif "ld.so.preload" in low:
                out.append(_signal("preload-drift", 45, "the loader preload list changed since the baseline", f,
                                   active=True))
            else:
                out.append(_signal("host-drift", 4, "a persistence file or listening port changed", f))
        if area == "port":
            if sev == 0:
                out.append(_signal("critical-exposure", 6, "a critical service is reachable", f))
            elif sev == 1:
                out.append(_signal("sensitive-exposure", 2, "a sensitive service is reachable", f))
        if area == "packets":
            if "port scan" in low or "probed" in low:
                out.append(_signal("port-scan", 5, "a source is scanning ports (recon)", f))
            elif "syn cookie" in low or "syn flood" in low:
                out.append(_signal("syn-flood", 15, "a SYN flood is filling the listen queue", f))
    return out


def assess(findings, network_findings=None, profile=None):
    """Score findings. -> {active, confidence, priority, kind, score, reasons, active_signals, evidence}.

    `profile` is accepted for future policy (for example, a known red-team exercise) and is not required.
    """
    all_findings = list(findings or []) + list(network_findings or [])
    sigs = _signals(all_findings)
    score = sum(s["points"] for s in sigs)
    active_sigs = [s for s in sigs if s["active"] and s["points"] >= 40]
    active_keys = {s["key"] for s in sigs if s["active"]}
    # Exposure alone never adds up to an intrusion, however many ports are open. There must be at least one
    # active signal (execution, C2, gateway impersonation, ARP spoof, rogue DHCP, evil twin, brute success).
    active = bool(active_sigs) or (score >= 80 and bool(active_keys))
    if active:
        score = min(99, score + 8)
    confidence = min(99, max(0, score))
    if active and confidence < 60:
        confidence = 60
    # P1: two independent active signals, or one unambiguous one (gateway impersonation, ARP spoof,
    # rogue DHCP, a login that succeeded after brute force), or malware execution plus its C2.
    strong = (len(active_keys) >= 2 or any(s["points"] >= 50 for s in active_sigs)
              or {"process-exec", "c2-connection"} <= active_keys)
    if active and strong:
        priority = "P1"
    elif active:
        priority = "P2"
    elif score >= 35:
        priority = "P3"
    else:
        priority = "P4"
    reasons = []
    seen = set()
    for s in sorted(sigs, key=lambda x: (-x["points"], x["key"])):
        if s["key"] in seen:
            continue
        seen.add(s["key"])
        reasons.append(f"{s['why']} ({s['finding'] or s['key']})")
    kind = ("active intrusion" if active else
            "suspected intrusion" if priority == "P3" else
            "exposure or reconnaissance" if score else "no intrusion signal")
    return {"active": active, "confidence": confidence, "priority": priority, "kind": kind,
            "score": score, "reasons": reasons[:10], "active_signals": [s["key"] for s in active_sigs],
            "evidence": sorted({s["finding"] for s in sigs if s["finding"]}),
            "assets": _extract_assets(all_findings), "findings": len(all_findings)}


def _playbook(assessment, findings):
    low = " ".join(f"{f.get('id', '')} {f.get('fact', '')}" for f in findings).lower()
    contain = []
    if "process" in low or "reverse shell" in low or "miner" in low:
        contain.append("Pause (not kill) the offending PID, capture /proc/<pid>/exe, maps, cmdline and open sockets, "
                       "then remove its binary and the unit/cron/autostart that restarted it.")
    if "gateway" in low or "arp" in low or "dhcp" in low:
        contain.append("Treat the LAN as untrusted: verify the gateway MAC on the router's own page, check the "
                       "switch/AP client list for the offending MAC, and quarantine that MAC at the port or host.")
    if "persist" in low or "drift:" in low:
        contain.append("Copy the persistence file aside for evidence, disable the unit/cron/autostart/preload entry, "
                       "check which package owns the file (dpkg -S / rpm -qf), and remove any new SSH key you did "
                       "not add.")
    if "brute" in low or "logins" in low:
        contain.append("Block the public source IP, keep SSH password login off, and review every successful login.")
    if not contain:
        contain.append("Confirm the evidence and preserve volatile state (connections, processes, logs) before changes.")
    steps = [
        {"step": "verify", "title": "Verify and preserve evidence",
         "detail": "Re-read the evidence, save the finding ids and the timestamped command output, and decide whether "
                   "this is a true positive before touching anything.",
         "status": "doing" if assessment["active"] else "todo", "owner": "The user"},
        {"step": "contain", "title": "Contain the intrusion",
         "detail": " ".join(contain),
         "status": "todo", "owner": "The user"},
        {"step": "eradicate", "title": "Remove the intruder's foothold",
         "detail": "Remove the binary, persistence (systemd unit, cron, autostart), rogue DHCP/AP configuration and "
                   "any new accounts or keys. Rotate credentials that were exposed.",
         "status": "todo", "owner": "The user"},
        {"step": "recover", "title": "Recover and verify",
         "detail": "Reboot or restart into a known-good state, patch the entry point, and re-run the defender sweep "
                   "until the finding is gone. Confirm the gateway and Wi-Fi state from the router itself.",
         "status": "todo", "owner": "The user"},
        {"step": "review", "title": "Review and close",
         "detail": "Record the root cause, the detection gap and the rule that caught it; close the case only when "
                   "the evidence is preserved and the entry point is fixed.",
         "status": "todo", "owner": "The user"},
    ]
    return steps


def open_case(host, findings, assessment, alert_ids=None, profile=None, containment=None):
    """Open a new incident, or fold this sweep into the open incident for the same host. -> (case, created)."""
    host = _clean(host or "local", 80)
    findings = [f for f in (findings or []) if isinstance(f, dict)]
    assessment = assessment if isinstance(assessment, dict) else {}
    containment = _items(containment, 20)
    with _LOCK, _file_lock():
        cases = _replay()
        live = [c for c in cases.values() if c.get("host") == host and c.get("status") in OPEN_STATES]
        if live:
            case = sorted(live, key=lambda c: c.get("created", ""))[-1]
            case["updated"] = _now()
            case["evidence"] = list(dict.fromkeys(_items(case.get("evidence"), 60) + _items(assessment.get("evidence"), 60)))[-60:]
            case["alert_ids"] = list(dict.fromkeys(_items(case.get("alert_ids"), 80) + _items(alert_ids, 80)))[-80:]
            case["confidence"] = max(_int(case.get("confidence"), 0),
                                     _int(assessment.get("confidence"), 0))
            was = _prio(case.get("priority"))
            case["priority"] = min(was, _prio(assessment.get("priority")), key=lambda p: PRIORITIES.index(p))
            # An escalation (P4 -> P1, suspected -> active) restarts the response clock at the NEW priority and
            # renames the case: a P1 showing "23h left" and "SUSPECTED INTRUSION" is how a real one gets ignored.
            escalated = PRIORITIES.index(case["priority"]) < PRIORITIES.index(was)
            if assessment.get("active") and not case.get("active"):
                case["active"] = True
                escalated = True
            if escalated:
                due = min(_epoch(case.get("sla_due")) or float("inf"),
                          time.time() + SLA_MINUTES.get(case["priority"], 1440) * 60)
                case["sla_due"] = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(due))
                reasons_now = _items(assessment.get("reasons"), 12)
                case["title"] = _clean(("ACTIVE INTRUSION" if case.get("active") else "SUSPECTED INTRUSION")
                                       + " on " + host + ": " + (reasons_now[0] if reasons_now else
                                                                 "defender evidence"), 400)
                case["kind"] = _clean(assessment.get("kind"), 80) or case.get("kind")
                if not any(isinstance(x, dict) and x.get("status") == "done" for x in case.get("playbook") or []):
                    case["playbook"] = _playbook(assessment, findings)   # never wipe steps already done
            case["reasons"] = list(dict.fromkeys(_items(case.get("reasons"), 12) + _items(assessment.get("reasons"), 12)))[-12:]
            if containment:
                case["containment"] = list(dict.fromkeys(_items(case.get("containment"), 20) + containment))[-20:]
            case["event"] = "update"
            case["ts"] = _now()
            _append(case)
            return case, False
        cid = _new_id(cases)
        priority = _prio(assessment.get("priority"))
        due = time.time() + SLA_MINUTES.get(priority, 1440) * 60
        reasons = _items(assessment.get("reasons"), 12)
        title = (("ACTIVE INTRUSION" if assessment.get("active") else "SUSPECTED INTRUSION")
                 + " on " + host + ": " + (reasons[0] if reasons else "defender evidence"))
        case = {"id": cid, "ts": _now(), "event": "open", "status": "open", "phase": "triage",
                "host": host, "created": _now(), "updated": _now(),
                "priority": priority, "confidence": _int(assessment.get("confidence"), 0),
                "active": bool(assessment.get("active")), "kind": _clean(assessment.get("kind"), 80)
                or "suspected intrusion",
                "title": _clean(title, 400), "summary": _clean(" ".join(reasons), 1200),
                "assets": _items(assessment.get("assets"), 30), "evidence": _items(assessment.get("evidence"), 60),
                "alert_ids": _items(alert_ids, 80), "reasons": reasons,
                "containment": containment,
                "playbook": _playbook(assessment, findings), "sla_due": time.strftime(
                    "%Y-%m-%dT%H:%M:%S", time.localtime(due)), "by": "defender"}
        _append(case)
        case["timeline"] = [{"ts": case["ts"], "event": "open", "by": "defender", "note": case["summary"][:300]}]
        return case, True


def get_case(case_id):
    return _replay().get(str(case_id or "").strip().upper())


def listing(status=None, limit=50):
    cases = _replay()
    want = set(OPEN_STATES) if status in (None, "", "open") else {str(status).lower()}
    rows = [c for c in cases.values() if c.get("status") in want]
    rows.sort(key=lambda c: (PRIORITIES.index(c.get("priority")) if c.get("priority") in PRIORITIES else 9,
                             -_epoch(c.get("updated"))))
    return rows[:max(1, _int(limit, 50))]


def _epoch(ts):
    try:
        return time.mktime(time.strptime(str(ts), "%Y-%m-%dT%H:%M:%S"))
    except (ValueError, OverflowError):
        return 0.0


def update_case(case_id, op="note", note="", step="", by="The user"):
    """Advance one incident. op: note | ack | contain | eradicate | recover | close | false_positive | step."""
    op = str(op or "note").lower()
    steps = {"ack": "triage", "contain": "contained", "eradicate": "eradicated", "recover": "recovered",
             "close": "closed", "closed": "closed", "false_positive": "false_positive", "note": None,
             "step": None}
    if op not in steps:
        return None
    with _LOCK, _file_lock():
        cases = _replay()
        case = cases.get(str(case_id or "").strip().upper())
        if not case:
            return None
        # A closed case is a record, not a state machine: advancing it again would silently reopen it.
        if case.get("status") in CLOSED_STATES and op != "note":
            return None
        if op == "step":
            matched = False
            for s in case.get("playbook") or []:
                if isinstance(s, dict) and s.get("step") == step:
                    s["status"] = "done"
                    matched = True
            if not matched:
                return None
        # Forward-only: ack after contain must not drag a contained case back to "triage". close and
        # false_positive end a case from any phase (the operator's call); note/step never move it.
        order = ("open", "triage", "contained", "eradicated", "recovered")
        new = steps[op]
        if new in order and case.get("status") in order and order.index(new) < order.index(case["status"]):
            return None
        if new:
            case["status"] = new
            case["phase"] = new
        if op == "note" and note:
            case["note"] = _clean(note, 800)
        case["updated"] = _now()
        case["event"] = op
        case["by"] = _clean(by, 60) or "The user"
        case["note"] = _clean(note, 800)
        case["ts"] = _now()
        if not isinstance(case.get("timeline"), list):
            case["timeline"] = []
        case["timeline"] = (case["timeline"] + [{"ts": case["ts"], "event": op, "by": case["by"],
                                                 "note": _clean(note, 400)}])[-80:]
        _append(case)
        return case


def _sla_state(case):
    """A one-word SLA state for the queue: P1/P2 overdue is the first thing an operator must see."""
    if case.get("status") in CLOSED_STATES:
        return "closed"
    due = _epoch(case.get("sla_due"))
    if due <= 0:
        return "no clock"
    left = int((due - time.time()) / 60)
    if left < 0:
        return f"OVERDUE {abs(left)}m"
    if left < 60:
        return f"{left}m left"
    return f"{left // 60}h left"


def render_list(cases=None):
    rows = [c for c in (cases if cases is not None else listing()) if isinstance(c, dict)]
    if not rows:
        return "TRIAGE QUEUE: no open incidents. (defend action=triage opens one only when the evidence is active.)"
    lines = [f"TRIAGE QUEUE  {time.strftime('%Y-%m-%d %H:%M:%S')}   open {len(rows)}",
             "  " + "-" * 125,
             f"  {'ID':<14} {'PRI':<4} {'STATUS':<14} {'CONF':<5} {'SLA':<14} {'UPDATED':<17} HOST / SIGNAL",
             "  " + "-" * 125]
    for c in rows:
        lines.append(f"  {_clean(c.get('id'), 14):<14} {_prio(c.get('priority')):<4} "
                     f"{_clean(c.get('status'), 14):<14} "
                     f"{(str(_int(c.get('confidence'), 0)) + '%'):<5} {_sla_state(c):<14} "
                     f"{_clean(c.get('updated'), 17):<17} {_clean(c.get('host'), 24)} / "
                     f"{_clean(c.get('title'), 70)}")
    lines.append("  use defend(action=triage, id=<ID>) for the playbook; op=contain|eradicate|recover|close advances it")
    return "\n".join(lines)


def render_case(case):
    if not case:
        return "no such incident"
    assets = _items(case.get("assets"), 30)
    lines = [f"{_clean(case.get('id'), 20)}  {_prio(case.get('priority'))}  "
             f"{_clean(case.get('status'), 20).upper()}  confidence {_int(case.get('confidence'), 0)}%",
             f"  {_clean(case.get('title'), 400)}",
             f"  host: {_clean(case.get('host'), 80)}   opened: {_clean(case.get('created'), 30)}   "
             f"response due: {_clean(case.get('sla_due'), 30)}  ({_sla_state(case)})",
             f"  kind: {_clean(case.get('kind'), 80)}   assets: {', '.join(assets) or '-'}",
             "  summary: " + (_clean(case.get("summary"), 1200) or "-")]
    evidence = _items(case.get("evidence"), 20)
    alert_ids = _items(case.get("alert_ids"), 20)
    containment = _items(case.get("containment"), 20)
    if evidence:
        lines.append("  evidence: " + ", ".join(evidence))
    if alert_ids:
        lines.append("  alerts:   " + ", ".join(alert_ids))
    if containment:
        lines.append("  containment (AWAITING YOUR YES): " + ", ".join(containment))
        lines.append("    run /defender enforce ... or defend(action=respond, apply=true, ids=[...])")
    lines.append("  playbook:")
    for s in case.get("playbook") or []:
        if not isinstance(s, dict):
            continue
        mark = {"done": "[x]", "doing": "[>]"}.get(s.get("status"), "[ ]")
        lines.append(f"    {mark} {_clean(s.get('step'), 10):<10} {_clean(s.get('title'), 200)}")
        lines.append(f"        {_clean(s.get('detail'), 600)}")
    if case.get("timeline"):
        lines.append("  timeline:")
        for t in (case.get("timeline") or [])[-10:]:
            if isinstance(t, dict):
                lines.append(f"    {_clean(t.get('ts'), 30)} {_clean(t.get('event'), 30)} "
                             f"{_clean(t.get('note'), 400)}".rstrip())
    lines.append("  advance with defend(action=triage, id=" + _clean(case.get("id"), 20) +
                 ", op=contain|close|note)")
    return "\n".join(lines)


def summary_line():
    rows = listing()
    if not rows:
        return "triage: none open"
    p1 = sum(1 for c in rows if c.get("priority") == "P1")
    overdue = sum(1 for c in rows if _sla_state(c).startswith("OVERDUE"))
    return f"triage: {len(rows)} open" + (f" ({p1} P1)" if p1 else "") + \
        (f", {overdue} OVERDUE" if overdue else "")
