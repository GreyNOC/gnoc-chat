"""Per-turn request receipts, written by the harness, not by the model.

Why (program-19 hunt, 2026-11-25): the lead's final answer said "Probe count: 12 (6 GET + 6 OPTIONS/POST)"
when the six OPTIONS/POST sat only under "Next Probe" and were never sent (t8), and it cited a bot's capture of
app.example.com as a app.example.com result (t9). A count or a host the model writes is a claim. Every gated
request already lands in one place (gnoc_tools.net._capture); this module keeps an in-process ledger of those
captures so the end of a turn can print what was REALLY sent, by whom, and where its bytes are.

Stdlib only; gnoc_core never imports gnoc_agent.
"""
import collections
import contextvars
import os
import re
import threading
from urllib.parse import urlsplit

# Who is sending: None = the lead. run_worker sets it to the bot's tag ("bot 3", "builder") for the bot's whole
# run; contextvars ride into the tool threads gnoc_agent._parallel starts (it copies the caller's context).
ACTOR = contextvars.ContextVar("gnoc_receipt_actor", default=None)

# The tools whose turn gets a receipt block even when nothing was captured (browser / js_mine fetch outside the
# capture path; the block then says so instead of staying silent).
RECEIPT_TOOLS = frozenset({"http_request", "graphql", "probe_matrix", "race", "sweep", "host_sweep", "touch", "fingerprint",
                           "browser", "js_mine"})

TAG = "[RECEIPTS (harness)"   # a saved non-model note starts with this (session.INJECTED knows it)
MAX_LINES = 25

_LOCK = threading.Lock()
_SEQ = [0]
_LOG = collections.deque(maxlen=5000)


def body_error(body):
    """The first error message a JSON body carries ({"errors":[{"message":...}]} or {"error":...}), or ''.
    The initech replay 2026-11-25: the lead read a GraphQL 200 as "auth bypassed" when its body said "Workspace
    access denied. ReasonHint: Forbidden" - a 200 is not a pass (T-36), so the receipt shows the error inline."""
    try:
        d = body if isinstance(body, (dict, list)) else __import__("json").loads(str(body or ""))
    except Exception:  # noqa: BLE001 - not JSON: nothing to say
        return ""
    if isinstance(d, dict):
        errs = d.get("errors")
        if isinstance(errs, list) and errs and isinstance(errs[0], dict):
            return str(errs[0].get("message") or "error")
        if isinstance(d.get("error"), (str, dict)):
            e = d["error"]
            return str(e.get("message") if isinstance(e, dict) else e)
    return ""


def record(method, url, status, length, raw, actor=None, error=""):
    """One request that went on the wire and was captured. Never raises."""
    try:
        who = actor if actor is not None else ACTOR.get()
        with _LOCK:
            _SEQ[0] += 1
            _LOG.append({"seq": _SEQ[0], "method": str(method or "GET").upper(), "url": str(url or ""),
                         "status": status, "len": length, "raw": str(raw or ""), "actor": who,
                         "error": str(error or "")})
    except Exception:  # noqa: BLE001 - the ledger must never fail a probe that already happened
        pass


def mark():
    """The position a turn starts counting from."""
    with _LOCK:
        return _SEQ[0]


def since(start):
    with _LOCK:
        return [dict(e) for e in _LOG if e["seq"] > int(start or 0)]


# "PROBE COUNT: 8", "Probe count: 12 (6 GET ...)", "PROBES: 4", "probes fired: 3" - an explicit statement wins.
_EXPLICIT = re.compile(r"(?i)\b(?:probe\s*count|probes(?:\s+(?:fired|sent))?|requests?\s+(?:fired|sent))"
                       r"\W{0,4}\s*[:=]\W{0,4}\s*(\d{1,5})\b")
# "8 probes fired", "I fired 8 probes", "sent 6 requests". A bare "248 probes" is NOT taken: the t9 answer quoted
# "DEAD with 248 probes" from an older verdict, which is history, not a claim about this turn.
_VERBED = re.compile(r"(?i)\b(\d{1,5})\s+(?:new\s+|crafted\s+|live\s+|real\s+)?(?:probes?|requests?)\s+"
                     r"(?:were\s+)?(?:fired|sent)\b"
                     r"|\b(?:fired|sent)\s+(\d{1,5})\s+(?:new\s+|crafted\s+|live\s+|real\s+)?(?:probes?|requests?)\b")


def claimed_count(text):
    """The probe count the answer states for itself, or None. The LAST explicit statement wins (the summary line
    closes the answer); a verbed count ("8 probes fired") is the fallback."""
    t = str(text or "")
    hits = _EXPLICIT.findall(t)
    if hits:
        return int(hits[-1])
    hits = [a or b for a, b in _VERBED.findall(t)]
    return int(hits[-1]) if hits else None


# a raw capture the answer cites: "raw/202111980219", "raw/202111980219-post.json" or the bare basename
_RAWREF = re.compile(r"(?:\braw/|(?<![\w/.-]))(\d{12}(?:-[a-z0-9_]+)?)(?:\.json)?\b", re.I)
_HOSTREF = re.compile(r"\b((?:[a-z0-9-]+\.)+(?:com|net|org|io|co|ai|app|dev|cloud|gov|us|uk|de))\b", re.I)
_STATUS = re.compile(r"(?<![\w.=/-])([1-5]\d\d)(?![\w.%/-])")


def claim_mismatches(entries, answer):
    """Answer lines that cite ONE raw capture of this turn and state a status or host the capture does not carry.
    Why (initech replay 2026-11-25): the lead's table labelled raw/202111980219 "Nonsense sourceId -> 403" while
    that file was the bot's hotel request to www.initech.com. The receipt block listed the truth, the answer still
    asserted the wrong thing, and nothing compared the two. Returns [(ref, said, truth)]."""
    by = {}
    for e in entries:
        b = os.path.basename(e.get("raw") or "")
        if b:
            by[b[:-5] if b.endswith(".json") else b] = e
    out = []
    for line in str(answer or "").splitlines():
        refs = list(dict.fromkeys(m.group(1).lower() for m in _RAWREF.finditer(line)))
        if len(refs) != 1:
            continue          # none, or several captures on one line: the line cannot be tied to one byte
        ref = refs[0]
        e = by.get(ref) or next((v for k, v in by.items() if k.lower().startswith(ref)), None)
        if not e:
            continue
        rest = " ".join(w for w in _RAWREF.sub(" ", line).split() if "/" not in w and "len=" not in w.lower())
        said_st = set(_STATUS.findall(rest))
        said_host = {h.lower() for h in _HOSTREF.findall(line)}
        host = (urlsplit(e["url"]).hostname or "").lower()
        bad = []
        if said_st and str(e.get("status")) not in said_st:
            bad.append("/".join(sorted(said_st)))
        if said_host and host and host not in said_host:
            bad.append(", ".join(sorted(said_host)))
        if bad:
            path = urlsplit(e["url"]).path or "/"
            out.append((ref, " ".join(bad), f"{e['method']} {host} {_short(path, 50)} -> {e.get('status')}"))
    return out


def _short(s, n):
    s = str(s or "")
    return s if len(s) <= n else s[:n - 3] + "..."


def lines(entries, answer="", probe_tools_ran=False):
    """The receipt block as plain lines (no colour), or [] when this turn had nothing to show."""
    if not entries and not probe_tools_ran:
        return []
    n = len(entries)
    bots = collections.Counter(e["actor"] for e in entries if e.get("actor"))
    lead = n - sum(bots.values())
    who = f"lead {lead}" + (f", bots {sum(bots.values())}" if bots else "")
    out = [f"receipts (harness): {n} request{'s' if n != 1 else ''} this turn - {who}"]
    if not entries:
        out[0] = ("receipts (harness): 0 captured requests this turn (a browser or js_mine fetch is not a "
                  "captured request)")
    for e in entries[:MAX_LINES]:
        u = urlsplit(e["url"])
        path = (u.path or "/") + (("?" + u.query) if u.query else "")
        ln = e.get("len")
        raw = e.get("raw") or ""
        raw = ("raw/" + os.path.basename(raw)) if raw else "-"
        tail = f"  [{e['actor']}]" if e.get("actor") else ""
        err = f"  error: {_short(e['error'], 50)}" if e.get("error") else ""
        out.append(f"  {e['method']} {u.hostname or '?'} {_short(path, 60)} -> {e.get('status')} "
                   f"len={ln if ln is not None else '?'}{err}  raw={raw}{tail}")
    dirs = sorted({os.path.dirname(e["raw"]) for e in entries if e.get("raw")})
    if n > MAX_LINES:
        out.append(f"  +{n - MAX_LINES} more" + (f", all in {', '.join(dirs[:2])}" if dirs else ""))
    elif dirs:
        out.append(f"  raw dir: {', '.join(dirs[:2])}")
    said = claimed_count(answer)
    if said is not None and said != n:
        out.append(f"the answer says {said}; the harness counted {n}")
    for ref, said_x, truth in claim_mismatches(entries, answer)[:6]:
        out.append(f"claim check: the answer ties raw/{ref} to {said_x}; that capture is {truth}")
    return out


def note(block):
    """The block as a saved non-model note: the next turn's model sees the true count, and it is never taken for
    the user's words or the model's."""
    return TAG + " - written by gnoc from the capture ledger, not by the model]\n" + "\n".join(block)
