"""mitmdump addon for the droid workbench: one JSON line per completed flow.

Env (set by droid.py when it starts mitmdump):
  WB_JSONL   output path for the per-flow summary lines
  WB_SCOPE   targets/<program>/SCOPE.txt used to mark in_scope true/false (empty = all false)

The full flows go to the -w file mitmdump writes itself. This addon never replays, modifies or
blocks anything: hosts the app contacts on its own are recorded as passive observations only.
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bbtools"))
try:
    from lib_scope import in_scope as _in_scope
except Exception:  # scope lib missing: fail closed (everything out of scope)
    _in_scope = None

JSONL = os.environ.get("WB_JSONL", "")
SCOPE = os.environ.get("WB_SCOPE", "")
_cache = {}


def _scoped(host):
    if not SCOPE or _in_scope is None or not host:
        return False
    if host not in _cache:
        try:
            _cache[host] = bool(_in_scope(host, SCOPE))
        except Exception:
            _cache[host] = False
    return _cache[host]


def _write(rec):
    if not JSONL:
        return
    with open(JSONL, "a") as f:
        f.write(json.dumps(rec, separators=(",", ":")) + "\n")


def response(flow):
    req, resp = flow.request, flow.response
    host = req.pretty_host
    _write({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "method": req.method, "scheme": req.scheme, "host": host, "port": req.port,
        "path": req.path.split("?", 1)[0], "has_query": "?" in req.path,
        "status": resp.status_code if resp else None,
        "length": len(resp.raw_content or b"") if resp else 0,
        "ctype": (resp.headers.get("content-type", "") if resp else "")[:80],
        "in_scope": _scoped(host),
    })


def error(flow):
    req = flow.request
    _write({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "method": req.method, "scheme": req.scheme, "host": req.pretty_host, "port": req.port,
        "path": req.path.split("?", 1)[0], "status": None, "length": 0,
        "error": str(flow.error)[:200], "in_scope": _scoped(req.pretty_host),
    })


def tls_failed_client(data):
    # The app refused our CA (pinning not bypassed, or the CA is not trusted): worth a line, it is the
    # single most common reason a run captures nothing.
    try:
        sni = data.context.client.sni or ""
    except Exception:
        sni = ""
    _write({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": "client-tls-failed",
            "host": sni, "error": str(getattr(data.conn, "error", ""))[:200], "in_scope": _scoped(sni)})
