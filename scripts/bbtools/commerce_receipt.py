#!/usr/bin/env python3
"""
commerce_receipt.py - before/after money-state receipt harness for commerce findings.

WHY: every commerce finding (price-tamper, coupon-race, wallet-overdraft, idempotency-replay)
requires a captured before-state, the attack call, and a captured after-state that shows the
delta. Without this triple every submission is mechanism-without-capability (28 of 39 negatives
killed there). This harness pins the discipline as code so it cannot be skipped.

FUNCTIONS

  snapshot(session, read_url, fields=None)
      Read the current money state. Returns a dict of all JSON keys (or only `fields` if given).
      Stores the raw response bytes so the reviewer can byte-verify the receipt.

  prove(session, read_url, action_fn, fields=None, expect=None)
      Captures before-state, runs action_fn(session), captures after-state, computes per-field
      deltas, sets confirmed=True only when at least one field changed (mirrors
      bola_discriminant's changed=before!=after discipline). Emits a copy-paste capture.log
      block to stdout. Returns {before, after, delta, receipt_bytes, confirmed, log_block}.
      expect: "decrease" | "increase" | "change" (optional; gates confirmed further).

  idem_replay(session, req, key, n=3, mutate=None)
      Idempotency-key replay: fire `req` n times with the SAME idempotency key, then once more
      with the same key but a mutated body (if mutate given). Returns a list of row dicts
      {attempt, status, body_excerpt, delta} scored against prove(). The finding is confirmed
      when attempt 2+ returns success status AND the server-side settled state changed more
      than once (wallet/quota drained N times instead of 1).

SECURITY: scope-gated. snapshot() and prove() refuse an off-scope read_url when scope_file
is passed to the module-level set_scope() or directly as a kwarg.

CLI:
  commerce_receipt.py selfcheck     run offline assertion suite (no network)
"""
import json
import sys
import os
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from lib_scope import in_scope, extract_host  # noqa: E402


# ---------------------------------------------------------------------------
# Module-level scope file (set once; callers can also pass per-call)
# ---------------------------------------------------------------------------

_MODULE_SCOPE_FILE: "str | None" = None


def set_scope(scope_file: str) -> None:
    """Set a default SCOPE.txt for all subsequent calls (avoids per-call arg)."""
    global _MODULE_SCOPE_FILE
    _MODULE_SCOPE_FILE = scope_file


def _check_scope(url: str, scope_file: "str | None") -> None:
    sf = scope_file or _MODULE_SCOPE_FILE
    if sf is None:
        return
    if not in_scope(url, sf):
        raise ValueError(f"OUT_OF_SCOPE {extract_host(url)} (scope_file={sf})")


# ---------------------------------------------------------------------------
# 1. snapshot
# ---------------------------------------------------------------------------

def snapshot(session, read_url: str, fields: "list | None" = None,
             scope_file: "str | None" = None) -> dict:
    """Read the current money/account state at read_url.

    Parameters
    ----------
    session     curl_cffi (or requests-like) authed session.
    read_url    The GET endpoint that returns the account/wallet/order state as JSON.
    fields      If given, return only these top-level JSON keys. If None, return all keys.
    scope_file  Override module-level scope file. Raises ValueError if URL is out of scope.

    Returns
    -------
    {
      "status":    int HTTP status,
      "fields":    dict of key->value (subset if fields given),
      "raw_bytes": bytes of the full response body,
      "ts":        unix timestamp float,
    }
    Raises ValueError on scope violation. Does NOT raise on non-200 (caller decides).
    """
    _check_scope(read_url, scope_file)
    r = session.get(read_url, timeout=20)
    raw = getattr(r, "content", None) or (r.text.encode() if hasattr(r, "text") else b"")
    ts = time.time()
    try:
        body = json.loads(raw)
    except Exception:
        body = {}
    if isinstance(body, dict):
        if fields:
            state = {k: body.get(k) for k in fields}
        else:
            state = dict(body)
    else:
        state = {"_raw": body}
    return {"status": r.status_code, "fields": state, "raw_bytes": raw, "ts": ts}


# ---------------------------------------------------------------------------
# 2. prove
# ---------------------------------------------------------------------------

def prove(session, read_url: str, action_fn, fields: "list | None" = None,
          expect: "str | None" = None, scope_file: "str | None" = None) -> dict:
    """Capture before-state, run the attack, capture after-state, prove a delta.

    Parameters
    ----------
    session     Authed session.
    read_url    URL returning JSON account/wallet state (GET).
    action_fn   Callable(session) -> response. The attack/confirm call.
    fields      Which JSON keys to track. None = all keys present in before-state.
    expect      Optional directional gate: "decrease" | "increase" | "change".
                "decrease": at least one numeric field went down -> confirmed.
                "increase": at least one numeric field went up -> confirmed.
                "change":   at least one field value differs -> confirmed (default).
    scope_file  Scope file override.

    Returns
    -------
    {
      "before":        snapshot dict (before the action),
      "after":         snapshot dict (after the action),
      "action_status": HTTP status of the action call,
      "action_bytes":  bytes of the action response (the attack receipt),
      "delta":         dict key -> (before_val, after_val) for every key that changed,
      "receipt_bytes": bytes of the after-state GET (the settling read),
      "confirmed":     bool - True when the actual byte-delta passes the expect gate,
      "log_block":     str - copy-paste capture.log section ready for a report,
    }
    """
    _check_scope(read_url, scope_file)

    # Step 1: before-state
    before = snapshot(session, read_url, fields=fields, scope_file=scope_file)
    _fields = fields or list(before["fields"].keys())

    # Step 2: action
    action_r = action_fn(session)
    action_raw = getattr(action_r, "content", None) or (
        action_r.text.encode() if hasattr(action_r, "text") else b""
    )
    action_status = getattr(action_r, "status_code", 0)

    # Step 3: after-state
    after = snapshot(session, read_url, fields=_fields, scope_file=scope_file)

    # Step 4: delta
    delta = {}
    for k in _fields:
        bv = before["fields"].get(k)
        av = after["fields"].get(k)
        if bv != av:
            delta[k] = (bv, av)

    # Step 5: confirm
    confirmed = _evaluate_expect(delta, before["fields"], after["fields"], expect)

    # Step 6: log block
    log_block = _build_log_block(before, after, delta, action_status,
                                 action_raw, after["raw_bytes"], confirmed)

    print(log_block)

    return {
        "before": before,
        "after": after,
        "action_status": action_status,
        "action_bytes": action_raw,
        "delta": delta,
        "receipt_bytes": after["raw_bytes"],
        "confirmed": confirmed,
        "log_block": log_block,
    }


def _evaluate_expect(delta: dict, before_fields: dict, after_fields: dict,
                     expect: "str | None") -> bool:
    """Return True when the delta satisfies the expect gate."""
    if not delta:
        return False
    mode = (expect or "change").lower()
    if mode == "change":
        return bool(delta)
    if mode == "decrease":
        for k, (bv, av) in delta.items():
            try:
                if float(av) < float(bv):
                    return True
            except (TypeError, ValueError):
                pass
        return False
    if mode == "increase":
        for k, (bv, av) in delta.items():
            try:
                if float(av) > float(bv):
                    return True
            except (TypeError, ValueError):
                pass
        return False
    return bool(delta)


def _build_log_block(before: dict, after: dict, delta: dict,
                     action_status: int, action_bytes: bytes,
                     receipt_bytes: bytes, confirmed: bool) -> str:
    sep = "=" * 60
    lines = [
        sep,
        "# COMMERCE RECEIPT - capture.log",
        sep,
        "",
        "## BEFORE-STATE",
        f"  ts:     {before['ts']:.3f}",
        f"  status: {before['status']}",
        "  fields:",
    ]
    for k, v in before["fields"].items():
        lines.append(f"    {k}: {v!r}")

    lines += [
        "",
        "## ATTACK REQUEST",
        f"  action_status: {action_status}",
        f"  action_body:   {action_bytes[:400].decode('utf-8', errors='replace')!r}",
        "",
        "## AFTER-STATE",
        f"  ts:     {after['ts']:.3f}",
        f"  status: {after['status']}",
        "  fields:",
    ]
    for k, v in after["fields"].items():
        lines.append(f"    {k}: {v!r}")

    lines += [
        "",
        "## DELTA",
    ]
    if delta:
        for k, (bv, av) in delta.items():
            lines.append(f"    {k}: {bv!r} -> {av!r}")
    else:
        lines.append("    (no change detected)")

    lines += [
        "",
        f"## CONFIRMED: {confirmed}",
        "",
        "## SETTLING READ (raw bytes, first 400B)",
        f"  {receipt_bytes[:400].decode('utf-8', errors='replace')!r}",
        sep,
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 3. idem_replay
# ---------------------------------------------------------------------------

def idem_replay(session, req: dict, key: str, n: int = 3,
                mutate: "dict | None" = None,
                read_url: "str | None" = None,
                fields: "list | None" = None,
                scope_file: "str | None" = None) -> list:
    """Idempotency-key replay: fire req n times with the same key, then once mutated.

    Parameters
    ----------
    session     Authed session.
    req         {method, url, json?, data?, headers?} - the payment/transfer request.
    key         Idempotency key value to pin (same key for all N replays).
    n           Number of identical replays (default 3). Expect: only first effect persists.
    mutate      If given, a dict merged into req["json"] for the (n+1)th call (same key,
                different body - tests key->resource binding). If the server returns success
                AND the resource changes, the key is not body-bound (the bug).
    read_url    If given, snapshot the settled state after each attempt for delta scoring.
    fields      Which state fields to track (passed to snapshot).
    scope_file  Scope file override.

    Returns
    -------
    List of row dicts, one per attempt:
    {
      "attempt":      int (1-indexed),
      "key":          str,
      "mutated":      bool (True for the mutate call),
      "status":       int HTTP status,
      "body_excerpt": str first 300 chars of response,
      "state_after":  snapshot dict or None,
      "delta":        dict of changed fields vs attempt-1 state, or None,
    }
    A confirmed idempotency bug: attempt 2+ returns success status AND state_after differs
    from attempt 1 state_after (the server executed the action twice instead of caching).
    """
    if read_url:
        _check_scope(read_url, scope_file)
    _check_scope(req.get("url", ""), scope_file)

    results = []
    prev_state = None

    for i in range(1, n + 1):
        body = dict(req.get("json") or {})
        headers = dict(req.get("headers") or {})
        headers["Idempotency-Key"] = key

        r = session.request(
            req.get("method", "POST"),
            req["url"],
            json=body if body else None,
            data=req.get("data"),
            headers=headers,
            timeout=20,
        )
        raw = getattr(r, "content", None) or (r.text.encode() if hasattr(r, "text") else b"")
        excerpt = raw[:300].decode("utf-8", errors="replace")

        state = None
        delta = None
        if read_url:
            state = snapshot(session, read_url, fields=fields, scope_file=scope_file)
            if prev_state is not None:
                delta = {
                    k: (prev_state["fields"].get(k), state["fields"].get(k))
                    for k in (fields or list(state["fields"].keys()))
                    if prev_state["fields"].get(k) != state["fields"].get(k)
                }
            prev_state = state

        results.append({
            "attempt": i,
            "key": key,
            "mutated": False,
            "status": r.status_code,
            "body_excerpt": excerpt,
            "state_after": state,
            "delta": delta,
        })

    # Mutated replay (same key, different body)
    if mutate is not None:
        body2 = dict(req.get("json") or {})
        body2.update(mutate)
        headers2 = dict(req.get("headers") or {})
        headers2["Idempotency-Key"] = key

        r2 = session.request(
            req.get("method", "POST"),
            req["url"],
            json=body2,
            headers=headers2,
            timeout=20,
        )
        raw2 = getattr(r2, "content", None) or (r2.text.encode() if hasattr(r2, "text") else b"")
        state2 = None
        delta2 = None
        if read_url:
            state2 = snapshot(session, read_url, fields=fields, scope_file=scope_file)
            if prev_state is not None:
                delta2 = {
                    k: (prev_state["fields"].get(k), state2["fields"].get(k))
                    for k in (fields or list(state2["fields"].keys()))
                    if prev_state["fields"].get(k) != state2["fields"].get(k)
                }

        results.append({
            "attempt": n + 1,
            "key": key,
            "mutated": True,
            "status": r2.status_code,
            "body_excerpt": raw2[:300].decode("utf-8", errors="replace"),
            "state_after": state2,
            "delta": delta2,
        })

    return results


# ---------------------------------------------------------------------------
# SELFCHECK
# ---------------------------------------------------------------------------

class _Resp:
    def __init__(self, status: int, body: str):
        self.status_code = status
        self.content = body.encode()
        self.text = body


class _MockSess:
    """Mock session: stores a mutable state dict, returns it on GET; records POSTs."""
    def __init__(self, state: dict):
        self._state = dict(state)
        self.posts: list = []

    def get(self, url, **k):
        return _Resp(200, json.dumps(self._state))

    def post(self, url, **k):
        self.posts.append((url, k))
        return _Resp(200, '{"ok": true}')

    def request(self, method, url, **k):
        if method.upper() == "GET":
            return self.get(url, **k)
        return self.post(url, **k)


def _selfcheck():
    import tempfile

    # ------------------------------------------------------------------
    # 1. snapshot basic
    # ------------------------------------------------------------------
    s = _MockSess({"balance": 100, "credits": 5})
    snap = snapshot(s, "https://shop.example.com/account")
    assert snap["status"] == 200
    assert snap["fields"]["balance"] == 100
    assert snap["fields"]["credits"] == 5
    assert isinstance(snap["raw_bytes"], bytes)

    # ------------------------------------------------------------------
    # 2. snapshot with field filter
    # ------------------------------------------------------------------
    snap2 = snapshot(s, "https://shop.example.com/account", fields=["balance"])
    assert "balance" in snap2["fields"]
    assert "credits" not in snap2["fields"]

    # ------------------------------------------------------------------
    # 3. scope-gate refuses off-scope URL
    # ------------------------------------------------------------------
    sf = tempfile.NamedTemporaryFile(delete=False, suffix=".txt").name
    with open(sf, "w") as fh:
        fh.write("shop.example.com\n")
    try:
        snapshot(s, "https://evil.org/account", scope_file=sf)
        raise SystemExit("scope gate FAILED to block off-scope URL")
    except ValueError as e:
        assert "OUT_OF_SCOPE" in str(e), str(e)
    finally:
        os.unlink(sf)

    # ------------------------------------------------------------------
    # 4. prove detects a real delta (balance decreases)
    # ------------------------------------------------------------------
    sf2 = tempfile.NamedTemporaryFile(delete=False, suffix=".txt").name
    with open(sf2, "w") as fh:
        fh.write("shop.example.com\n")
    try:
        class _DecSess:
            """Session whose state decreases on POST."""
            def __init__(self):
                self._bal = 100

            def get(self, url, **k):
                return _Resp(200, json.dumps({"balance": self._bal}))

            def post(self, url, **k):
                self._bal -= 10
                return _Resp(200, '{"charged": 10}')

            def request(self, method, url, **k):
                return self.get(url) if method.upper() == "GET" else self.post(url)

        ds = _DecSess()
        result = prove(
            ds,
            "https://shop.example.com/account",
            lambda sess: sess.post("https://shop.example.com/charge"),
            fields=["balance"],
            expect="decrease",
            scope_file=sf2,
        )
        assert result["confirmed"] is True, f"expected confirmed=True, got {result}"
        assert "balance" in result["delta"], f"expected balance in delta, got {result['delta']}"
        bv, av = result["delta"]["balance"]
        assert av < bv, f"expected balance to decrease, got {bv} -> {av}"
        assert len(result["log_block"]) > 100
        assert "CONFIRMED: True" in result["log_block"]
    finally:
        os.unlink(sf2)

    # ------------------------------------------------------------------
    # 5. prove returns confirmed=False when no delta
    # ------------------------------------------------------------------
    sf3 = tempfile.NamedTemporaryFile(delete=False, suffix=".txt").name
    with open(sf3, "w") as fh:
        fh.write("shop.example.com\n")
    try:
        class _NoChangeSess:
            def get(self, url, **k):
                return _Resp(200, '{"balance": 50}')

            def post(self, url, **k):
                return _Resp(400, '{"error": "declined"}')

            def request(self, method, url, **k):
                return self.get(url) if method.upper() == "GET" else self.post(url)

        nc = _NoChangeSess()
        r2 = prove(
            nc,
            "https://shop.example.com/account",
            lambda sess: sess.post("https://shop.example.com/charge"),
            scope_file=sf3,
        )
        assert r2["confirmed"] is False, f"expected confirmed=False, got {r2['confirmed']}"
        assert r2["delta"] == {}, f"expected empty delta, got {r2['delta']}"
    finally:
        os.unlink(sf3)

    # ------------------------------------------------------------------
    # 6. idem_replay: replays same key, detects repeat effect
    # ------------------------------------------------------------------
    sf4 = tempfile.NamedTemporaryFile(delete=False, suffix=".txt").name
    with open(sf4, "w") as fh:
        fh.write("pay.example.com\n")
    try:
        class _IdemSess:
            """Bad server: applies every request regardless of idempotency key."""
            def __init__(self):
                self._bal = 100

            def get(self, url, **k):
                return _Resp(200, json.dumps({"balance": self._bal}))

            def request(self, method, url, json=None, **k):
                if method.upper() == "GET":
                    return self.get(url)
                self._bal -= 10
                return _Resp(200, '{"ok": true}')

        is_ = _IdemSess()
        rows = idem_replay(
            is_,
            {"method": "POST", "url": "https://pay.example.com/charge",
             "json": {"amount": 10}},
            key="idem-test-key-001",
            n=3,
            read_url="https://pay.example.com/account",
            fields=["balance"],
            scope_file=sf4,
        )
        assert len(rows) == 3, f"expected 3 rows, got {len(rows)}"
        # delta on row 2 and 3 should show balance dropped again (bad idempotency)
        assert rows[1]["delta"] is not None and rows[1]["delta"] != {}, \
            f"expected delta on attempt 2, got {rows[1]['delta']}"
    finally:
        os.unlink(sf4)

    # ------------------------------------------------------------------
    # 7. idem_replay with mutate call
    # ------------------------------------------------------------------
    sf5 = tempfile.NamedTemporaryFile(delete=False, suffix=".txt").name
    with open(sf5, "w") as fh:
        fh.write("pay.example.com\n")
    try:
        class _MutateSess:
            def __init__(self):
                self._bal = 200
                self.calls: list = []

            def get(self, url, **k):
                return _Resp(200, json.dumps({"balance": self._bal}))

            def request(self, method, url, json=None, **k):
                if method.upper() == "GET":
                    return self.get(url)
                self.calls.append(json)
                return _Resp(200, '{"ok": true}')

        ms = _MutateSess()
        rows2 = idem_replay(
            ms,
            {"method": "POST", "url": "https://pay.example.com/charge",
             "json": {"amount": 10}},
            key="idem-mutate-key",
            n=2,
            mutate={"amount": 99},
            scope_file=sf5,
        )
        assert len(rows2) == 3, f"expected 3 rows (2 replays + 1 mutate), got {len(rows2)}"
        assert rows2[2]["mutated"] is True
        # verify the mutated body was sent
        assert ms.calls[-1]["amount"] == 99, f"mutate body not sent: {ms.calls}"
    finally:
        os.unlink(sf5)

    print("SELFCHECK OK  snapshot/prove delta-detection, scope-gate, idem_replay confirmed")


def main(argv):
    if argv and argv[0] == "selfcheck":
        return _selfcheck()
    print(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
