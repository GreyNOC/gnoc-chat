#!/usr/bin/env python3
"""
bola_discriminant.py - the distinct-identity gate + paired cross-user read/write prober.

An IDOR/BOLA claim is real only when the CAPTURED bytes show both:
  1. the two sessions are genuinely DIFFERENT identities (else you "crossed" to yourself
     - a same-account false positive), and
  2. session A reads/writes an object whose owner-key belongs to B, not A.
This asserts (1) BEFORE attempting (2), so the same-account false positive cannot ship.
Pairs with lib_provision.provision_pair (mint A+B) and lib_auth (log them in).

  assert_distinct(id_a, id_b)     fail loud if A and B resolve to the same id / unresolved
  paired_read(sess_a, url_b)      A fetches B's object -> the read-IDOR capture
  paired_write(...)               A mutates B's object; capture B's OWN before/after view
  run(a, b, whoami, obj_b_url...) distinct-gate -> read -> (reversible) write -> revert

CLI: bola_discriminant.py selfcheck   (offline logic check on mock sessions)
"""
import json, sys


def assert_distinct(id_a, id_b):
    """Gate: a cross-user test requires two resolved, different identities."""
    if id_a is None or id_b is None:
        raise ValueError(f"identity unresolved (A={id_a!r} B={id_b!r}) - cannot prove BOLA")
    # a dict/object whoami would compare-distinct even for the SAME user (differing session
    # fields) and ship a same-account false positive - force a stable scalar owner-key.
    if not isinstance(id_a, (str, int)) or not isinstance(id_b, (str, int)):
        raise ValueError(f"whoami must return a SCALAR id (got {type(id_a).__name__}/{type(id_b).__name__}); "
                         f"pass a stable key like user['id'], not the whole object")
    if str(id_a) == str(id_b):
        raise ValueError(f"SAME IDENTITY {id_a!r} for both sessions - not a cross-user test")
    return True


def paired_read(sess_a, url_b, expect_field=None):
    """A reads B's object. A private body from B under A's session is the read receipt."""
    r = sess_a.get(url_b, timeout=20)
    body = r.text or ""
    return {"status": r.status_code, "len": len(body), "body": body[:1500],
            "has_field": (expect_field in body) if expect_field else None}


def paired_write(sess_a, url_b, body, sess_b=None, read_b_url=None, method="PATCH"):
    """A mutates B's object. If sess_b + read_b_url are given, capture B's OWN view
    before and after - the receipt that the write LANDED cross-user (not merely 200'd)."""
    before = sess_b.get(read_b_url, timeout=20).text[:800] if (sess_b and read_b_url) else None
    w = sess_a.request(method, url_b, json=body, timeout=20)
    after = sess_b.get(read_b_url, timeout=20).text[:800] if (sess_b and read_b_url) else None
    return {"write_status": w.status_code, "before": before, "after": after,
            "changed": (before != after) if before is not None else None}


def run(sess_a, sess_b, whoami, obj_b_url, write_body=None, read_b_url=None,
        expect_field=None, method="PATCH", revert_body=None):
    """Full BOLA discipline. whoami(session)->id is target-specific (an endpoint that
    returns the caller's own id). Returns the capture dict; raises on the distinct-gate."""
    id_a, id_b = whoami(sess_a), whoami(sess_b)
    assert_distinct(id_a, id_b)                       # gate FIRST, before any cross-read
    out = {"id_a": id_a, "id_b": id_b, "distinct": True}
    out["read"] = paired_read(sess_a, obj_b_url, expect_field)
    if write_body is not None:
        out["write"] = paired_write(sess_a, obj_b_url, write_body, sess_b, read_b_url, method)
        if revert_body is not None:                   # reversible-touch: flip back, keep the receipt
            paired_write(sess_a, obj_b_url, revert_body, method=method)
            out["reverted"] = True
    return out


class _MockResp:
    def __init__(self, status, text):
        self.status_code, self.text = status, text


class _MockSess:
    def __init__(self, ident, store):
        self.id, self.store = ident, store

    def get(self, url, **k):
        return _MockResp(200, self.store.get(url, ""))

    def request(self, m, url, json=None, **k):
        self.store[url] = str(json)
        return _MockResp(200, "ok")


def _selfcheck():
    # the gate rejects a same-identity pair
    try:
        assert_distinct("7", "7")
        raise SystemExit("gate FAILED to reject same identity")
    except ValueError:
        pass
    assert assert_distinct("7", "9")
    # a dict whoami (same user, different session fields) must be REJECTED, not passed
    try:
        assert_distinct({"user_id": 7, "session": "A"}, {"user_id": 7, "session": "B"})
        raise SystemExit("gate FAILED to reject non-scalar identity")
    except ValueError:
        pass
    # paired read/write/revert on mock sessions
    store = {"https://x/obj/B": "B-private-secret-value"}
    A, B = _MockSess("A", store), _MockSess("B", store)
    out = run(A, B, lambda s: s.id, "https://x/obj/B",
              write_body={"name": "pwned"}, read_b_url="https://x/obj/B",
              expect_field="secret", revert_body={"name": "orig"})
    assert out["distinct"] and out["read"]["has_field"] is True, "read receipt"
    assert out["write"]["changed"] is True and out.get("reverted"), "write+revert receipt"
    print("SELFCHECK OK  distinct-gate rejects self, paired read/write/revert pass")


def main(argv):
    if argv and argv[0] == "selfcheck":
        return _selfcheck()
    print(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
