#!/usr/bin/env python3
"""
race_burst.py - concurrent burst + serial-replay control for the SIG-1 seam-race class
(the #1 paid signature) and the floor-gate requirement that any single-use / check-then-act
path gets a CONCURRENT burst before a DEAD verdict.

A race finding SHIPS only with BOTH legs captured:
  - concurrent: the burst lets K>1 through a one-shot gate (the bug), and
  - serial control: the same N calls fired sequentially let exactly 1 through (the proof
    it was atomicity, not a weak limit).

  burst(fn, n=30, warmup=None)        fire fn(i) on n threads released together by a Barrier
  burst_http(req, n=30)               n concurrent identical HTTP requests (curl_cffi)
  serial_control(fn, n=30)            the same N calls SEQUENTIALLY - the discriminant
  count_ok(results, ok)               count results satisfying ok(val)

ponytail: threading.Barrier alignment, not raw single-packet last-byte sync. Good for most
seam races (coupon/wallet/OTP/quota); for a sub-millisecond H2 single-packet window use Burp
Turbo Intruder. The concurrent-vs-serial discriminant is the load-bearing part and it is here.

CLI: race_burst.py selfcheck   (offline: proves the burst creates a real overdraft race)
"""
import sys, threading, time


def burst(fn, n=30, warmup=None):
    """Fire fn(i) on n threads released simultaneously by a Barrier. Returns [(i, val_or_exc)].
    warmup(): optional per-thread pre-barrier work (open the connection so only the final
    request byte is in flight at release)."""
    barrier = threading.Barrier(n)
    out = [None] * n

    def worker(i):
        if warmup:
            try:
                warmup()
            except Exception:
                pass
        try:
            barrier.wait()
        except threading.BrokenBarrierError:
            pass
        try:
            out[i] = (i, fn(i))
        except Exception as e:
            out[i] = (i, e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return out


def burst_http(req, n=30, session_factory=None):
    """n concurrent identical requests. req = {method,url,json?,data?,headers?}. Fresh
    curl_cffi chrome124 session per thread. Returns [(i, status, len, body[:200])]."""
    from curl_cffi import requests as creq

    def one(i):
        s = session_factory() if session_factory else creq.Session(impersonate="chrome124")
        r = s.request(req["method"], req["url"], json=req.get("json"),
                      data=req.get("data"), headers=req.get("headers"), timeout=20)
        b = r.text or ""
        return (r.status_code, len(b), b[:200])

    rows = []
    for i, v in burst(one, n):
        rows.append((i,) + (v if not isinstance(v, Exception) else (0, 0, str(v)[:200])))
    return rows


def serial_control(fn, n=30):
    """The same N calls SEQUENTIALLY - proves atomicity was broken (concurrent lets K>1
    through, serial lets exactly 1)."""
    out = []
    for i in range(n):
        try:
            out.append((i, fn(i)))
        except Exception as e:
            out.append((i, e))
    return out


def count_ok(results, ok):
    """Count rows whose value satisfies ok(). Works for BOTH burst()/serial_control() rows
    (i, val) and burst_http() rows (i, status, len, body) - ok() receives element [1] (the val,
    or the status). Exceptions never count."""
    c = 0
    for row in results:
        v = row[1] if isinstance(row, (list, tuple)) and len(row) >= 2 else row
        try:
            if not isinstance(v, Exception) and ok(v):
                c += 1
        except Exception:
            pass
    return c


def _selfcheck():
    # simulate a single-use coupon: bal=1, each call spends if bal>0, with a check->act window
    state = {"bal": 1}

    def spend(i):
        if state["bal"] > 0:            # CHECK
            time.sleep(0.01)            # the TOCTOU window
            state["bal"] -= 1           # ACT (no lock)
            return "spent"
        return "denied"

    concurrent_spent = count_ok(burst(spend, 25), lambda v: v == "spent")
    state["bal"] = 1                    # reset for the serial control
    serial_spent = count_ok(serial_control(spend, 25), lambda v: v == "spent")
    assert serial_spent == 1, f"serial control should allow exactly 1, got {serial_spent}"
    assert concurrent_spent >= 2, f"burst did not create a race (concurrent spent={concurrent_spent})"
    # count_ok must also consume burst_http-shaped 4-tuples (i, status, len, body)
    assert count_ok([(0, 200, 10, "x"), (1, 403, 5, "y"), (2, 200, 9, "z")], lambda st: st == 200) == 2
    print(f"SELFCHECK OK  burst races: concurrent overspent={concurrent_spent} vs serial={serial_spent}")


def main(argv):
    if argv and argv[0] == "selfcheck":
        return _selfcheck()
    print(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
