#!/usr/bin/env python3
"""live-lane.py - the ONE way a hand-written live probe leaves the box.

Every live lane used to re-implement its own scope check (some did not), its own rate, its own
capture and its own idea of the programme's identification header. This runner makes the live
contract structural instead of remembered. A request is refused BEFORE the wire unless ALL of:

  scope    lib_scope.program_allows(url, program): SCOPE.txt + NOSCOPE.txt, no internal IPs,
           no third-party hosts, no bare-TLD rows. Same parser as the hook and the scope proxy.
  policy   lib_policy.policy(program) says network_ok (no AI-agent ban; a scanner ban only
           constrains the tool, which this runner already is not).
  stop     .claude/state/hunt-loop/STOP does not exist (the user's kill switch), and the economy
           PAUSE does not exist.
  session  gnoc_session says a live `gnoc chat` is open, or GNOC_HUNT_NO_SESSION=1 was set by a
           human for one deliberate run (the refusal names the variable).
  cap      the lane's ledger has fewer than --cap fired requests (default 25).
  rate     1 / lib_policy rps, tracked per program on disk so two shells cannot double the rate.

A fired request is captured raw (request + response headers + body) under
targets/<program>/hunts/<tag>/raw/ and sealed with gnoc_oracle; one line per request lands in
raw/../ledger.jsonl and commands.txt. Redirects are NOT followed (lib_egress 2026-11-04): a 30x is
returned as the answer, because following it is how an in-scope host walks a probe out of scope.

    live-lane.py <program> <tag> METHOD URL [--body FILE] [--header K:V ...] [--identity state.json]
                                      [--cap N] [--dry-run] [--timeout S]
    live-lane.py --selfcheck          offline: proves the refusals without any network

Exit 0 = fired (or a dry-run plan), 2 = refused, 1 = the request itself failed.
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
WS = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "bbtools"))

from bbtools import lib_policy, lib_scope                      # noqa: E402
from bbtools.lib_egress import make_session, OutOfScope        # noqa: E402

STOPF = os.path.join(WS, ".claude/state/hunt-loop/STOP")
PAUSEF = os.path.join(WS, ".claude/state/economy/PAUSE")


class Refused(Exception):
    """A gate said no. Nothing left the box."""


def _now():
    return datetime.now(timezone.utc)


def _lane_dir(program, tag):
    if not (isinstance(tag, str) and tag and all(c.isalnum() or c in "-_." for c in tag) and ".." not in tag):
        raise Refused(f"bad tag {tag!r}")
    d = os.path.join(WS, "targets", program, "hunts", tag)
    os.makedirs(os.path.join(d, "raw"), exist_ok=True)
    return d


def _fired(program, tag):
    p = os.path.join(_lane_dir(program, tag), "ledger.jsonl")
    try:
        with open(p, encoding="utf-8") as f:
            return sum(1 for ln in f if ln.strip())
    except OSError:
        return 0


def _throttle(program, rps):
    """Per-program spacing, persisted on disk so two shells cannot each think they are under the cap."""
    gap = 1.0 / max(float(rps or 0.1), 0.1)
    stamp = os.path.join(WS, ".claude/state/hunt-loop", f"live-lane-last-{program}")
    last = 0.0
    try:
        with open(stamp, encoding="utf-8") as f:
            last = float((f.read() or "0").strip() or 0)
    except (OSError, ValueError):
        last = 0.0
    wait = last + gap - time.time()
    if wait > 0:
        time.sleep(wait)
    try:
        os.makedirs(os.path.dirname(stamp), exist_ok=True)
        with open(stamp, "w") as f:
            f.write(str(time.time()))
    except OSError:
        pass


def _carrier(headers, pol):
    """The programme's own identification, through the agent's one implementation (T-294)."""
    try:
        import gnoc_agent as G
        return G._apply_carrier(dict(headers or {}), pol)
    except Exception as e:  # noqa: BLE001 - a missing carrier must be reported, not guessed
        raise Refused(f"carrier could not be applied ({type(e).__name__}: {e})") from e


def plan(program, url, headers=None, tag="live", cap=25, stopf=None, paused=None):
    """Every pre-wire gate. Returns (policy, headers) or raises Refused. NO network."""
    stopf = STOPF if stopf is None else stopf
    paused = PAUSEF if paused is None else paused
    if os.path.exists(stopf):
        raise Refused(f"STOP is set ({stopf}): the lane is killed, no request fired")
    if os.path.exists(paused):
        raise Refused(f"economy PAUSE is set ({paused}): no request fired")
    # CAP IS A LOCAL FACT, so it is checked before any URL-dependent work: a spent lane must not be
    # able to look "allowed" just because the next URL happens to parse.
    if _fired(program, tag) >= int(cap):
        raise Refused(f"lane cap reached: {cap} request(s) already in targets/{program}/hunts/{tag}")
    try:
        import gnoc_session
        ok, why = gnoc_session.require("live-lane")
    except Exception:  # noqa: BLE001 - no session module: fail closed
        ok, why = False, "gnoc_session unavailable"
    if not ok:
        raise Refused(why)
    if why:
        print(f"NOTE: {why}", file=sys.stderr)
    if not os.path.isfile(os.path.join(WS, "targets", program, "SCOPE.txt")):
        raise Refused(f"no targets/{program}/SCOPE.txt: not an intaken program")
    bok, bwhy = lib_scope.program_allows(url, program, WS)
    if not bok:
        raise Refused(f"OUT_OF_SCOPE {url} for {program}: {bwhy}")
    pol = lib_policy.policy(program)
    if not pol.get("network_ok"):
        raise Refused(f"{program} policy {pol.get('status')}: {pol.get('evidence', '')[:200]}")
    return pol, _carrier(headers, pol)


def fire(program, tag, method, url, headers=None, body=None, identity=None, cap=25, timeout=30):
    """Gate, throttle, send once, capture raw + sealed, ledger it. Returns the response."""
    pol, hdrs = plan(program, url, headers, tag=tag, cap=cap)
    _throttle(program, pol.get("rps") or 3.0)
    scope_file = os.path.join(WS, "targets", program, "SCOPE.txt")
    s = make_session(scope_file)
    if identity:
        with open(identity, encoding="utf-8") as f:
            state = json.load(f)
        # ONLY cookies that belong to the target: a storage state also carries analytics and ad-network
        # cookies (doubleclick, taboola...), and shipping those to the target is both noise and a leak.
        host = (url.split("/")[2] if "://" in url else "").split(":")[0].lower()
        base = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host
        for c in state.get("cookies") or []:
            dom = (c.get("domain") or "").lstrip(".").lower()
            if not dom or not (dom == host or dom.endswith("." + base) or dom == base):
                continue
            s.cookies.set(c["name"], c["value"], domain=c.get("domain"), path=c.get("path", "/"))
    t0 = time.monotonic()
    try:
        r = s.request(method.upper(), url, headers=hdrs, data=body, timeout=timeout)
    except OutOfScope as e:
        raise Refused(str(e)) from e
    elapsed = round(time.monotonic() - t0, 3)
    d = _lane_dir(program, tag)
    rp = os.path.join(d, "raw", f"{_now():%H%M%S%f}-{method.lower()}.json")
    row = {"ts": _now().isoformat(), "lane": tag, "program": program, "elapsed": elapsed,
           "request": {"method": method.upper(), "url": url, "headers": hdrs, "body": body},
           "response": {"status": r.status_code, "headers": dict(r.headers),
                        "body": (r.text if r.text is not None else "")[:2_000_000]}}
    with open(rp, "w", encoding="utf-8") as f:
        json.dump(row, f, indent=1, default=str)
    try:
        import gnoc_oracle
        gnoc_oracle.seal(rp)
    except Exception:  # noqa: BLE001 - an unsealed capture is usable evidence, just not oracle proof
        pass
    with open(os.path.join(d, "ledger.jsonl"), "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": row["ts"], "method": method.upper(), "url": url,
                            "status": r.status_code, "len": len(r.content or b""),
                            "ct": r.headers.get("content-type", ""), "raw": os.path.relpath(rp, WS)}) + "\n")
    with open(os.path.join(d, "commands.txt"), "a", encoding="utf-8") as f:
        f.write(f"{_now():%H:%M:%S} {tag} {method.upper()} {url} -> {r.status_code} "
                f"{len(r.content or b'')}b {elapsed}s\n")
    return r


def _selfcheck():
    """Offline proof of the refusals. Loopback is used as the out-of-scope host: no external traffic."""
    import tempfile
    # The session gate is proven by test_gnoc_session.py; here it would mask the other refusals, so the
    # deliberate override (the same one a human sets for one unattended run) is set for THIS process only.
    os.environ["GNOC_HUNT_NO_SESSION"] = "1"
    bad = 0
    prog = next((p for p in sorted(os.listdir(os.path.join(WS, "targets")))
                 if os.path.isfile(os.path.join(WS, "targets", p, "SCOPE.txt"))), None)
    if not prog:
        print("live-lane selfcheck: no intaken program on disk")
        return 1
    checks = []

    def expect(name, fn, want):
        try:
            fn()
            got = "fired"
        except Refused as e:
            got = str(e)
        ok = want in got
        checks.append((ok, name, got[:100]))
        return 0 if ok else 1

    tmp = tempfile.mkdtemp(prefix="live-lane-")
    stop = os.path.join(tmp, "STOP")
    open(stop, "w").close()
    bad += expect("STOP refuses before any gate work",
                  lambda: plan(prog, f"https://{prog}.example/", tag="selfcheck", stopf=stop, paused=os.path.join(tmp, "nope")),
                  "STOP is set")
    bad += expect("out-of-scope URL is refused",
                  lambda: plan(prog, "https://definitely-not-in-scope.example/x", tag="selfcheck",
                               stopf=os.path.join(tmp, "no"), paused=os.path.join(tmp, "no")),
                  "OUT_OF_SCOPE")
    bad += expect("lane cap refuses the next request",
                  lambda: (_lane_dir(prog, "selfcheck-cap"),
                           open(os.path.join(_lane_dir(prog, "selfcheck-cap"), "ledger.jsonl"), "w").write("{}\n"),
                           plan(prog, f"https://{prog}.example/", tag="selfcheck-cap", cap=1,
                                stopf=os.path.join(tmp, "no"), paused=os.path.join(tmp, "no"))),
                  "lane cap")
    import shutil
    shutil.rmtree(os.path.join(WS, "targets", prog, "hunts", "selfcheck-cap"), ignore_errors=True)
    shutil.rmtree(tmp, ignore_errors=True)
    for ok, name, got in checks:
        print(f"{'ok  ' if ok else 'FAIL'} {name}" + ("" if ok else f"\n     ! {got}"))
    print("live-lane selfcheck:", "ALL ASSERTIONS PASS" if not bad else f"{bad} FAILED")
    return 0 if not bad else 1


def main(argv):
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--selfcheck", action="store_true")
    ap.add_argument("program", nargs="?")
    ap.add_argument("tag", nargs="?")
    ap.add_argument("method", nargs="?")
    ap.add_argument("url", nargs="?")
    ap.add_argument("--body")
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--identity")
    ap.add_argument("--cap", type=int, default=25)
    ap.add_argument("--timeout", type=float, default=30)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    if a.selfcheck or not (a.program and a.tag and a.method and a.url):
        return _selfcheck()
    hdrs = {}
    for kv in a.header:
        k, _, v = kv.partition(":")
        hdrs[k.strip()] = v.strip()
    body = None
    if a.body:
        with open(a.body, encoding="utf-8") as f:
            body = f.read()
    try:
        if a.dry_run:
            pol, hdrs = plan(a.program, a.url, hdrs, tag=a.tag, cap=a.cap)
            print(json.dumps({"program": a.program, "url": a.url, "rps": pol.get("rps"),
                              "header": pol.get("header"), "ua_literal": pol.get("ua_literal"),
                              "headers": hdrs, "cap": a.cap, "dry_run": True}, indent=1))
            return 0
        r = fire(a.program, a.tag, a.method, a.url, hdrs, body, a.identity, a.cap, a.timeout)
    except Refused as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 2
    print(f"{a.tag} {r.status_code} {len(r.content or b'')}b ct={r.headers.get('content-type')}")
    print((r.text or "")[:int(os.environ.get("N", "600"))])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
