#!/usr/bin/env python3
"""PRT - the Pre-Registered Terminal.

Three commitments written BEFORE a probe, so a terminal cannot be rationalised afterwards:

  C1 PROOF   - sha256 of a canary preimage planted in an object we own
  C2 PREMISE - the complete set of what the attacker can already do
  C3 DELTA   - the one new capability, which must lie outside C2

The adjudicator is NON-AI code. It scans captured response bytes for a token whose sha256
equals the committed hash. A finder cannot pass this by asserting that it passed.

WHY: our dominant historical kill is mechanism-without-capability (28 of 39 informatives) and
the disclosed-corpus dominant kill is the precondition trap (66% of 103 rejections). Both are
post-hoc rationalisations. Pre-registration removes the opportunity to make one.

USAGE
  prt.py commit  --target <prog> --vector <slug> --location "B profile email" \
                 --identity-excluded "account A" --premise-file premise.txt --delta "..."
        -> plants nothing itself; it MINTS the canary, prints the preimage ONCE for you to
           plant, and stores only the hash + metadata.
  prt.py adjudicate --target <prog> --vector <slug> --capture <file> [--capture <file> ...]
        -> CONFIRMED / NOT-CONFIRMED, exit 0 / 1. Scans for any token hashing to the commitment.
  prt.py control --target <prog> --vector <slug> --capture <file>
        -> asserts the preimage is ABSENT (the negative control). exit 0 if correctly absent.
  prt.py show    --target <prog> [--vector <slug>]
  prt.py selfcheck
"""
import argparse, hashlib, json, os, re, secrets, sys, time

STATE = os.environ.get("PRT_STATE", os.path.join(os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), ".claude/state/prt"))
# A canary is a high-entropy token. We scan captures for anything token-shaped and hash it.
TOKEN_RE = re.compile(rb"[A-Za-z0-9_-]{16,128}")


def _dir(target):
    d = os.path.join(STATE, target)
    os.makedirs(d, exist_ok=True)
    return d


def _path(target, vector):
    return os.path.join(_dir(target), f"{vector}.json")


def _sealed(target, vector):
    d = os.path.join(_dir(target), "sealed")
    os.makedirs(d, mode=0o700, exist_ok=True)
    return os.path.join(d, f"{vector}.preimage")


def cmd_commit(a):
    p = _path(a.target, a.vector)
    if os.path.exists(p) and not a.force:
        print(f"REFUSED: commitment already exists at {p}", file=sys.stderr)
        print("A commitment is immutable by design. Use a new --vector, or --force only if the", file=sys.stderr)
        print("previous commitment was never probed.", file=sys.stderr)
        return 2
    premise = []
    if a.premise_file:
        premise = [l.strip() for l in open(a.premise_file) if l.strip()]
    premise += (a.premise or [])
    if not premise:
        print("REFUSED: C2 PREMISE is empty. Enumerate what the attacker can ALREADY do, as", file=sys.stderr)
        print("capabilities, before probing. 66% of disclosed rejections are a premise failure.", file=sys.stderr)
        return 2
    if not a.delta:
        print("REFUSED: C3 DELTA is required - one sentence of new capability outside C2.", file=sys.stderr)
        return 2
    canary = "gn" + secrets.token_urlsafe(24).replace("-", "").replace("_", "")
    h = hashlib.sha256(canary.encode()).hexdigest()
    rec = {
        "target": a.target, "vector": a.vector,
        "c1_proof_sha256": h,
        "c2_premise": premise,
        "c3_delta": a.delta,
        "location": a.location,
        "identity_excluded": a.identity_excluded,
        "committed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "state": "COMMITTED",
        "adjudications": [],
    }
    json.dump(rec, open(p, "w"), indent=1)
    sp = _sealed(a.target, a.vector)
    with open(sp, "w") as f:
        f.write(canary + "\n")
    os.chmod(sp, 0o600)
    print("C1 PROOF   sha256 =", h)
    print("C2 PREMISE", len(premise), "capabilities recorded")
    print("C3 DELTA  ", a.delta)
    print()
    print("PLANT THIS PREIMAGE NOW, in:", a.location)
    print("  ", canary)
    print()
    print("It must sit where", a.identity_excluded, "cannot legitimately read it.")
    print("If that location is public by design, finding it proves NOTHING - pick another field.")
    print("Never plant in an object owned by a real user. Ours only.")
    print(f"commitment: {p}")
    print(f"sealed preimage: {sp}  (do not quote this in any digest or verdict)")
    return 0


def _load(target, vector):
    p = _path(target, vector)
    if not os.path.exists(p):
        print(f"NO COMMITMENT at {p} - you cannot adjudicate a terminal you never pre-registered.",
              file=sys.stderr)
        sys.exit(2)
    return json.load(open(p)), p


def _scan(paths, want_hash):
    hits = []
    for fp in paths:
        try:
            blob = open(fp, "rb").read()
        except Exception as e:
            print(f"  unreadable {fp}: {e}", file=sys.stderr); continue
        if os.path.getsize(fp) == 0:
            print(f"  WARNING zero-byte capture {fp} - an empty file reads as a tested negative",
                  file=sys.stderr)
        for m in set(TOKEN_RE.findall(blob)):
            if hashlib.sha256(m).hexdigest() == want_hash:
                hits.append((fp, m.decode(errors="replace")))
    return hits


def cmd_adjudicate(a):
    rec, p = _load(a.target, a.vector)
    hits = _scan(a.capture, rec["c1_proof_sha256"])
    res = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "captures": a.capture, "verdict": "CONFIRMED" if hits else "NOT-CONFIRMED",
           "hits": [{"file": f, "token": t} for f, t in hits]}
    rec["adjudications"].append(res)
    rec["state"] = res["verdict"]
    json.dump(rec, open(p, "w"), indent=1)
    if hits:
        print("CONFIRMED")
        for f, t in hits:
            print(f"  {f}: contains a token whose sha256 == {rec['c1_proof_sha256']}")
        print()
        print("TERMINAL RECEIPT (arithmetic, not judgement):")
        print(f"  the capture contains a string committed at {rec['committed_at_utc']}, BEFORE the")
        print(f"  probe, which existed only in: {rec['location']}")
        print(f"  and which {rec['identity_excluded']} must not be able to read.")
        print(f"  NEW CAPABILITY: {rec['c3_delta']}")
        print()
        print("STILL REQUIRED before this ships:")
        print("  1. the negative control: prt.py control  (same read, pre-crossing, preimage ABSENT)")
        print("  2. the premise check: is C3 outside every line of C2? re-read them now.")
        print("  3. public prior-art dedup - this gate does NOT address duplicates, which killed")
        print("     5 of our 7 filings.")
        return 0
    print("NOT-CONFIRMED")
    print("  no token in the captures hashes to the commitment.")
    print("  This is a LEAD at best. Do not write it as a terminal.")
    return 1


def cmd_control(a):
    rec, _ = _load(a.target, a.vector)
    hits = _scan([a.capture], rec["c1_proof_sha256"])
    if hits:
        print("CONTROL FAILED - the preimage is present in the control capture.")
        print("  The canary is reachable WITHOUT the defect, so it proves nothing.")
        print("  Either the location is public by design, or the control is not actually a control.")
        return 1
    print("CONTROL HELD - preimage absent from the control capture, as predicted.")
    return 0


def cmd_show(a):
    d = _dir(a.target)
    vs = [a.vector] if a.vector else [f[:-5] for f in sorted(os.listdir(d)) if f.endswith(".json")]
    for v in vs:
        rec, _ = _load(a.target, v)
        print(f"[{rec['state']}] {rec['target']}/{rec['vector']}  committed {rec['committed_at_utc']}")
        print(f"   C3 DELTA: {rec['c3_delta']}")
        print(f"   location: {rec['location']}   excluded: {rec['identity_excluded']}")
        print(f"   C2 premise ({len(rec['c2_premise'])}):")
        for l in rec["c2_premise"]:
            print(f"      - {l}")
        for ad in rec["adjudications"]:
            print(f"   {ad['at']} {ad['verdict']} on {len(ad['captures'])} capture(s)")
    return 0




LEDGER = os.path.join(os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "research/technique/PRECISION-LEDGER.json")


def cmd_precision(a):
    """Look up our OWN historical precision for a class or program before investing in it."""
    try:
        led = json.load(open(LEDGER))
    except Exception as e:
        print(f"no precision ledger at {LEDGER}: {e}", file=sys.stderr)
        return 2
    print(f"our own adjudicated record: {led['overall_precision_pct']}% positive "
          f"on n={led['n_adjudicated']}  ({led['definition']})")
    print()

    def report(book, key, label):
        rows = led[book]
        # case-insensitive substring match, so a partial class name works
        hits = {k: v for k, v in rows.items() if key.lower() in k.lower()}
        if not hits:
            print(f"  no {label} row matching {key!r}. Absence is NOT a good sign or a bad one -")
            print("  it means we have never shipped it, so there is no rate to steer on.")
            return
        for k, v in sorted(hits.items(), key=lambda kv: -kv[1]["n"]):
            verdict = ""
            if v["n"] < 5:
                verdict = "n too small to steer on - treat as unmeasured"
            elif v["precision_pct"] < 20:
                verdict = "POOR CONVERTER - needs a new gate or a different angle, not more volume"
            elif v["precision_pct"] >= 40:
                verdict = "our best-converting ground"
            else:
                verdict = "middling"
            print(f"  {label} {k!r}: {v['precision_pct']}% positive ({v['positive']}/{v['n']}), "
                  f"dupes {v['dupe_pct']}%")
            print(f"      -> {verdict}")
            if v["dupe_pct"] >= 30 and v["n"] >= 4:
                print(f"      -> DUPE WARNING {v['dupe_pct']}%: the asset is telling you it is "
                      f"already fully hunted")

    if a.klass:
        report("by_class", a.klass, "class")
    if a.program:
        report("by_program", a.program, "program")
    if not a.klass and not a.program:
        print("pass --class and/or --program. Worst converters on real n:")
        for k, v in sorted(led["by_class"].items(), key=lambda kv: kv[1]["precision_pct"]):
            if v["n"] >= 5:
                print(f"  {v['precision_pct']:3d}%  {v['positive']}/{v['n']}  {k}")
    print()
    print("Reminder: our severity self-rating is INVERSELY calibrated (self-rated critical 26%,")
    print("high 21%, medium 16%). The moment a finding feels Critical is the moment the premise")
    print("ledger is most likely to be unwritten. Write it then.")
    return 0

def cmd_gate(a):
    """G1 premise gate + G3 terminal gate + G4 still-a-bug gate, as a filing decision."""
    rec, _ = _load(a.target, a.vector)
    print(f"PRT FILING GATE  {rec['target']}/{rec['vector']}")
    print()
    fail = []
    warn = []

    # G3 - terminal, mechanical
    confirmed = any(ad["verdict"] == "CONFIRMED" for ad in rec["adjudications"])
    print("G3 TERMINAL (mechanical)")
    if confirmed:
        print("   CONFIRMED - a capture contains the committed preimage")
    else:
        print("   NOT CONFIRMED - no adjudication has matched the commitment")
        fail.append("G3: no confirmed terminal. This is a LEAD, not a report.")
    if not a.control_held:
        fail.append("G3: --control-held not asserted. Run `prt.py control` on the pre-crossing "
                    "capture and confirm the preimage is ABSENT, or the canary proves nothing.")
    print()

    # G1 - premise
    print("G1' PREMISE (the 66% kill; in the backtest this veto dropped 18 filings and cost 0 positives)")
    print("   complete in writing: \"if the attacker can already <hardest precondition P>, then ___\"")
    print("   the gate FAILS if that blank can hold this report's own terminal")
    print("   C2, what the attacker can ALREADY do:")
    for l in rec["c2_premise"]:
        print(f"      - {l}")
    print(f"   C3 DELTA: {rec['c3_delta']}")
    if not a.delta_outside_premise:
        fail.append("G1: --delta-outside-premise not asserted. If the delta sits INSIDE the premise "
                    "there is no finding at any depth - relocate the premise (G2) or park it.")
    else:
        print("   asserted: the delta lies outside every line of C2")
    print()

    # G4 - still a bug
    print("G4' STILL-A-BUG (predicts informative vs resolved)")
    print("   Q: write the one-line fix commit. Does it change behaviour the program DOCUMENTS,")
    print("      ADVERTISES or BILLS FOR? If not, this is an informative.")
    if a.still_a_bug is None:
        fail.append("G4: answer --still-a-bug yes|no. Unanswered means unexamined.")
    elif a.still_a_bug == "yes":
        warn.append("G4: this is the INFORMATIVE shape. 50 of 95 informative closes say 'it "
                    "identified a bug'; 0 of 109 not-applicable closes do. A real contribution, "
                    "but expect informative, not resolved. File it knowing that, or escalate so the "
                    "boundary crossing - not the bug - is the claim.")
        print("   answered YES -> informative shape")
    else:
        print("   answered NO -> the shape that resolves: the boundary crossing is the claim")
    print()

    if warn:
        print("WARNINGS")
        for w in warn:
            print("   ! " + w)
        print()
    if fail:
        print("VERDICT: NOT FILEABLE")
        for f in fail:
            print("   x " + f)
        print()
        print("Reminder: this gate does NOT check duplicates. The public prior-art sweep is")
        print("separate and mandatory - 5 of our 7 filings died as known-accepted duplicates.")
        return 1
    print("VERDICT: FILEABLE on the PRT gates.")
    print()
    print("Still required, none of which PRT checks:")
    print("  - public prior-art dedup (the dominant kill on OUR record)")
    print("  - program policy: class qualifies, asset in scope, venue pays")
    print("  - make the triager's repro cheap: one command, exact version/commit/config")
    print("  - no hedge words where a measurement belongs; no code claim absent from the source")
    return 0

def cmd_selfcheck(a):
    import tempfile, shutil
    global STATE
    tmp = tempfile.mkdtemp(prefix="prt-selfcheck-")
    STATE = tmp
    ok = True

    def chk(name, cond):
        nonlocal ok
        print(("  PASS  " if cond else "  FAIL  ") + name)
        ok = ok and cond

    pf = os.path.join(tmp, "premise.txt")
    open(pf, "w").write("can register a free account\ncan read own profile\n")
    ns = argparse.Namespace(target="selftest", vector="v1", location="B private email",
                            identity_excluded="account A", premise_file=pf, premise=None,
                            delta="read account B private email", force=False)
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cmd_commit(ns)
    chk("commit returns 0", rc == 0)
    out = buf.getvalue()
    canary = open(os.path.join(tmp, "selftest", "sealed", "v1.preimage")).read().strip()
    chk("preimage was sealed", len(canary) > 20)
    chk("preimage is printed once for planting", canary in out)

    # immutability
    with contextlib.redirect_stderr(io.StringIO()):
        rc2 = cmd_commit(ns)
    chk("re-commit without --force is REFUSED", rc2 == 2)

    # empty premise is refused
    ns2 = argparse.Namespace(target="selftest", vector="v2", location="x", identity_excluded="y",
                             premise_file=None, premise=None, delta="z", force=False)
    with contextlib.redirect_stderr(io.StringIO()):
        chk("empty C2 premise is REFUSED", cmd_commit(ns2) == 2)

    # adjudication: positive
    cap = os.path.join(tmp, "resp.txt")
    open(cap, "w").write('{"email":"' + canary + '","id":42}')
    with contextlib.redirect_stdout(io.StringIO()):
        chk("adjudicate CONFIRMS a capture containing the preimage",
            cmd_adjudicate(argparse.Namespace(target="selftest", vector="v1", capture=[cap])) == 0)
    # adjudication: negative
    cap2 = os.path.join(tmp, "resp2.txt")
    open(cap2, "w").write('{"email":"someoneelse@example.com","id":42}')
    with contextlib.redirect_stdout(io.StringIO()):
        chk("adjudicate REFUSES a capture without the preimage",
            cmd_adjudicate(argparse.Namespace(target="selftest", vector="v1", capture=[cap2])) == 1)
    # a near-miss must not pass
    cap3 = os.path.join(tmp, "resp3.txt")
    open(cap3, "w").write(canary[:-1] + "X")
    with contextlib.redirect_stdout(io.StringIO()):
        chk("a one-character-off near-miss does NOT confirm",
            cmd_adjudicate(argparse.Namespace(target="selftest", vector="v1", capture=[cap3])) == 1)
    # control
    with contextlib.redirect_stdout(io.StringIO()):
        chk("control HOLDS when preimage absent",
            cmd_control(argparse.Namespace(target="selftest", vector="v1", capture=cap2)) == 0)
        chk("control FAILS when preimage present",
            cmd_control(argparse.Namespace(target="selftest", vector="v1", capture=cap)) == 1)
    # adjudicating an unregistered vector must hard-exit
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            cmd_adjudicate(argparse.Namespace(target="selftest", vector="never", capture=[cap]))
        chk("adjudicating an unregistered vector exits", False)
    except SystemExit as e:
        chk("adjudicating an unregistered vector exits 2", e.code == 2)
    # gate
    with contextlib.redirect_stdout(io.StringIO()):
        rcg = cmd_gate(argparse.Namespace(target="selftest", vector="v1", control_held=True,
                       delta_outside_premise=True, still_a_bug="no"))
    chk("gate passes with confirmed terminal + control + premise + G4 no", rcg == 0)
    with contextlib.redirect_stdout(io.StringIO()):
        rcg2 = cmd_gate(argparse.Namespace(target="selftest", vector="v1", control_held=False,
                        delta_outside_premise=True, still_a_bug="no"))
    chk("gate FAILS without the negative control", rcg2 == 1)
    with contextlib.redirect_stdout(io.StringIO()):
        rcg3 = cmd_gate(argparse.Namespace(target="selftest", vector="v1", control_held=True,
                        delta_outside_premise=False, still_a_bug="no"))
    chk("gate FAILS when the delta is not outside the premise", rcg3 == 1)
    with contextlib.redirect_stdout(io.StringIO()):
        rcg4 = cmd_gate(argparse.Namespace(target="selftest", vector="v1", control_held=True,
                        delta_outside_premise=True, still_a_bug=None))
    chk("gate FAILS when G4 is unanswered", rcg4 == 1)
    shutil.rmtree(tmp, ignore_errors=True)
    print("SELFCHECK", "GREEN" if ok else "RED")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="PRT - the Pre-Registered Terminal")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("commit"); c.set_defaults(fn=cmd_commit)
    c.add_argument("--target", required=True); c.add_argument("--vector", required=True)
    c.add_argument("--location", required=True, help="where the canary will be planted")
    c.add_argument("--identity-excluded", required=True, help="the actor that must not reach it")
    c.add_argument("--premise-file"); c.add_argument("--premise", action="append")
    c.add_argument("--delta"); c.add_argument("--force", action="store_true")
    a_ = sub.add_parser("adjudicate"); a_.set_defaults(fn=cmd_adjudicate)
    a_.add_argument("--target", required=True); a_.add_argument("--vector", required=True)
    a_.add_argument("--capture", action="append", required=True)
    k = sub.add_parser("control"); k.set_defaults(fn=cmd_control)
    k.add_argument("--target", required=True); k.add_argument("--vector", required=True)
    k.add_argument("--capture", required=True)
    s = sub.add_parser("show"); s.set_defaults(fn=cmd_show)
    s.add_argument("--target", required=True); s.add_argument("--vector")
    pr = sub.add_parser("precision"); pr.set_defaults(fn=cmd_precision)
    pr.add_argument("--class", dest="klass"); pr.add_argument("--program")
    g = sub.add_parser("gate"); g.set_defaults(fn=cmd_gate)
    g.add_argument("--target", required=True); g.add_argument("--vector", required=True)
    g.add_argument("--control-held", action="store_true",
                   help="assert prt.py control showed the preimage ABSENT pre-crossing")
    g.add_argument("--delta-outside-premise", action="store_true",
                   help="G1': you completed \"if the attacker can already <hardest precondition>, "
                        "then ___\" and the blank does NOT hold this report's own terminal")
    g.add_argument("--still-a-bug", choices=["yes", "no"], default=None,
                   help="G4': write the one-line fix commit - does it change behaviour the program "
                        "documents, advertises or bills for? no = informative shape")
    sc = sub.add_parser("selfcheck"); sc.set_defaults(fn=cmd_selfcheck)
    args = ap.parse_args()
    sys.exit(args.fn(args))


if __name__ == "__main__":
    main()
