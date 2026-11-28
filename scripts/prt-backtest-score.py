#!/usr/bin/env python3
"""Score the blinded PRT backtest against the held-back ground truth.

Reads BACKTEST-PREDICTIONS.md (rows containing a case id and a PREDICTION token) and
KEY.json (the truth). Reports accuracy, the confusion matrix, and - the part that
matters - whether the gates separate POSITIVE from everything else better than the
base rate. A gate set that cannot beat the base rate is not a technique.
"""
import json, re, sys, collections, os

ROOT = os.path.join(os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "research/technique/backtest")
KEY = os.path.join(ROOT, "KEY.json")
PRED = os.path.join(ROOT, "BACKTEST-PREDICTIONS.md")
POS = {"resolved", "triaged", "retesting", "pending-program-review"}


def truth_bucket(state):
    if state in POS:
        return "POSITIVE"
    return {"duplicate": "DUPLICATE", "informative": "INFORMATIVE",
            "not-applicable": "NOT-APPLICABLE"}.get(state, state.upper())


def main():
    key = json.load(open(KEY))
    txt = open(PRED).read()
    # a row is any line mentioning a case id and a prediction token
    preds = {}
    gates = {}
    for line in txt.splitlines():
        m = re.search(r"\bB(\d{3})\b", line)
        if not m:
            continue
        cid = "B" + m.group(1)
        p = re.search(r"\b(POSITIVE|INFORMATIVE|DUPLICATE|NOT-APPLICABLE)\b", line)
        if p and cid not in preds:
            preds[cid] = p.group(1)
            g = {}
            for name, pat in (("G1", r"G1[^|]*?(pass|fail)"), ("G3", r"G3[^|]*?(pass|fail)"),
                              ("G4", r"G4[^|]*?(yes|no)"), ("dupe", r"dupe[- ]risk[^|]*?(low|med|high)")):
                mm = re.search(pat, line, re.I)
                if mm:
                    g[name] = mm.group(1).lower()
            gates[cid] = g
    scored = [(c, p, truth_bucket(key[c]["state"])) for c, p in preds.items() if c in key]
    if not scored:
        print("no scorable rows parsed - check the prediction row format", file=sys.stderr)
        return 2
    n = len(scored)
    exact = sum(1 for _, p, t in scored if p == t)
    base = collections.Counter(t for _, _, t in scored)
    majority = base.most_common(1)[0]
    print(f"scored {n} of {len(key)} cases  (unparsed/missing: {len(key)-n})")
    print(f"ground truth: {dict(base)}")
    print()
    print(f"EXACT 4-WAY ACCURACY: {exact}/{n} = {100*exact//n}%")
    print(f"  majority-class baseline: always say {majority[0]} -> {100*majority[1]//n}%")
    print()
    # the decision that matters: POSITIVE vs not
    tp = sum(1 for _, p, t in scored if p == "POSITIVE" and t == "POSITIVE")
    fp = sum(1 for _, p, t in scored if p == "POSITIVE" and t != "POSITIVE")
    fn = sum(1 for _, p, t in scored if p != "POSITIVE" and t == "POSITIVE")
    tn = sum(1 for _, p, t in scored if p != "POSITIVE" and t != "POSITIVE")
    prec = 100*tp//(tp+fp) if tp+fp else 0
    rec = 100*tp//(tp+fn) if tp+fn else 0
    bp = 100*base.get("POSITIVE", 0)//n
    print("BINARY: would the gates have told us to FILE?")
    print(f"  predicted POSITIVE: {tp+fp}   actually POSITIVE: {tp+fn}")
    print(f"  precision {prec}%  recall {rec}%   (base rate {bp}%)")
    lift = prec - bp
    print(f"  LIFT OVER BASE RATE: {lift:+d} points")
    if lift <= 0:
        print("  >> THE GATES ADD NOTHING on this data. Do not ship them as a filter.")
    elif lift < 10:
        print("  >> marginal. Not enough to gate filing on.")
    else:
        print("  >> real signal.")
    print()
    print("CONFUSION (rows predicted, cols actual):")
    cats = ["POSITIVE", "INFORMATIVE", "DUPLICATE", "NOT-APPLICABLE"]
    print("              " + "".join(f"{c[:9]:>12s}" for c in cats))
    for pc in cats:
        row = [sum(1 for _, p, t in scored if p == pc and t == tc) for tc in cats]
        print(f"  {pc:12s}" + "".join(f"{v:12d}" for v in row))
    print()
    # per-gate discrimination
    for gname, good in (("G1", "pass"), ("G3", "pass"), ("G4", "no")):
        rows = [(gates[c].get(gname), t) for c, p, t in scored if gates.get(c, {}).get(gname)]
        if len(rows) < 20:
            print(f"{gname}: only {len(rows)} rows carried a parseable value - cannot assess")
            continue
        g = [t for v, t in rows if v == good]
        b = [t for v, t in rows if v != good]
        gp = 100*sum(1 for t in g if t == "POSITIVE")//len(g) if g else 0
        bpr = 100*sum(1 for t in b if t == "POSITIVE")//len(b) if b else 0
        print(f"{gname}: {good}->{gp}% positive (n={len(g)})   other->{bpr}% positive (n={len(b)})"
              f"   separation {gp-bpr:+d} pts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
