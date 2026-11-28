#!/usr/bin/env python3
# H1 directory picker. Pages public directory GraphQL (no auth), filters to the operator's criteria,
# prints ONLY the ranked shortlist. Raw JSON stays in memory/disk, never printed.
import json, subprocess, datetime, sys

GQL = "https://hackerone.com/graphql"
TODAY = datetime.datetime.now(datetime.timezone.utc)
RECENT_CUTOFF = TODAY - datetime.timedelta(days=14)   # "resolved in last 2 weeks"

QUERY = """query($first:Int,$after:String,$where:FiltersTeamFilterInput){
 teams(first:$first,after:$after,where:$where){
  pageInfo{endCursor hasNextPage}
  edges{node{
   handle name resolved_report_count response_efficiency_percentage last_report_resolved_at
   average_bounty_lower_amount average_bounty_upper_amount top_bounty_lower_amount top_bounty_upper_amount minimum_bounty
   offers_bounties submission_state
   structured_scopes(first:100,eligible_for_submission:true){edges{node{asset_type asset_identifier eligible_for_bounty}}}
  }}
 }}"""

def call(after):
    variables = {
        "first": 100, "after": after,
        "where": {"submission_state": {"_eq": "open"}, "offers_bounties": {"_eq": True}},
    }
    body = json.dumps({"query": QUERY, "variables": variables})
    out = subprocess.run(
        ["curl", "-s", "-X", "POST", GQL, "-H", "Content-Type: application/json",
         "-H", "User-Agent: Mozilla/5.0", "-d", body],
        capture_output=True, text=True, timeout=60).stdout
    return json.loads(out)

# ---- page everything ----
nodes, after, pages = [], None, 0
while True:
    d = call(after)
    if "errors" in d:
        print("GQL ERROR:", json.dumps(d["errors"])[:300]); sys.exit(1)
    t = d["data"]["teams"]
    nodes += [e["node"] for e in t["edges"]]
    pages += 1
    if not t["pageInfo"]["hasNextPage"] or pages > 40:
        break
    after = t["pageInfo"]["endCursor"]

json.dump(nodes, open("/tmp/h1_programs_full.json", "w"))

def parse_dt(s):
    if not s: return None
    return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))

def wildcards(n):
    w = []
    for e in n.get("structured_scopes", {}).get("edges", []):
        sc = e["node"]
        aid = (sc.get("asset_identifier") or "")
        if sc.get("asset_type") == "WILDCARD" or "*" in aid:
            w.append((aid, sc.get("eligible_for_bounty")))
    return w

# ---- reference: massive band ----
pal = next((n for n in nodes if "massive" in n["handle"].lower()), None)

# ---- filter ----
rows = []
for n in nodes:
    h = n["handle"].lower()
    if "massive" in h:  # excluded from picks, shown as reference
        continue
    resolved = n.get("resolved_report_count") or 0
    eff = n.get("response_efficiency_percentage")
    lr = parse_dt(n.get("last_report_resolved_at"))
    top = n.get("top_bounty_upper_amount") or 0
    w = wildcards(n)
    wb = [x for x in w if x[1]]                       # bounty-eligible wildcards
    if resolved < 100:            continue            # min 100 total resolved
    if eff is None or not (70 <= eff <= 95): continue # response efficiency band
    if lr is None or lr < RECENT_CUTOFF: continue     # resolved in last ~2 weeks
    if not wb:                    continue            # good wildcard scope, bounty-eligible
    if top < 1000:                continue            # pays medium (real payouts)
    days = (TODAY - lr).days
    rows.append({
        "h": n["handle"], "resolved": resolved, "eff": eff, "days": days,
        "avg_lo": n.get("average_bounty_lower_amount"), "avg_hi": n.get("average_bounty_upper_amount"),
        "top": top, "nwild": len(wb), "sample": wb[0][0] if wb else "",
    })

# ---- rank: active + not-saturated + solid pay. Prefer moderate volume (proxy for <100/90d). ----
def score(r):
    s = 0
    s += 40 if r["resolved"] <= 400 else (20 if r["resolved"] <= 900 else 0)  # not saturated
    s += max(0, 14 - r["days"]) * 2                                            # freshness
    s += 15 if 78 <= r["eff"] <= 93 else 0                                     # human-responsive band
    s += 10 if (r["top"] or 0) >= 3000 else 0
    s += 8  if (r["avg_hi"] or 0) >= 500 else 0
    return s
rows.sort(key=lambda r: (-score(r), r["days"]))

def money(lo, hi):
    if not hi: return "-"
    return f"${lo or hi}-{hi}"

print("REFERENCE (excluded) Massive public:")
if pal:
    print(f"  resolved={pal.get('resolved_report_count')} eff={pal.get('response_efficiency_percentage')}% "
          f"avg={money(pal.get('average_bounty_lower_amount'),pal.get('average_bounty_upper_amount'))} "
          f"top=${pal.get('top_bounty_upper_amount')} lastResolved={pal.get('last_report_resolved_at')}")
print(f"\nUniverse pulled: {len(nodes)} open+bounty programs. Matches all hard filters: {len(rows)}\n")

hdr = f'{"#":<3}{"handle":<26}{"resolvd":>8}{"eff%":>5}{"ago(d)":>7}{"avgBnty":>12}{"topBnty":>9}{"wild":>5}  sample-scope'
print(hdr); print("-"*len(hdr))
for i, r in enumerate(rows[:20], 1):
    print(f'{i:<3}{r["h"][:25]:<26}{r["resolved"]:>8}{r["eff"]:>5}{r["days"]:>7}'
          f'{money(r["avg_lo"],r["avg_hi"]):>12}{("$"+str(r["top"])):>9}{r["nwild"]:>5}  {r["sample"][:40]}')

print("\nMODERATE volume (resolved<=400, best 'room-to-hunt' proxy for <100/90d):")
for r in rows:
    if r["resolved"] <= 400:
        print(f'  {r["h"]:<26} resolved={r["resolved"]:<5} eff={r["eff"]}% {r["days"]}d ago '
              f'avg={money(r["avg_lo"],r["avg_hi"])} top=${r["top"]} wild={r["nwild"]}')
