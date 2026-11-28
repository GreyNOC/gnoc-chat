#!/usr/bin/env python3
"""Forensic extractor over the last N session transcripts. Streams each jsonl (never
loads it whole) and measures what we ACTUALLY did, not what the injected memory mentions.

Key correctness choices (v2):
  - Agent dispatch tool is named "Agent" (also accept legacy "Task").
  - classes_worked counts a class ONLY from (a) a dispatched hunter's subagent_type or
    (b) a probe command's content - NEVER from assistant prose or tool_result or the
    auto-injected MEMORY.md (which lists every class for a locked target and would make
    every session look broad). This is what answers 'do we test 1 class per vector'.
  - type=="attachment" lines (hook/memory injections) are skipped for text scanning.

Read-only over ~/.claude/projects/<proj>/*.jsonl. Run:
    python3 scripts/learn/session-forensics.py [N]     # default 100
"""
import json, os, re, sys, glob, collections, statistics

PROJ = os.path.expanduser("~/.claude/projects/-home-you-gnoc-workspace")
N = int(sys.argv[1]) if len(sys.argv) > 1 else 100
OUTDIR = os.path.join(os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "scripts/learn/out")
os.makedirs(OUTDIR, exist_ok=True)

# hunter subagent_type -> vuln-class family. Support/recon/gate agents map to None.
def agent_family(st):
    s = (st or "").lower()
    table = [
        (("idor", "bola", "bfla", "unauth-access", "access"), "access"),
        (("ssrf",), "ssrf"),
        (("xss",), "xss"),
        (("oauth", "oidc", "sso"), "oauth"),
        (("saml", "jwt", "token-standard"), "token"),  # token-standard is on-chain; refined below
        (("race",), "race"),
        (("sqli", "sql", "nosql"), "sqli"),
        (("rce", "ssti", "deserial", "command"), "rce"),
        (("cache",), "cache"),
        (("smuggl", "desync"), "smuggling"),
        (("graphql",), "graphql"),
        (("takeover",), "takeover"),
        (("client-trust", "csrf", "cors", "clickjack", "redirect"), "client-trust"),
        (("protopollution", "prototype"), "pp"),
        (("exposure",), "exposure"),
        (("llm",), "llm"),
        (("onchain", "evm-", "proxy-upgrade", "defi", "oracle", "contract-authz", "sig-replay",
          "bridge", "aa-hunter", "mev", "starknet", "algorand", "substrate"), "onchain"),
    ]
    if "token-standard" in s:
        return "onchain"
    for keys, fam in table:
        if any(k in s for k in keys):
            return fam
    return None  # support/recon/gate/meta agent - not a vuln class


CLASS_RX = {
    "access": re.compile(r"idor|bola|bfla|owner-?key|/users?/\d|/accounts?/\d|x-user-id|tenant", re.I),
    "ssrf": re.compile(r"ssrf|169\.254|metadata|url=https?|callback=https?|webhook", re.I),
    "xss": re.compile(r"<script|onerror=|javascript:|alert\(|innerhtml|canary", re.I),
    "oauth": re.compile(r"redirect_uri|/authorize|/oauth|code_challenge|id_token|response_type", re.I),
    "token": re.compile(r"jwt|alg=?none|SAMLResponse|kid=|\.eyJ", re.I),
    "race": re.compile(r"concurrent|--parallel|xargs -P|single-packet|race", re.I),
    "sqli": re.compile(r"union\s+select|' or '1|sleep\(|waitfor|\$ne|pg_sleep", re.I),
    "rce": re.compile(r"\{\{7\*7|;sleep |\$\(|__import__|/etc/passwd|php://|ognl", re.I),
    "cache": re.compile(r"x-forwarded-host|cache|x-cache|purge", re.I),
    "smuggling": re.compile(r"transfer-encoding|content-length: 0|smuggl|cl\.te|te\.cl", re.I),
    "graphql": re.compile(r"graphql|__schema|introspection|persistedquery", re.I),
    "takeover": re.compile(r"cname|dig |nslookup|nxdomain|takeover", re.I),
    "client-trust": re.compile(r"origin:|access-control-allow|x-frame|csrf", re.I),
    "pp": re.compile(r"__proto__|constructor\.prototype", re.I),
    "exposure": re.compile(r"\.env|\.git/|actuator|swagger|openapi|\.js\.map|/debug", re.I),
    "llm": re.compile(r"ignore (previous|above)|system prompt|prompt inject", re.I),
    "onchain": re.compile(r"cast call|forge |eth_call|reentran|foundry|extrinsic", re.I),
}
PROBE_NAME_RX = re.compile(r"send_http|mcp__burp", re.I)
PROBE_CMD_RX = re.compile(r"\b(curl|nuclei|ffuf|wfuzz|httpx|katana|subfinder|gau|sqlmap|ghauri|websocat|wscat|nikto|amass|dalfox|frida|curl_cffi|playwright|dig|nslookup|cast)\b", re.I)
HOST_RX = re.compile(r"https?://([a-z0-9.-]+)", re.I)
SURRENDER_RX = re.compile(r"no findings|exhausted|tried everything|dead[- ]end|fully hardened|receipt-dead|nothing (more|else|actionable)|hit a wall", re.I)
TARGET_RX = re.compile(r"targets/([a-z0-9_.-]+)/", re.I)


def iter_events(fp):
    with open(fp, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def analyze(fp):
    m = {"agents": collections.Counter(), "hunter_classes": set(), "probe_classes": set(),
         "hosts": set(), "probes": 0, "drafts": 0, "surrenders": 0, "tool_turns": 0,
         "targets": collections.Counter(), "kb": round(os.path.getsize(fp) / 1024)}
    for ev in iter_events(fp):
        if ev.get("type") == "attachment":
            continue  # injected memory/hook context - not our action
        msg = ev.get("message") or {}
        content = msg.get("content")
        if not isinstance(content, list):
            continue
        for c in content:
            if not isinstance(c, dict):
                continue
            t = c.get("type")
            if t == "tool_use":
                name = c.get("name", "")
                inp = c.get("input", {}) or {}
                inp_s = json.dumps(inp)[:6000]
                m["tool_turns"] += 1
                if name in ("Agent", "Task"):
                    st = inp.get("subagent_type") or "?"
                    m["agents"][st] += 1
                    fam = agent_family(st)
                    if fam:
                        m["hunter_classes"].add(fam)
                cmd = inp.get("command", "") if isinstance(inp, dict) else ""
                is_probe = bool(PROBE_NAME_RX.search(name)) or bool(PROBE_CMD_RX.search(cmd))
                if is_probe:
                    m["probes"] += 1
                    for k, rx in CLASS_RX.items():
                        if rx.search(inp_s):
                            m["probe_classes"].add(k)
                    for h in HOST_RX.findall(cmd + " " + inp_s):
                        m["hosts"].add(h.lower())
                for tg in TARGET_RX.findall(inp_s):
                    m["targets"][tg.lower()] += 1
                if "reports/drafts/" in inp_s:
                    m["drafts"] += 1
            elif t == "text":
                blob = c.get("text") or ""
                if SURRENDER_RX.search(blob):
                    m["surrenders"] += 1
                for tg in TARGET_RX.findall(blob):
                    m["targets"][tg.lower()] += 1
    return m


files = sorted(glob.glob(f"{PROJ}/*.jsonl"), key=os.path.getmtime, reverse=True)[:N]
rows = []
for fp in files:
    try:
        m = analyze(fp)
    except Exception as e:
        print(f"skip {fp}: {e}", file=sys.stderr); continue
    worked = sorted(m["hunter_classes"] | m["probe_classes"])
    rows.append({
        "session": os.path.basename(fp)[:8],
        "target": (m["targets"].most_common(1)[0][0] if m["targets"] else "?"),
        "classes_worked": worked, "n_classes_worked": len(worked),
        "hunter_classes": sorted(m["hunter_classes"]),
        "n_hosts": len(m["hosts"]),
        "agents": dict(m["agents"]), "n_agent_dispatch": sum(m["agents"].values()),
        "n_agent_kinds": len(m["agents"]),
        "probes": m["probes"], "drafts": m["drafts"], "surrenders": m["surrenders"],
        "tool_turns": m["tool_turns"], "kb": m["kb"],
    })
json.dump(rows, open(f"{OUTDIR}/session-metrics.json", "w"), indent=1)


def pct(n, d): return f"{(100*n//d) if d else 0}%"


# a HUNT session = it actually probed or dispatched a hunter (drop meta/infra sessions)
hunt = [r for r in rows if r["probes"] >= 3 or r["hunter_classes"]]
print(f"===== SESSION FORENSICS v2: last {len(rows)} sessions; {len(hunt)} are real hunts =====\n")

print("## '1 class per vector' - distinct vuln-classes ACTUALLY WORKED per hunt session")
print("   (from dispatched hunter agents + probe-command content only; injected memory excluded)")
ch = collections.Counter(r["n_classes_worked"] for r in hunt)
for k in sorted(ch):
    print(f"  {k:2d} classes: {ch[k]:3d} sessions  {'#'*ch[k]}")
if hunt:
    med = statistics.median(r["n_classes_worked"] for r in hunt)
    le1 = sum(1 for r in hunt if r["n_classes_worked"] <= 1)
    le2 = sum(1 for r in hunt if r["n_classes_worked"] <= 2)
    print(f"  median classes-worked/hunt: {med}")
    print(f"  hunts working <=1 class: {le1}/{len(hunt)} ({pct(le1,len(hunt))})")
    print(f"  hunts working <=2 classes: {le2}/{len(hunt)} ({pct(le2,len(hunt))})   <- confirms 'shallow per vector' if high\n")

print("## Depth vs breadth: probes and hosts per class worked")
if hunt:
    avg_probes = round(sum(r["probes"] for r in hunt) / len(hunt))
    avg_hosts = round(sum(r["n_hosts"] for r in hunt) / len(hunt))
    avg_cls = round(sum(r["n_classes_worked"] for r in hunt) / len(hunt), 1)
    print(f"  avg probes/hunt={avg_probes}  avg hosts/hunt={avg_hosts}  avg classes/hunt={avg_cls}")
    print(f"  => ~{round(avg_probes/max(avg_cls,1))} probes per class (deep on few classes if high)\n")

print("## Agent usage (fleet leverage vs hands-on)")
disp = collections.Counter()
for r in rows:
    for a, n in r["agents"].items():
        disp[a] += n
hands_on = sum(1 for r in hunt if r["n_agent_dispatch"] == 0)
print(f"  hunts with ZERO agent dispatch (orchestrator hunts hands-on): {hands_on}/{len(hunt)} ({pct(hands_on,len(hunt))})")
print(f"  distinct agent kinds ever dispatched: {len(disp)}")
print("  top agents: " + ", ".join(f"{a}={n}" for a, n in disp.most_common(14)))
hunters = {a: n for a, n in disp.items() if agent_family(a)}
print(f"  distinct HUNTER classes dispatched fleet-wide: {len(set(agent_family(a) for a in hunters))}")

print("\n## Class coverage worked across ALL hunts (what we hunt vs neglect)")
allc = collections.Counter()
for r in hunt:
    for c in r["classes_worked"]:
        allc[c] += 1
for c, n in allc.most_common():
    print(f"  {n:3d}  {c}")
missed = [c for c in CLASS_RX if c not in allc]
if missed:
    print("  NEVER worked: " + ", ".join(missed))

print("\n## Outcome + concentration")
print(f"  hunts that drafted: {sum(1 for r in hunt if r['drafts']>0)}/{len(hunt)}")
print(f"  hunts with a surrender phrase: {sum(1 for r in hunt if r['surrenders']>0)}/{len(hunt)}")
tc = collections.Counter(r["target"] for r in rows if r["target"] != "?")
print("  top targets (sessions): " + ", ".join(f"{t}={n}" for t, n in tc.most_common(8)))
print(f"\nwrote {OUTDIR}/session-metrics.json")
