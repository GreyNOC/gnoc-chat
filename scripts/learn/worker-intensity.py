#!/usr/bin/env python3
"""
worker-intensity.py - Forensic measure of how empirically INTENSE bug-bounty sub-agent
workers actually are. Streams every */subagents/agent-*.jsonl (one file = one dispatched
worker) and computes per-worker probe intensity, dead/found markers, and cascade depth.

Lazy: streams line-by-line, never loads a full file into memory, prints only aggregates.
"""
import json, os, re, glob, statistics, sys

ROOT = "~/.claude/projects/-home-you-gnoc-workspace"
OUT = os.path.join(os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "scripts/learn/out/WORKER-INTENSITY.md")

# ---- live-probe classification ----
# Burp / intruder / WebFetch are direct probe tools.
RE_BURP = re.compile(r"send_http[12]_request|send_to_intruder", re.I)
# Bash commands that fire real network requests.
RE_BASH_PROBE = re.compile(
    r"\bcurl\b|\bwget\b|\bnc\b|\bhttpx\b|\bnuclei\b|\bffuf\b|\bgobuster\b|\bkatana\b|"
    r"\bsubfinder\b|\bamass\b|\bdnsx\b|curl_cffi|requests\.(get|post|put|delete|patch|request|Session)|"
    r"urllib|http\.client|socket\.(socket|create_connection)|aiohttp|httplib|\bwfuzz\b|\bmasscan\b|\bnmap\b",
    re.I,
)
# High-volume markers: a single Bash tool_use that fires MANY real requests.
RE_HIGHVOL = re.compile(
    r"\bfor\b\s.*\b(curl|wget|python|httpx|requests|nc)\b|"           # for-loop over a probe
    r"\bwhile\b\s.*\b(curl|wget|python|requests|nc)\b|"               # while-loop
    r"\bseq\b|"                                                       # seq generation (typ. loop)
    r"xargs\s+-\w*P|xargs\s.*-P|"                                     # parallel xargs
    r"\bnuclei\b|\bffuf\b|\bgobuster\b|\bmasscan\b|\bkatana\b|\bwfuzz\b|"  # native fuzzers
    r"send_to_intruder|"                                             # burp intruder = many
    r"ThreadPool|ProcessPool|concurrent\.futures|threading\.Thread|asyncio\.gather|multiprocessing|"  # py concurrency
    r"range\(\s*\d{2,}|"                                             # python range(NN..)
    r"-P\s*\d+|--threads|-c\s*\d{2,}",                               # thread/conc flags
    re.I,
)

# ---- dead / found VERDICT markers ----
# These are applied to the worker's FINAL assistant text block (the verdict), NOT to every
# line: the any-line version matched ~94/97% of workers (the words "confirmed"/"dead" appear
# incidentally everywhere) and was useless. The last-block regex gives a realistic split.
RE_DEAD = re.compile(
    r"receipt-dead|receipt.dead|dead-with-control|no findings|no finding\b|exhausted|"
    r"no.{0,3}(bug|vuln|vulnerabilit|finding)|not vulnerable|"
    r"could not (find|confirm|reproduce|exploit)|unable to (find|confirm|reproduce|exploit)|"
    r"\bDEAD\b|dead[- ]with|not exploitable|no (impact|vulnerability|exploit|cross|leak)|"
    r"declared? dead|is dead\b|receipt.?dead|\bceiling\b|VERDICT.{0,20}(dead|negative|no)",
    re.I,
)
# strict found: only real terminal / confirmed-vuln language, not the bare word "confirmed"/"candidate".
RE_FOUND = re.compile(
    r"\bCONFIRMED\b|terminal (captured|receipt|action)|finding-candidate|FOUND-CANDIDATE|"
    r"candidate finding|\bVULNERABLE\b|IDOR confirmed|BOLA confirmed|leak confirmed|"
    r"exploit confirmed|cross-tenant .{0,25}(confirm|captur|proven)|"
    r"cross-user .{0,25}(confirm|captur|proven)|proof captured|"
    r"successfully (read|wrote|exfil|accessed|leaked)|"
    r"200 OK.{0,40}(another user|other user|cross|leak)",
    re.I,
)

# ---- worker TYPE tagging (best-effort, scan first ~4 events' text) ----
# Order matters: more specific first. Returns a bucket string.
TYPE_PATTERNS = [
    ("report", re.compile(r"report[- ]?(writer|killer)|write a .{0,30}report|editing .{0,10}(one )?.{0,10}draft|report draft|draft report", re.I)),
    ("reviewer", re.compile(r"reviewer|adversarial (review|kill)|13[- ]?gate|report-killer|devil'?s advocate|try to kill", re.I)),
    ("triage-validator", re.compile(r"triage[- ]?validat|\bvalidator\b|triage-validator|re-?run every .{0,10}claim|independent repro", re.I)),
    ("dedup", re.compile(r"dedup|duplicate check|prior-art|saturation|hacktivity|already (submitted|reported)", re.I)),
    ("target-model", re.compile(r"target[- ]?model|model the target|trust boundar|actors.{0,10}roles|catastroph", re.I)),
    ("hypothesis", re.compile(r"hypothes|ranked .{0,15}hypothes|generate .{0,15}hypothes", re.I)),
    ("cvss-scorer", re.compile(r"cvss|severity scor|score this finding", re.I)),
    ("recon-scout", re.compile(r"recon|subdomain|enumerat|subfinder|amass|asset discovery|dns|attack surface map|js.?recon|bundle", re.I)),
    ("onchain-hunter", re.compile(r"onchain|on-chain|fork|foundry|smart contract|solidity|evm|precompile|cosmos|substrate|cairo|starknet|algorand|immunefi|reentran|defi", re.I)),
    ("oauth-hunter", re.compile(r"oauth|oidc|redirect_uri|saml|jwt|sso|token confusion|pkce|account[- ]?link", re.I)),
    ("idor-hunter", re.compile(r"\bidor\b|\bbola\b|\bbfla\b|cross[- ]?tenant|cross[- ]?user|owner[- ]?key|object.reference", re.I)),
    ("ssrf-hunter", re.compile(r"\bssrf\b|server-side request|imds|metadata endpoint|blind oob|collaborator", re.I)),
    ("xss-hunter", re.compile(r"\bxss\b|cross-site scripting|dom.?xss|stored xss|reflected|\{@html|sanitiz", re.I)),
    ("race-hunter", re.compile(r"\brace\b|race condition|concurren|toctou|burst|single-use", re.I)),
    ("graphql-hunter", re.compile(r"graphql|\.gql|introspection|persisted quer|alias batch", re.I)),
    ("llm-hunter", re.compile(r"\bllm\b|prompt injection|rag\b|\bmcp\b|jailbreak|ai agent|excessive agency", re.I)),
    ("browser-hunter", re.compile(r"headless|playwright|puppeteer|browser|postmessage|cswsh|in-page fetch", re.I)),
    ("unauth-hunter", re.compile(r"unauth|pre-auth|zero[- ]?credential|exposure|actuator|\.env\b|swagger|open bucket", re.I)),
    ("takeover-hunter", re.compile(r"takeover|dangling|cname|nxdomain|claim the (bucket|resource|app)", re.I)),
    ("hunter-generic", re.compile(r"\bhunt\b|exploit|probe|vector|escalat|chain|attack|bypass|leak|find a bug|primitive", re.I)),
]
HUNTER_TYPES = {
    "onchain-hunter","oauth-hunter","idor-hunter","ssrf-hunter","xss-hunter","race-hunter",
    "graphql-hunter","llm-hunter","browser-hunter","unauth-hunter","takeover-hunter","hunter-generic",
}
NON_HUNTER_TYPES = {
    "report","reviewer","triage-validator","dedup","target-model","hypothesis",
    "cvss-scorer","recon-scout",
}

def classify_type(head_text):
    for name, pat in TYPE_PATTERNS:
        if pat.search(head_text):
            return name
    return "unknown"

def iter_content_items(o):
    """Yield (kind, payload): ('text', str) or ('tool', (name, input_dict))."""
    msg = o.get("message", {})
    if not isinstance(msg, dict):
        return
    c = msg.get("content")
    if isinstance(c, str):
        yield ("text", c)
    elif isinstance(c, list):
        for it in c:
            if not isinstance(it, dict):
                continue
            t = it.get("type")
            if t == "text":
                yield ("text", it.get("text", "") or "")
            elif t == "tool_use":
                yield ("tool", (it.get("name", ""), it.get("input", {}) or {}))

def analyze_file(path):
    r = {
        "n_probe_tooluses": 0, "n_highvol": 0, "n_burp": 0, "n_curl": 0,
        "est_real_requests": 0,
        "sum_output_tokens": 0, "n_tool_turns": 0,
        "dead": False, "found": False,
        "n_probes_after_first_found": 0, "type": "unknown",
        "first_found_seen": False,
    }
    head_text = []
    last_asst_text = ""   # the final substantive assistant text block = the verdict
    line_no = 0
    try:
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    o = json.loads(line)
                except Exception:
                    continue
                line_no += 1
                msg = o.get("message", {})
                role = msg.get("role") if isinstance(msg, dict) else None
                if isinstance(msg, dict):
                    usage = msg.get("usage", {})
                    if isinstance(usage, dict):
                        r["sum_output_tokens"] += usage.get("output_tokens", 0) or 0
                for kind, payload in iter_content_items(o):
                    if kind == "text":
                        txt = payload
                        if line_no <= 4:
                            head_text.append(txt)
                        # track final assistant verdict block (overwrite -> ends at last)
                        if role == "assistant" and txt.strip():
                            last_asst_text = txt
                        # cascade: the FIRST strict-found occurrence anywhere marks the pivot
                        if not r["first_found_seen"] and RE_FOUND.search(txt):
                            r["first_found_seen"] = True
                    else:  # tool
                        name, inp = payload
                        r["n_tool_turns"] += 1
                        is_probe = False
                        is_highvol = False
                        est = 0
                        if RE_BURP.search(name) or name == "WebFetch":
                            is_probe = True
                            if RE_BURP.search(name):
                                r["n_burp"] += 1
                            if "send_to_intruder" in name:
                                is_highvol = True
                                est = 50   # an intruder run = many requests (floor)
                            else:
                                est = 1
                        elif name == "Bash":
                            cmd = inp.get("command", "") or ""
                            if RE_BASH_PROBE.search(cmd):
                                is_probe = True
                                r["n_curl"] += 1
                                if RE_HIGHVOL.search(cmd):
                                    is_highvol = True
                                est = est_requests_in_cmd(cmd, is_highvol)
                        if is_probe:
                            r["n_probe_tooluses"] += 1
                            r["est_real_requests"] += est
                            if is_highvol:
                                r["n_highvol"] += 1
                            if r["first_found_seen"]:
                                r["n_probes_after_first_found"] += 1
    except Exception as e:
        r["error"] = str(e)
    # VERDICT decided on the last assistant block only (tail 1800 chars).
    tail = last_asst_text[-1800:]
    r["dead"] = bool(RE_DEAD.search(tail))
    r["found"] = bool(RE_FOUND.search(tail))
    r["type"] = classify_type("\n".join(head_text)[:4000])
    return r

# count of literal request-firing tokens inside one Bash command (a floor on real requests).
RE_REQ_TOKEN = re.compile(r"\bcurl\b|\bwget\b|requests\.(get|post|put|delete|patch|request)|"
                          r"\bhttpx\b|urlopen|session\.(get|post|request)", re.I)
def est_requests_in_cmd(cmd, is_highvol):
    """Lower-bound estimate of real requests a single Bash tool_use fires.
    Non-burst -> count literal request tokens (>=1). Burst -> multiply by a conservative
    loop factor read from seq/range/-P/-c/-n numbers, else a floor of 10."""
    tokens = len(RE_REQ_TOKEN.findall(cmd)) or 1
    if not is_highvol:
        return tokens
    factor = 0
    for m in re.finditer(r"seq\s+(\d+)\s+(\d+)|range\(\s*(\d+)|-[PncN]\s*(\d+)|--threads\s*(\d+)", cmd, re.I):
        for g in m.groups():
            if g and g.isdigit():
                factor = max(factor, int(g))
    if factor <= 1:
        factor = 10           # conservative floor for an unquantified loop/fuzz/burst
    factor = min(factor, 500)  # cap runaway estimates
    return tokens * factor

def pct(part, whole):
    return (100.0 * part / whole) if whole else 0.0

def dist(vals):
    """Return dict of distribution stats for a list of ints."""
    if not vals:
        return {"n":0,"median":0,"p50":0,"p75":0,"p90":0,"max":0,"mean":0}
    s = sorted(vals)
    n = len(s)
    def q(pp):
        idx = min(n-1, int(round(pp*(n-1))))
        return s[idx]
    return {
        "n": n, "median": statistics.median(s), "p50": q(0.50),
        "p75": q(0.75), "p90": q(0.90), "max": s[-1],
        "mean": round(sum(s)/n, 2),
    }

def bucket_probes(vals):
    b = {"0":0,"1-2":0,"3-5":0,"6-20":0,"21+":0}
    for v in vals:
        if v == 0: b["0"] += 1
        elif v <= 2: b["1-2"] += 1
        elif v <= 5: b["3-5"] += 1
        elif v <= 20: b["6-20"] += 1
        else: b["21+"] += 1
    return b

def main():
    files = sorted(glob.glob(os.path.join(ROOT, "*", "subagents", "agent-*.jsonl")))
    n_files = len(files)
    print(f"[worker-intensity] scanning {n_files} worker files ...", file=sys.stderr)

    workers = []
    for i, f in enumerate(files):
        workers.append(analyze_file(f))
        if (i+1) % 500 == 0:
            print(f"  ... {i+1}/{n_files}", file=sys.stderr)

    N = len(workers)
    all_probes = [w["n_probe_tooluses"] for w in workers]
    tot_probe = sum(all_probes)
    tot_est_req = sum(w["est_real_requests"] for w in workers)
    tot_highvol = sum(w["n_highvol"] for w in workers)
    tot_burp = sum(w["n_burp"] for w in workers)
    tot_curl = sum(w["n_curl"] for w in workers)
    tot_out = sum(w["sum_output_tokens"] for w in workers)

    # A. TOTALS
    A = {
        "n_workers": N,
        "total_probe_tooluses": tot_probe,
        "total_highvol_probes": tot_highvol,
        "total_output_tokens": tot_out,
        "out_tokens_per_probe": round(tot_out / tot_probe, 1) if tot_probe else 0,
        "est_real_requests": tot_est_req,
        "out_tokens_per_real_request": round(tot_out / tot_est_req, 1) if tot_est_req else 0,
        "total_burp_probes": tot_burp,
        "total_curl_probes": tot_curl,
    }

    # B. probe distribution (all workers)
    B_dist = dist(all_probes)
    B_bucket = bucket_probes(all_probes)

    # C. dead-marker workers
    dead_workers = [w for w in workers if w["dead"]]
    dead_probes = [w["n_probe_tooluses"] for w in dead_workers]
    C_dist = dist(dead_probes)
    C_bucket = bucket_probes(dead_probes)
    C_le2 = sum(1 for v in dead_probes if v <= 2)
    C_0 = sum(1 for v in dead_probes if v == 0)

    # D. hunter-only
    hunters = [w for w in workers if w["type"] in HUNTER_TYPES]
    h_probes = [w["n_probe_tooluses"] for w in hunters]
    h_out = sum(w["sum_output_tokens"] for w in hunters)
    h_tot_probe = sum(h_probes)
    D_dist = dist(h_probes)
    D_bucket = bucket_probes(h_probes)
    h_dead = [w for w in hunters if w["dead"]]
    h_dead_probes = [w["n_probe_tooluses"] for w in h_dead]
    D_dead_dist = dist(h_dead_probes)
    D_dead_le2 = sum(1 for v in h_dead_probes if v <= 2)
    D_dead_0 = sum(1 for v in h_dead_probes if v == 0)
    D_out_per_probe = round(h_out / h_tot_probe, 1) if h_tot_probe else 0

    # E. cascade among found-marker workers
    found_workers = [w for w in workers if w["found"]]
    cascade = [w["n_probes_after_first_found"] for w in found_workers]
    E_dist = dist(cascade)
    E_bucket = bucket_probes(cascade)
    E_zero = sum(1 for v in cascade if v == 0)
    E_ge3 = sum(1 for v in cascade if v >= 3)

    # F. burp vs curl share
    F_total = tot_burp + tot_curl

    # ----- type census (for transparency) -----
    from collections import Counter
    type_census = Counter(w["type"] for w in workers)

    # ---------- render ----------
    L = []
    def p(s=""):
        L.append(s)

    p("# WORKER INTENSITY - empirical probe-intensity of bug-bounty sub-agents")
    p("")
    p(f"Streamed {N} worker transcripts (`*/subagents/agent-*.jsonl`).")
    p("Assumption: one file = one dispatched worker; a probe tool_use = Burp send_http[12]/intruder, WebFetch, "
      "or a Bash cmd containing curl/wget/nc/httpx/nuclei/ffuf/gobuster/katana/subfinder/amass/python-requests/socket. "
      "HIGH-VOLUME = that tool_use fires many real requests (for/while/seq/xargs-P/nuclei/ffuf/ThreadPool/range(NN)/intruder). "
      "DEAD/FOUND verdict = regex on the worker's FINAL assistant text block only (an any-line match hit ~94/97% "
      "of workers on incidental words and was discarded); they are NOT mutually exclusive (a worker can end "
      "'confirmed X but no impact'). Cascade counts probes after the first strict-found token appears mid-stream. "
      "Markers are a noisy proxy, not ground truth.")
    p("")

    p("## A. TOTALS (reasoning:testing ratio)")
    p("")
    p("| metric | value |")
    p("|---|---|")
    p(f"| workers | {A['n_workers']:,} |")
    p(f"| total probe tool_uses | {A['total_probe_tooluses']:,} |")
    p(f"| total HIGH-VOLUME probe tool_uses (loop/fuzz/burst) | {A['total_highvol_probes']:,} |")
    p(f"| est. REAL requests fired (loop/burst-expanded, conservative floor) | {A['est_real_requests']:,} |")
    p(f"| total output tokens (all workers) | {A['total_output_tokens']:,} |")
    p(f"| **output tokens / probe tool_use** | **{A['out_tokens_per_probe']:,}** |")
    p(f"| output tokens / est. REAL request | {A['out_tokens_per_real_request']:,} |")
    p(f"| probes via Burp MCP | {A['total_burp_probes']:,} |")
    p(f"| probes via curl/CLI (Bash) | {A['total_curl_probes']:,} |")
    p(f"| mean probe tool_uses / worker | {round(tot_probe/N,2)} |")
    p("")

    p("## B. PROBE DISTRIBUTION - all workers")
    p("")
    p("| stat | probe tool_uses |")
    p("|---|---|")
    p(f"| median | {B_dist['median']} |")
    p(f"| p50 | {B_dist['p50']} |")
    p(f"| p75 | {B_dist['p75']} |")
    p(f"| p90 | {B_dist['p90']} |")
    p(f"| max | {B_dist['max']} |")
    p(f"| mean | {B_dist['mean']} |")
    p("")
    p("| probes fired | % of workers | count |")
    p("|---|---|---|")
    for k in ["0","1-2","3-5","6-20","21+"]:
        p(f"| {k} | {pct(B_bucket[k],N):.1f}% | {B_bucket[k]:,} |")
    p("")

    p("## C. KEY TABLE - workers that DECLARED DEAD (no bug): probes fired BEFORE declaring")
    p("")
    p(f"dead-marker workers: {len(dead_workers):,} ({pct(len(dead_workers),N):.1f}% of all)")
    p("")
    p("| stat | probes before dead |")
    p("|---|---|")
    p(f"| median | {C_dist['median']} |")
    p(f"| p75 | {C_dist['p75']} |")
    p(f"| p90 | {C_dist['p90']} |")
    p(f"| max | {C_dist['max']} |")
    p(f"| mean | {C_dist['mean']} |")
    p("")
    p("| probes before declaring dead | % of dead workers | count |")
    p("|---|---|---|")
    for k in ["0","1-2","3-5","6-20","21+"]:
        p(f"| {k} | {pct(C_bucket[k],len(dead_workers)):.1f}% | {C_bucket[k]:,} |")
    p("")
    p(f"- declared dead after **<=2** probes: **{pct(C_le2,len(dead_workers)):.1f}%** ({C_le2:,})")
    p(f"- declared dead after **0** probes (pure reasoning): **{pct(C_0,len(dead_workers)):.1f}%** ({C_0:,})")
    p("")

    p("## D. HUNTER-ONLY - *-hunter/exploit workers (recon/scout/validator/reviewer/report/dedup/model/hyp excluded)")
    p("")
    p(f"hunter workers: {len(hunters):,} ({pct(len(hunters),N):.1f}% of all)")
    p("")
    p("| stat | probe tool_uses (hunters) |")
    p("|---|---|")
    p(f"| median | {D_dist['median']} |")
    p(f"| p75 | {D_dist['p75']} |")
    p(f"| p90 | {D_dist['p90']} |")
    p(f"| max | {D_dist['max']} |")
    p(f"| mean | {D_dist['mean']} |")
    p(f"| **output tokens / probe (hunters)** | **{D_out_per_probe:,}** |")
    p("")
    p("| probes fired (hunters) | % | count |")
    p("|---|---|---|")
    for k in ["0","1-2","3-5","6-20","21+"]:
        p(f"| {k} | {pct(D_bucket[k],len(hunters)):.1f}% | {D_bucket[k]:,} |")
    p("")
    p(f"hunter workers that declared DEAD: {len(h_dead):,}")
    p("")
    p("| stat | probes before dead (hunters) |")
    p("|---|---|")
    p(f"| median | {D_dead_dist['median']} |")
    p(f"| p90 | {D_dead_dist['p90']} |")
    p(f"| max | {D_dead_dist['max']} |")
    p("")
    p(f"- hunter declared dead after **<=2** probes: **{pct(D_dead_le2,len(h_dead)):.1f}%** ({D_dead_le2:,})")
    p(f"- hunter declared dead after **0** probes: **{pct(D_dead_0,len(h_dead)):.1f}%** ({D_dead_0:,})")
    p("")

    p("## E. CASCADE - among found-marker workers, probes fired AFTER first found (variant depth)")
    p("")
    p(f"found-marker workers: {len(found_workers):,} ({pct(len(found_workers),N):.1f}% of all)")
    p("")
    p("| stat | probes after first found |")
    p("|---|---|")
    p(f"| median | {E_dist['median']} |")
    p(f"| p75 | {E_dist['p75']} |")
    p(f"| p90 | {E_dist['p90']} |")
    p(f"| max | {E_dist['max']} |")
    p(f"| mean | {E_dist['mean']} |")
    p("")
    p("| probes after first found | % of found workers | count |")
    p("|---|---|---|")
    for k in ["0","1-2","3-5","6-20","21+"]:
        p(f"| {k} | {pct(E_bucket[k],len(found_workers)):.1f}% | {E_bucket[k]:,} |")
    p("")
    p(f"- stopped at first found (**0** cascade probes): **{pct(E_zero,len(found_workers)):.1f}%** ({E_zero:,})")
    p(f"- multiplied into **3+** variant probes: **{pct(E_ge3,len(found_workers)):.1f}%** ({E_ge3:,})")
    p("")

    p("## F. BURP vs CURL - probe channel share")
    p("")
    p("| channel | probes | share |")
    p("|---|---|---|")
    p(f"| Burp MCP (send_http/intruder) | {tot_burp:,} | {pct(tot_burp,F_total):.1f}% |")
    p(f"| curl / CLI (Bash) | {tot_curl:,} | {pct(tot_curl,F_total):.1f}% |")
    p("")

    p("## Worker TYPE census (best-effort keyword tagging)")
    p("")
    p("| type | workers |")
    p("|---|---|")
    for t, c in type_census.most_common():
        p(f"| {t} | {c:,} |")
    p("")

    text = "\n".join(L)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as fh:
        fh.write(text + "\n")

    # stdout: compact machine-parseable summary the caller reads
    print(text)
    print("\n[SAVED]", OUT, file=sys.stderr)

if __name__ == "__main__":
    main()
