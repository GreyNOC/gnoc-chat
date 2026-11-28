#!/usr/bin/env python3
"""
Forensic effort-vs-yield analysis over ALL Claude Code session transcripts of the
bug-bounty operation.

Streams every .jsonl line-by-line (never loads a whole transcript into memory) and
per session extracts token spend, sub-agent dispatches, network probes, draft writes,
dead/surrender markers, and best-guess target + platform. Then aggregates the tables
requested in the forensics brief and writes the report to out/FORENSIC-750.md.

Confirmed schema (grepped from the corpus, not assumed):
  - sub-agent dispatch tool name is "Agent" (the string "Task" never appears). Agent
    input carries subagent_type + model + prompt.
  - assistant token usage lives at message.usage.{output_tokens,input_tokens,
    cache_read_input_tokens,cache_creation_input_tokens}.
  - tool calls are content items with type=="tool_use" and a "name".
  - Bash input has "command"; Write/Edit/Read input has "file_path".
  - target names appear in tool-input paths (targets/<t>/, reports/drafts/<t>/, ...)
    and in the per-event "cwd" (e.g. .../targets/<t>).
  - assistant free text is content items with type=="text".

Assumptions (stated per brief):
  A1. session date = file mtime (per brief).
  A2. input_tokens per session = sum over assistant events of
      (input_tokens + cache_read_input_tokens + cache_creation_input_tokens), i.e.
      the full billed input footprint incl. cache, per the brief's "incl cache-read".
  A3. platform is taken from the workspace scope files (targets/<t>/PROGRAM.md or
      SCOPE.txt) when the guessed target has one; else inferred from marker text in
      the transcript; else "unknown". Scope-file mapping is authoritative because it
      is the program's own registration, not a passing mention.
  A4. best-guess target = the most frequent token seen in tool-input paths matching
      (targets|reports/drafts|reports/submitted|reports)/<token> across the session,
      with the per-event cwd token (.../targets/<t>) counted too and weighted, since
      cwd is a strong per-session lock signal. Ties fall back to "unknown".
  A5. a "probe" = a tool_use that touches a network endpoint: Bash whose command
      contains curl/wget/nc/ncat/openssl s_client/nmap/httpx/nuclei/dig/host/
      nslookup/ping/ffuf/gobuster, OR mcp__burp__send_http1/2_request, OR WebFetch,
      OR the built-in web fetch/search server tools. (nc matched as a token, not the
      substring 'nc' inside other words.)
  A6. a "draft write" = a Write or Edit tool_use whose file_path contains
      "reports/drafts/".
"""
import os, sys, json, re, glob, datetime, collections

PROJDIR = "~/.claude/projects/-home-you-gnoc-workspace"
TARGETSDIR = os.path.join(os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "targets")
OUTDIR = os.path.join(os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "scripts/learn/out")
OUTFILE = os.path.join(OUTDIR, "FORENSIC-750.md")

DEAD_MARKERS = ["receipt-dead", "exhausted", "surrender", "no findings",
                "parked-at-frontier", "dead-with-control"]

# Immunefi / smart-contract targets the brief names explicitly (union with any
# target whose resolved platform is Immunefi).
IMMUNEFI_NAMED = {"veda","ethena","morpho","kamino","zest","berachain","polygon",
                  "hydration","trufin","sei","orderlynetwork","dexe","balancer"}

# curl/nc-style network tokens for Bash probe detection. Matched on word boundaries.
NET_CMD_TOKENS = ["curl","wget","nc","ncat","socat","openssl","nmap","httpx","httprobe",
                  "nuclei","dig","host","nslookup","ping","ping6","ffuf","gobuster",
                  "feroxbuster","dirb","wfuzz","masscan","amass","subfinder","katana",
                  "hydra","whatweb","wpscan","sqlmap","testssl","s_client"]
NET_CMD_RE = re.compile(r'(?<![\w./-])(' + "|".join(NET_CMD_TOKENS) + r')(?![\w])')

PROBE_TOOLNAMES = {
    "WebFetch", "WebSearch",
    "mcp__burp__send_http1_request", "mcp__burp__send_http2_request",
    "mcp__caveman-shrink__send_http1_request", "mcp__caveman-shrink__send_http2_request",
    "mcp__burp__get_collaborator_interactions",
    "mcp__caveman-shrink__get_collaborator_interactions",
}

PATH_TOKEN_RE = re.compile(r'(?:targets|reports/drafts|reports/submitted|reports)/([A-Za-z0-9_.\-]+)')
CWD_TOKEN_RE  = re.compile(r'/targets/([A-Za-z0-9_.\-]+)')

# ---------------------------------------------------------------------------
# Build target -> platform map from the workspace scope files (read once, small).
# ---------------------------------------------------------------------------
# authoritative overrides for targets whose scope files omit a clean platform word.
# program-19: its own PROGRAM.md is headed "reconciled from H1 API" (H1, handle
# researcher, confirmed in workspace memory). just-eat: Bugcrowd (no keyword in scope file,
# resolved via text-fallback anyway, pinned here for stability).
PLATFORM_OVERRIDE = {
    "program-19": "H1",
    "just-eat": "Bugcrowd",
}

def build_platform_map():
    m = dict(PLATFORM_OVERRIDE)
    order = [("immunefi","Immunefi"),("yeswehack","YWH"),("hackenproof","HackenProof"),
             ("hackerone","H1"),("bugcrowd","Bugcrowd"),("intigriti","Intigriti")]
    tok_order = [(r'\bh1\b',"H1"), (r'\bywh\b',"YWH")]
    for d in glob.glob(os.path.join(TARGETSDIR, "*")):
        if not os.path.isdir(d):
            continue
        t = os.path.basename(d)
        if t in PLATFORM_OVERRIDE:
            continue
        blob = ""
        for fn in ("PROGRAM.md", "SCOPE.txt"):
            p = os.path.join(d, fn)
            if os.path.exists(p):
                try:
                    with open(p, errors="replace") as fh:
                        blob += fh.read(8000).lower()
                except OSError:
                    pass
        plat = None
        # priority order: immunefi wins first (SC targets), then paid web platforms.
        for key, label in order:
            if key in blob:
                plat = label
                break
        if plat is None:
            for rx, label in tok_order:
                if re.search(rx, blob):
                    plat = label
                    break
        if plat:
            m[t] = plat
    return m

# tokens that are workspace nouns, never program handles.
BAD_TOKENS = {"drafts","submitted","INBOX","INBOX.md","README","README.md",
              "templates","template","_index","index","index.md","common",
              "shared","tmp","test","example"}

def guess_platform_from_text(text_markers):
    # text_markers: lowercased concatenation of a bounded sample of assistant text.
    for key, label in (("immunefi","Immunefi"),("yeswehack","YWH"),("hackenproof","HackenProof"),
                       ("hackerone","H1"),("bugcrowd","Bugcrowd"),("intigriti","Intigriti")):
        if key in text_markers:
            return label
    if re.search(r'\bh1\b', text_markers):
        return "H1"
    if re.search(r'\bywh\b', text_markers):
        return "YWH"
    return "unknown"

def process_file(path, platmap):
    st = os.stat(path)
    date = datetime.date.fromtimestamp(st.st_mtime)
    sid = os.path.basename(path)[:-6]  # strip .jsonl

    out_tok = in_tok = 0
    n_dispatch = 0
    agent_hist = collections.Counter()
    n_probes = 0
    n_draft_writes = 0
    draft_targets = collections.Counter()
    n_dead = 0
    tgt_counter = collections.Counter()
    text_sample = []          # bounded, for platform text fallback only
    text_sample_len = 0

    with open(path, errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue

            cwd = d.get("cwd")
            if cwd:
                mm = CWD_TOKEN_RE.search(cwd)
                if mm:
                    tok = mm.group(1)
                    if tok not in BAD_TOKENS:
                        tgt_counter[tok] += 2   # cwd is a strong per-session signal

            if d.get("type") != "assistant":
                continue
            msg = d.get("message", {}) or {}
            u = msg.get("usage", {}) or {}
            if u:
                out_tok += int(u.get("output_tokens", 0) or 0)
                in_tok += (int(u.get("input_tokens", 0) or 0)
                           + int(u.get("cache_read_input_tokens", 0) or 0)
                           + int(u.get("cache_creation_input_tokens", 0) or 0))

            for c in (msg.get("content") or []):
                if not isinstance(c, dict):
                    continue
                ctype = c.get("type")
                if ctype == "text":
                    txt = c.get("text", "") or ""
                    low = txt.lower()
                    for mk in DEAD_MARKERS:
                        n_dead += low.count(mk)
                    if text_sample_len < 20000:
                        text_sample.append(low)
                        text_sample_len += len(low)
                    continue
                if ctype != "tool_use":
                    continue

                name = c.get("name")
                inp = c.get("input", {}) or {}

                # dispatch
                if name == "Agent":
                    n_dispatch += 1
                    stype = inp.get("subagent_type") or "unknown-agent"
                    agent_hist[stype] += 1

                # probes
                is_probe = False
                if name in PROBE_TOOLNAMES:
                    is_probe = True
                elif name == "Bash":
                    cmd = inp.get("command", "") or ""
                    if NET_CMD_RE.search(cmd):
                        is_probe = True
                if is_probe:
                    n_probes += 1

                # target-path tokens from any string field
                for v in inp.values():
                    if isinstance(v, str) and v:
                        for tok in PATH_TOKEN_RE.findall(v):
                            if tok not in BAD_TOKENS:
                                tgt_counter[tok] += 1

                # draft writes
                if name in ("Write", "Edit"):
                    fp = inp.get("file_path", "") or ""
                    if "reports/drafts/" in fp:
                        n_draft_writes += 1
                        dm = re.search(r'reports/drafts/([A-Za-z0-9_.\-]+)', fp)
                        if dm:
                            draft_targets[dm.group(1)] += 1

    # resolve target
    if tgt_counter:
        target = tgt_counter.most_common(1)[0][0]
    else:
        target = "unknown"

    # resolve platform: scope-file map first, else text fallback
    platform = platmap.get(target)
    if not platform:
        platform = guess_platform_from_text(" ".join(text_sample))
    if not platform:
        platform = "unknown"

    return {
        "session_id": sid,
        "date": date,
        "out_tok": out_tok,
        "in_tok": in_tok,
        "n_dispatch": n_dispatch,
        "agent_hist": agent_hist,
        "n_probes": n_probes,
        "n_draft_writes": n_draft_writes,
        "draft_targets": draft_targets,
        "n_dead": n_dead,
        "target": target,
        "platform": platform,
        "has_draft": n_draft_writes > 0,
    }

def fmt(n):
    return f"{n:,}"

def pct(a, b):
    return f"{(100.0*a/b):.1f}%" if b else "n/a"

def main():
    os.makedirs(OUTDIR, exist_ok=True)
    platmap = build_platform_map()
    files = sorted(glob.glob(os.path.join(PROJDIR, "*.jsonl")))
    sessions = []
    for i, f in enumerate(files, 1):
        try:
            sessions.append(process_file(f, platmap))
        except Exception as e:
            sys.stderr.write(f"[warn] {f}: {e}\n")
        if i % 100 == 0:
            sys.stderr.write(f"  processed {i}/{len(files)}\n")

    # ---- aggregate ----
    n_sessions = len(sessions)
    dates = [s["date"] for s in sessions]
    dmin, dmax = min(dates), max(dates)
    tot_out = sum(s["out_tok"] for s in sessions)
    tot_in = sum(s["in_tok"] for s in sessions)
    tot_disp = sum(s["n_dispatch"] for s in sessions)
    tot_probe = sum(s["n_probes"] for s in sessions)
    tot_draftw = sum(s["n_draft_writes"] for s in sessions)
    n_draft_sess = sum(1 for s in sessions if s["has_draft"])
    n_dead_no_draft = sum(1 for s in sessions if s["n_dead"] > 0 and not s["has_draft"])

    # per-target rollup
    T = collections.defaultdict(lambda: {"sessions":0,"out":0,"in":0,"disp":0,
                                         "probe":0,"draftw":0,"draft_sess":0,
                                         "platform":collections.Counter()})
    for s in sessions:
        t = s["target"]; r = T[t]
        r["sessions"] += 1
        r["out"] += s["out_tok"]; r["in"] += s["in_tok"]
        r["disp"] += s["n_dispatch"]; r["probe"] += s["n_probes"]
        r["draftw"] += s["n_draft_writes"]
        r["draft_sess"] += 1 if s["has_draft"] else 0
        r["platform"][s["platform"]] += 1
    for t, r in T.items():
        r["platform_top"] = r["platform"].most_common(1)[0][0] if r["platform"] else "unknown"

    def target_platform(t):
        return T[t]["platform_top"]

    # global agent histogram
    global_agents = collections.Counter()
    for s in sessions:
        global_agents.update(s["agent_hist"])

    # concentration
    by_out = sorted(T.items(), key=lambda kv: -kv[1]["out"])
    top5 = sum(r["out"] for _, r in by_out[:5])
    top10 = sum(r["out"] for _, r in by_out[:10])
    pal_out = sum(r["out"] for t, r in T.items() if t.startswith("massive"))
    pp_out  = sum(r["out"] for t, r in T.items() if t == "umbrella")

    # Immunefi combined: named set OR resolved platform == Immunefi
    imm_targets = set(t for t in T if target_platform(t) == "Immunefi") | (set(T) & IMMUNEFI_NAMED)
    imm_out = sum(T[t]["out"] for t in imm_targets)
    imm_sess = sum(T[t]["sessions"] for t in imm_targets)
    imm_draftsess = sum(T[t]["draft_sess"] for t in imm_targets)

    # platform split
    P = collections.defaultdict(lambda: {"sessions":0,"out":0,"draft_sess":0})
    for s in sessions:
        p = s["platform"]; P[p]["sessions"] += 1; P[p]["out"] += s["out_tok"]
        P[p]["draft_sess"] += 1 if s["has_draft"] else 0

    # weekly trend (ISO week)
    W = collections.defaultdict(lambda: {"sessions":0,"out":0,"draft_sess":0,"disp":0})
    for s in sessions:
        iy, iw, _ = s["date"].isocalendar()
        key = f"{iy}-W{iw:02d}"
        W[key]["sessions"] += 1; W[key]["out"] += s["out_tok"]
        W[key]["draft_sess"] += 1 if s["has_draft"] else 0
        W[key]["disp"] += s["n_dispatch"]

    # ---- render ----
    L = []
    P_ = L.append
    P_("# FORENSIC-750 - effort-vs-yield over all bug-bounty session transcripts\n")
    P_(f"generated {datetime.datetime.now().isoformat(timespec='seconds')}  |  source {PROJDIR}\n")
    P_("Assumptions: session date = file mtime; input_tokens = sum(input + cache_read + cache_creation) over assistant events; "
       "platform from workspace scope files (PROGRAM.md/SCOPE.txt) with text fallback; target = most-frequent path/cwd token; "
       "probe = network-touching Bash (curl/nc/...) + burp send_http + WebFetch/WebSearch; draft = Write/Edit into reports/drafts/.\n")

    P_("\n## A. TOTALS")
    P_(f"n_sessions          : {fmt(n_sessions)}")
    P_(f"date range          : {dmin} .. {dmax}")
    P_(f"total output_tokens : {fmt(tot_out)}")
    P_(f"total input_tokens  : {fmt(tot_in)}   (incl cache-read + cache-creation)")
    P_(f"total Agent (Task) dispatches : {fmt(tot_disp)}")
    P_(f"total probes        : {fmt(tot_probe)}")
    P_(f"total draft-writes  : {fmt(tot_draftw)}   (sessions with >=1 draft: {fmt(n_draft_sess)})")
    P_(f"top dispatched agents: " + ", ".join(f"{a}={c}" for a,c in global_agents.most_common(12)))

    def target_table(rows, title):
        P_(f"\n## {title}")
        P_(f"{'target':<26}{'sess':>5}{'out_tok':>13}{'disp':>7}{'probe':>7}{'draftS':>7}  platform")
        for t, r in rows:
            P_(f"{t[:25]:<26}{r['sessions']:>5}{fmt(r['out']):>13}{r['disp']:>7}"
               f"{r['probe']:>7}{r['draft_sess']:>7}  {r['platform_top']}")

    by_sess = sorted(T.items(), key=lambda kv: (-kv[1]["sessions"], -kv[1]["out"]))
    target_table(by_sess[:20], "B. TOP 20 TARGETS by session-count")
    target_table(by_out[:20], "C. TOP 20 TARGETS by output_tokens")

    P_("\n## D. CONCENTRATION (share of ALL output_tokens)")
    P_(f"top-5 targets   : {pct(top5, tot_out)}  ({fmt(top5)})")
    P_(f"top-10 targets  : {pct(top10, tot_out)}  ({fmt(top10)})")
    P_(f"massive*       : {pct(pal_out, tot_out)}  ({fmt(pal_out)})")
    P_(f"umbrella          : {pct(pp_out, tot_out)}  ({fmt(pp_out)})")
    P_(f"Immunefi/SC all : {pct(imm_out, tot_out)}  ({fmt(imm_out)})  "
       f"[{len(imm_targets)} targets, {imm_sess} sessions, {imm_draftsess} draft-sessions]")

    P_("\n## E. YIELD RATIOS (global)")
    dp = (tot_disp/tot_probe) if tot_probe else 0
    dw = (tot_disp/tot_draftw) if tot_draftw else float('inf')
    P_(f"dispatches / probes            : {dp:.2f}   ({fmt(tot_disp)} / {fmt(tot_probe)})")
    P_(f"dispatches / draft-writes      : {('%.1f'%dw) if tot_draftw else 'inf'}   ({fmt(tot_disp)} / {fmt(tot_draftw)})")
    P_(f"%% sessions with >=1 draft-write: {pct(n_draft_sess, n_sessions)}   ({fmt(n_draft_sess)}/{fmt(n_sessions)})")
    P_(f"%% sessions dead-marker & 0 draft: {pct(n_dead_no_draft, n_sessions)}   ({fmt(n_dead_no_draft)}/{fmt(n_sessions)})")
    P_(f"mean dispatches / session      : {tot_disp/n_sessions:.2f}")
    P_(f"mean probes / session          : {tot_probe/n_sessions:.2f}")

    P_("\n## F. WEEKLY TREND")
    P_(f"{'iso_week':<10}{'sess':>5}{'out_tok':>14}{'draftS':>8}{'disp':>7}{'out/draftS':>13}")
    for k in sorted(W):
        w = W[k]
        opd = (w["out"]/w["draft_sess"]) if w["draft_sess"] else 0
        opd_s = fmt(int(opd)) if w["draft_sess"] else "0-draft"
        P_(f"{k:<10}{w['sessions']:>5}{fmt(w['out']):>14}{w['draft_sess']:>8}{w['disp']:>7}{opd_s:>13}")

    P_("\n## G. PLATFORM SPLIT")
    P_(f"{'platform':<12}{'sess':>6}{'out_tok':>14}{'out_share':>11}{'draftS':>8}")
    for p, r in sorted(P.items(), key=lambda kv: -kv[1]["out"]):
        P_(f"{p:<12}{r['sessions']:>6}{fmt(r['out']):>14}{pct(r['out'],tot_out):>11}{r['draft_sess']:>8}")
    P_("\n(Immunefi is UNSUBMITTABLE for this researcher: fee + verification gate. "
       "Its token share is a pure sink.)")

    # sharpest findings
    zero_draft_out = sum(r["out"] for t, r in T.items() if r["draft_sess"] == 0)
    P_("\n## SHARPEST FINDINGS")
    P_(f"- {pct(zero_draft_out, tot_out)} of ALL output_tokens went to targets that produced ZERO draft sessions.")
    P_(f"- {pct(imm_out, tot_out)} of ALL output_tokens went to Immunefi/SC targets, which are UNSUBMITTABLE (fee+level gate) = pure sink.")
    P_(f"- {pct(pal_out, tot_out)} of ALL output_tokens went to massive* alone; only {pct(n_draft_sess,n_sessions)} of all {n_sessions} sessions ever wrote a draft.")

    report = "\n".join(L) + "\n"
    with open(OUTFILE, "w") as fh:
        fh.write(report)
    # echo the parts the caller wants to stdout too
    print(report)
    sys.stderr.write(f"\n[written] {OUTFILE}\n")

if __name__ == "__main__":
    main()
