"""gnoc_qaqc_func.py - FUNCTIONAL QA for gnoc chat: call every registered tool for real and judge what comes back.

`gnoc qaqc` checks that the code parses, imports and that the registry is consistent. None of that calls a tool,
so a tool can be registered, documented and completely broken (a crash on ordinary input, a guard that does not
guard, a refusal that reads like a result) and every check still passes. This battery drives the tools.

Each case names the tool, the arguments, and what SHOULD happen:
    ok        it must do the thing and return something useful
    refuse    it must REFUSE (out of scope, missing identity, outside the repo, protected path): a guard that
              lets this through is a finding, not a pass
    either    it may do either depending on local state; only a crash or an empty answer fails
Nothing here sends traffic to an in-scope host, writes outside a scratch dir, spends cloud tokens or needs
approval: the tool functions are called directly, so the approval layer is out of the picture by design, and the
cases are chosen so the CODE guards are the thing under test.

    python3 scripts/gnoc_qaqc_func.py [--json] [--only <substr>] [--with-models]
"""
import io
import json
import os
import re
import shutil
import sys
import tempfile
import time
import contextlib

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(WS, "scripts"))

OOS = "qaqc-out-of-scope.invalid"          # never in any SCOPE.txt: the scope gate must refuse it
# every alternative needs its own tail: \b(refus|...)\b required a boundary right after "refus", so the most
# common refusal word in the codebase - "refused" - never matched, and 11 correct guards were reported as holes
REFUSAL = re.compile(r"(refus\w*|bad arguments?\b|out[_ ]of[_ ]scope|not in scope|denied|forbidden|blocked|no such|not a \w|"
                     r"needs? \w|must \w|cannot|can't|unable|missing|invalid|unknown|outside|"
                     r"^no \w|no (files|header|report|active|test|such)\b|is not (set up|a |in )|"
                     r"action is \w|kind is \w|not found|does not (exist|resolve))", re.I)
SLOW_S = 25.0


def _cases(G, scratch, prog):
    """(name, callable, expectation, note). Built lazily so a missing tool is reported, not an import error."""
    f = G
    rel = os.path.relpath(scratch, WS) if scratch.startswith(WS) else scratch
    C = []

    def add(tool, fn, expect, note=""):
        C.append((tool, fn, expect, note))

    ctx = G.Ctx({"program": prog})
    ex = lambda name, args: f._exec(name, args, ctx)  # noqa: E731 - the wrapper the chat calls
    nctx = G.Ctx({})  # no program: the program-gated tools must say so

    # ---- reading and the workspace
    add("read_file", lambda: f.t_read_file(ctx, "SPINE.md", 1, 3), "ok")
    add("read_file", lambda: f.t_read_file(ctx, "/etc/passwd"), "refuse", "outside the repo")
    add("list_dir", lambda: f.t_list_dir(ctx, "scripts"), "ok")
    # search past chats (2026-11-23): an answer either way (matches, or "no past chat mentions"), never a crash
    add("recall", lambda: __import__("gnoc_recall").t_recall(ctx, "router password", 3), "ok")
    add("recall", lambda: __import__("gnoc_recall").t_recall(ctx, ""), "either", "no query")
    add("grep", lambda: f.t_grep(ctx, "SPINE", "*.md"), "ok")
    add("find_symbol", lambda: f.t_find_symbol(ctx, "launch_dir"), "ok")
    add("repo_map", lambda: f.t_repo_map(ctx, "scripts"), "ok")
    add("hunt_search", lambda: f.t_hunt_search(ctx, "gatewayco / focus: zero click ato"), "ok",
        "free text must not crash the FTS index")
    add("dedup", lambda: f.t_dedup(ctx, "oauth state"), "either")
    add("decode", lambda: f.t_decode(ctx, "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."), "ok", "alg none JWT")
    add("decode", lambda: f.t_decode(ctx, "not-a-token"), "either")

    # ---- writing, inside and outside the sandbox
    add("write_file", lambda: f.t_write_file(ctx, os.path.join(rel, "qaqc.txt"), "hello"), "either")
    add("write_file", lambda: f.t_write_file(ctx, "/etc/qaqc-should-not-exist", "x"), "refuse", "outside the repo")
    add("write_file", lambda: f.t_write_file(ctx, "SPINE.md", "x"), "refuse", "protected path")
    add("edit_file", lambda: f.t_edit_file(ctx, "SPINE.md", "a", "b"), "refuse", "protected path")
    add("apply_patch", lambda: f.t_apply_patch(ctx, "not a patch"), "refuse")

    # ---- shell
    add("bash", lambda: f.t_bash(ctx, "echo qaqc-ok"), "ok")
    add("bash", lambda: f.t_bash(ctx, "rm -rf /"), "refuse", "deny list")
    add("bash", lambda: f.t_bash(ctx, f"curl https://{OOS}/"), "refuse", "scope gate on shell")

    # ---- network: every one of these must be refused before a byte leaves
    add("http_request", lambda: f.t_http_request(ctx, f"https://{OOS}/"), "refuse")
    add("http_request", lambda: f.t_http_request(nctx, "https://example.com/"), "refuse", "no program")
    add("graphql", lambda: f.t_graphql(ctx, f"https://{OOS}/graphql", field="viewer", select=["id"]), "refuse")
    add("graphql", lambda: f.t_graphql(ctx, "https://example.com/graphql", query="query { a { } }"), "refuse",
        "malformed hand-written query, refused before the wire")
    add("graph_overview", lambda: f.t_graph_overview(nctx), "refuse", "no program")
    # MCP: the client is configured per workspace; no servers is a valid state, a missing server is refused
    add("mcp", lambda: f.t_mcp(ctx, action="servers"), "either", "no configured servers is a fine answer")
    add("mcp", lambda: f.t_mcp(ctx, action="tools"), "refuse", "tools needs a server name")
    add("asset", lambda: f.t_asset(nctx, action="coverage"), "refuse", "no program")
    add("node", lambda: f.t_node(nctx, action="search"), "refuse", "no program")
    add("probe_matrix", lambda: f.t_probe_matrix(ctx, f"https://{OOS}/"), "refuse")
    add("race", lambda: f.t_race(ctx, f"https://{OOS}/", n=3), "refuse")
    add("scan", lambda: f.t_scan(ctx, "nuclei", f"https://{OOS}/"), "refuse")
    add("recon", lambda: f.t_recon(ctx, OOS), "refuse")
    add("js_mine", lambda: f.t_js_mine(ctx, f"https://{OOS}/app.js"), "refuse")
    add("touch", lambda: f.t_touch(ctx, f"https://{OOS}/a", f"https://{OOS}/a", "{}", as_identity=None),
        "refuse", "no owning identity")
    add("touch", lambda: f.t_touch(ctx, f"https://{OOS}/a", f"https://{OOS}/a", "{}", as_identity="A"), "refuse")
    add("web_fetch", lambda: f.t_web_fetch(ctx, "http://169.254.169.254/"), "refuse", "private address")
    add("web_fetch", lambda: f.t_web_fetch(ctx, f"https://{OOS}/"), "either", "third party, not a target")
    add("web_search", lambda: f.t_web_search(ctx, "llama.cpp rpc server", 3), "either",
        "live search; a provider outage must degrade to a note, never a traceback")
    add("web_search", lambda: f.t_web_search(ctx, "", 3), "either", "empty query must not throw")

    # ---- the hunt ledger
    add("hunt_brief", lambda: f.t_hunt_brief(ctx), "ok")
    add("hunt_model", lambda: f.t_hunt_model(ctx, "show"), "either")
    add("hunt_model", lambda: f.t_hunt_model(ctx, "add", boundaries="B9: nothing; excludes nobody"), "either")
    add("hunt_hypothesis", lambda: f.t_hunt_hypothesis(ctx, "list"), "either")
    add("hunt_hypothesis", lambda: f.t_hunt_hypothesis(ctx, "add", title="qaqc"), "refuse", "needs A/V/P")
    add("hunt_edge", lambda: f.t_hunt_edge(ctx, "list"), "either")
    add("hunt_edge", lambda: f.t_hunt_edge(ctx, "add", frm="unauth"), "refuse", "needs to/via")
    add("hunt_chains", lambda: f.t_hunt_chains(ctx, 3), "either")
    add("record_outcome", lambda: f.t_record_outcome(ctx, "qaqc probe", "DEAD"), "refuse", "floor gate")

    # ---- the expert layer
    add("playbook", lambda: f.t_playbook(ctx, "moves", "ssrf", "D", 3), "ok")
    add("playbook", lambda: f.t_playbook(ctx, "opener"), "ok")
    add("playbook", lambda: f.t_playbook(ctx, "cards", "oauth redirect", k=3), "ok")
    add("playbook", lambda: f.t_playbook(ctx, "manual", "T-215"), "ok")
    add("playbook", lambda: f.t_playbook(ctx, "next_hops", "ssrf"), "ok")
    add("playbook", lambda: f.t_playbook(ctx, "attack_tree", "ato"), "ok")
    add("playbook", lambda: f.t_playbook(ctx, "kill_check", "username enumeration on login"), "ok")
    add("playbook", lambda: f.t_playbook(ctx, "nonsense-kind"), "refuse")
    add("fingerprint", lambda: f.t_fingerprint(ctx), "either")

    # ---- the goal
    add("goal", lambda: f.t_goal(ctx, "show"), "either")
    add("goal", lambda: f.t_goal(ctx, "nonsense"), "refuse")

    # ---- identities and secrets
    add("identities", lambda: f.t_identities(ctx, "list"), "either")
    add("identities", lambda: f.t_identities(ctx, "save", name="QAQC"), "refuse", "no headers or raw capture")

    # ---- code quality
    add("code_review", lambda: f.t_code_review(ctx, "files", ["/etc/passwd"]), "refuse", "outside the repo")
    add("sast", lambda: f.t_sast(ctx, "scripts/gnoc_goal.py", ["semgrep"]), "either")
    add("lint", lambda: f.t_lint(ctx, ["scripts/gnoc_goal.py"]), "either")
    add("run_tests", lambda: f.t_run_tests(ctx, ["scripts/does-not-exist.py"], timeout=60), "either")
    add("git", lambda: f.t_git(ctx, "status"), "ok")
    add("git", lambda: f.t_git(ctx, "commit", message="qaqc should refuse this"), "refuse", "no paths named")
    add("git", lambda: f.t_git(ctx, "blame", paths=["SPINE.md"], lines="1,2"), "ok")
    add("git", lambda: f.t_git(ctx, "restore"), "refuse", "restore names its paths")
    add("git", lambda: f.t_git(ctx, "show", ref="--output=/tmp/qaqc"), "refuse", "an option-shaped ref")
    add("typecheck", lambda: f.t_typecheck(ctx, ["/etc/passwd"]), "refuse", "outside the repo")
    add("bg", lambda: f.t_bg(ctx, "list"), "ok")
    add("bg", lambda: f.t_bg(ctx, "start", name="qaqc", command="shutdown -h now"), "refuse", "bash's deny list")
    add("bg", lambda: f.t_bg(ctx, "output", name="qaqc-none"), "refuse", "no such process")
    add("tasks", lambda: f.t_tasks(ctx, "list"), "either")

    # ---- malware / RE
    add("malware", lambda: f.t_malware(ctx, "/usr/bin/ls", "hashes"), "ok")
    add("malware", lambda: f.t_malware(ctx, "/usr/bin/ls", "elf"), "ok")
    add("malware", lambda: f.t_malware(ctx, "/usr/bin/ls", "sandbox"), "ok")
    add("malware", lambda: f.t_malware(ctx, "/nonexistent/file", "hashes"), "refuse")

    # ---- misc read-only
    add("jobs", lambda: f.t_jobs(ctx), "either")
    add("bot", lambda: f.t_bot(ctx, "summary"), "either")
    add("gnoc", lambda: f.t_gnoc(ctx, "status"), "either")
    add("gnoc", lambda: f.t_gnoc(ctx, "submit"), "refuse", "filing is the user's")
    add("burp_check", lambda: f.t_burp_check(ctx), "either")
    add("oast", lambda: f.t_oast(ctx, "status"), "either")
    add("set_program", lambda: f.t_set_program(ctx, "definitely-not-a-program-xyz"), "refuse")
    add("change_dir", lambda: f.t_change_dir(ctx, "/definitely/not/here"), "refuse")
    # isolated: this exercised `learn` against the LIVE lesson book, and its literal text became the most-
    # reinforced "lesson" in it (27 times, one per QAQC run, found 2026-10-22)
    def _learn_isolated():
        import gnoc_learn
        with gnoc_learn.isolated():
            return f.t_learn(ctx, "functional battery check: the learn tool round-trips", why="qaqc self-test")
    add("learn", _learn_isolated, "either")
    add("email_inbox", lambda: f.t_email_inbox(ctx, "list", n=1), "either", "no creds is a clean refusal")
    add("discord_read", lambda: f.t_discord_read(ctx, "channels"), "either")
    # isolated: every run used to leave a real queued outgoing draft in GreyNOC's approval outbox
    def _draft_isolated():
        import gnoc_comms
        with gnoc_comms.isolated():
            return f.t_draft_outgoing(ctx, "email", "qaqc battery self-test body",
                                      to="x@example.com", subject="qaqc")
    add("draft_outgoing", _draft_isolated, "either")
    add("desktop", lambda: f.t_desktop(ctx, "status"), "either")
    add("repro_check", lambda: f.t_repro_check(ctx, "reports/drafts/definitely-not-here"), "refuse")
    add("ship_chain", lambda: f.t_ship_chain(ctx, "reports/drafts/definitely-not-here"), "refuse")
    add("build_report", lambda: f.t_build_report(nctx), "refuse", "no program")
    add("pick_target", lambda: f.t_pick_target(ctx), "either")

    # ---- argument hardening: the shapes a 20B model actually sends, through the same wrapper the chat uses
    add("read_file", lambda: ex("read_file", {"path": "SPINE.md", "offset": "1", "limit": "3"}), "ok",
        "string ints are coerced")
    add("read_file", lambda: ex("read_file", {"limit": "abc"}), "refuse", "bad arguments, never a traceback")
    add("probe_matrix", lambda: ex("probe_matrix", {"url": f"https://{OOS}/", "allow_writes": "false",
                                                    "identities": "['A','B']"}), "refuse", "list literal + OOS")
    add("git", lambda: ex("git", {"action": "nuke"}), "refuse", "off-enum action names the choices")
    add("grep", lambda: f.t_grep(ctx, "(unclosed", "scripts"), "either", "broken regex says how to escape it")
    add("tasks", lambda: f.t_tasks(ctx, "delete"), "refuse", "unknown action writes nothing")
    add("record_outcome", lambda: f.t_record_outcome(ctx, "qaqc", "maybe"), "refuse", "off-vocabulary verdict")
    add("malware", lambda: f.t_malware(ctx, os.path.expanduser("~/.ssh/id_rsa"), "strings"), "refuse",
        "a credential file is never a sample")
    # model-backed tools: each guard fires before any model, GPU or cloud call
    add("delegate", lambda: f.t_delegate(ctx, "read targets/<program>/SCOPE.txt and report"), "refuse",
        "placeholder")
    add("fan_out", lambda: f.t_fan_out(ctx, []), "refuse", "empty task list")
    add("second_opinion", lambda: f.t_second_opinion(ctx, ""), "refuse", "empty question")
    add("hypothesize", lambda: f.t_hypothesize(nctx), "refuse", "no program")
    add("claude_worker", lambda: f.t_claude_worker(ctx, "no-such-agent-qaqc", "a brief long enough to pass"),
        "refuse", "unknown agent (or offline)")
    add("browser", lambda: f.t_browser(ctx, f"https://{OOS}/"), "refuse", "scope gate before Chromium starts")
    add("burp_panels", lambda: f.t_burp_panels(ctx, "targets/qaqc-none/raw.json"), "refuse", "no raw capture")

    # ---- the tools that had NO case until 2026-10-31. The gap is why the sweep scope-gate hole and the
    # "0 anomalies" headline on a wholly UNFIRED sweep both survived a green battery: an uncovered tool is an
    # untested tool. Each case here is read-only, or an argument the guard must refuse; none fires live traffic.
    add("econ_status", lambda: f.t_econ_status(ctx), "ok")
    add("econ_bounty", lambda: f.t_econ_bounty(ctx, "list"), "either")
    add("econ_bet", lambda: f.t_econ_bet(ctx, prog, "no-such-bounty", "nonsense-side", 0), "refuse",
        "side is long or short")
    add("find_file", lambda: f.t_find_file(ctx, "SCOPE.txt"), "ok", "find_file is scoped to the program dir")
    add("hunt_phase", lambda: f.t_hunt_phase(ctx), "either")
    add("lessons", lambda: f.t_lessons(ctx, "oauth", 3), "either")
    add("office_funnel", lambda: f.t_office_funnel(ctx), "either")
    add("pay_check", lambda: f.t_pay_check(ctx), "either")
    add("plan", lambda: f.t_plan(ctx, "show"), "either")
    add("plan", lambda: f.t_plan(ctx, "nonsense"), "refuse", "off-enum action writes nothing")
    add("team", lambda: f.t_team(ctx, ""), "refuse", "needs a brief")
    add("liveness", lambda: f.t_liveness(ctx, "reports/drafts/definitely-not-here"), "refuse", "no report.md")
    add("escalate", lambda: f.t_escalate(ctx, ""), "refuse", "runs only on an oracle PASS")
    add("provision", lambda: f.t_provision(ctx, "register"), "refuse", "no signup_url")
    add("defend", lambda: f.t_defend(ctx, "nonsense-action"), "refuse", "off-enum action")
    # site_redteam with no arguments fires REAL requests at GreyNOC's own live site, so the battery must never
    # call it that way: the case under test is the check-name guard, which answers before anything is sent.
    add("site_redteam", lambda: f.t_site_redteam(ctx, checks="nonsense-check"), "refuse", "unknown check")
    add("site_status", lambda: f.t_site_status(ctx), "either")
    # the oracle tools are registered from gnoc_oracle, so they are driven through the same wrapper the chat
    # uses rather than as module attributes of gnoc_agent (which they are not)
    add("oracle_status", lambda: ex("oracle_status", {}), "either")
    add("oracle_commit", lambda: ex("oracle_commit", {"hyp_id": "H-qaqc-none", "kind": "nonsense-kind"}),
        "refuse", "off-enum terminal kind")
    add("oracle_verify", lambda: ex("oracle_verify", {"oracle_id": "no-such-oracle", "captures": "{}"}),
        "refuse", "unknown oracle id")
    add("release_phase", lambda: ex("release_phase", {"cls": "nonsense-class"}), "either")
    # sweep: an OUT-OF-SCOPE seam must be refused in ONE line. Before 2026-10-31 it built a full variant table
    # of per-row PermissionErrors headed "N variants, 0 anomalies" - an UNFIRED sweep that read as a negative.
    add("sweep", lambda: f.t_sweep(ctx, f"https://{OOS}/?q={{{{X}}}}", cap=3), "refuse", "scope gate up front")
    add("sweep", lambda: f.t_sweep(ctx, f"https://{OOS}/"), "refuse", "no marker")
    # host_sweep (2026-11-10): no hosts is a bad-arguments refusal; an out-of-scope host is refused per host
    add("host_sweep", lambda: f.t_host_sweep(ctx, ""), "refuse", "no hosts")
    add("host_sweep", lambda: f.t_host_sweep(ctx, [OOS], cap=1), "refuse", "scope gate per host")
    # skills (2026-11-26, phase 3): an unknown name answers with the catalog, never a crash. propose_skill is driven
    # only with inputs its guards refuse BEFORE anything is written, because an accepted proposal lands in the
    # user's real pending queue: a turn that read outside text, and a name that is not a skill name.
    add("load_skill", lambda: f.t_load_skill(ctx, "no-such-skill-qaqc"), "refuse", "unknown skill")
    tctx = G.Ctx({"program": prog, "_tainted": ["web"]})
    add("propose_skill", lambda: f.t_propose_skill(tctx, "qaqc-skill", "one line", "x" * 60), "refuse",
        "a tainted turn cannot leave a skill behind")
    add("propose_skill", lambda: f.t_propose_skill(ctx, "Not A Name!", "one line", "x" * 60), "refuse",
        "bad name")
    return C


def run(only=None, with_models=False, verbose=True):
    import gnoc_agent as G
    scratch = tempfile.mkdtemp(prefix="gnoc-qaqc-")
    saved_root, saved_skip = G._ACTIVE_ROOT[0], G.SKIP_PERMS[0]
    prog = next((p for p in sorted(os.listdir(os.path.join(WS, "targets")))
                 if os.path.isfile(os.path.join(WS, "targets", p, "SCOPE.txt"))), None)
    rows, missing = [], []
    try:
        cases = _cases(G, scratch, prog)
        covered = {c[0] for c in cases}
        missing = sorted({n for n in G.TOOLS if not n.startswith("mcp__")} - covered - (set() if with_models else
                         {"delegate", "fan_out", "second_opinion", "claude_worker", "hypothesize", "browser",
                          "generate_image", "burp_panels"}))
        for tool, fn, expect, note in cases:
            if only and only not in tool:
                continue
            t0 = time.time()
            buf = io.StringIO()
            try:
                with contextlib.redirect_stdout(buf):
                    out = fn()
                err = None
            except Exception as e:  # noqa: BLE001 - a crash IS the finding here
                out, err = None, f"{type(e).__name__}: {e}"
            el = time.time() - t0
            text = "" if out is None else str(out)
            if err:
                verdict = "CRASH"
            elif not text.strip():
                verdict = "EMPTY"
            elif expect == "refuse":
                verdict = "PASS" if REFUSAL.search(text[:400]) else "GUARD-HOLE"
            elif expect == "ok":
                verdict = "SOFT" if REFUSAL.search(text[:200]) else "PASS"
            else:
                verdict = "PASS"
            rows.append({"tool": tool, "expect": expect, "verdict": verdict, "s": round(el, 1), "note": note,
                         "detail": (err or " ".join(text.split())[:150])})
            if verbose:
                mark = {"PASS": "ok  ", "SOFT": "soft", "EMPTY": "EMPTY", "CRASH": "CRASH", "GUARD-HOLE": "HOLE"}[verdict]
                line = f"[{mark}] {tool:<16} {expect:<6} {round(el, 1):>5}s  {rows[-1]['detail'][:88]}"
                print(line + (f"   ({note})" if note and verdict != "PASS" else ""))
    finally:
        G._ACTIVE_ROOT[0], G.SKIP_PERMS[0] = saved_root, saved_skip
        shutil.rmtree(scratch, ignore_errors=True)
    return rows, missing


def main(argv):
    only = argv[argv.index("--only") + 1] if "--only" in argv else None
    rows, missing = run(only, "--with-models" in argv, verbose="--json" not in argv)
    bad = [r for r in rows if r["verdict"] in ("CRASH", "GUARD-HOLE", "EMPTY")]
    slow = [r for r in rows if r["s"] >= SLOW_S]
    if "--json" in argv:
        print(json.dumps({"rows": rows, "bad": bad, "missing": missing}, indent=1))
    else:
        print()
        print(f"{len(rows)} calls, {len(rows) - len(bad)} good, {len(bad)} needing attention"
              + (f", {len(slow)} slow (>{SLOW_S:.0f}s)" if slow else ""))
        for r in bad:
            print(f"  {r['verdict']:<10} {r['tool']:<16} {r['detail'][:110]}")
        if missing:
            print(f"  no functional case yet: {', '.join(missing)}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
