#!/usr/bin/env python3
"""oss-bot - scope-proxied, policy-gated background scanner. Every output is a forced LEAD.

    bot.py status                       one-screen digest (read THIS, not raw output)
    bot.py plan [p]                     T-156 receipt: status, evidence, rps, header, tier, why excluded
    bot.py run <p> <job> [--dry]        one manual job (refuses network jobs when network_ok is False,
                                        and any job while STOP or PAUSE exists)
    bot.py proxytest <p>                offline proof that httpx, nuclei and katana route through the proxy
    bot.py leads [p] [--top N] [--all]
    bot.py mark <fp> fp|dupe|verified-elsewhere "<why>" [--rule]   (--rule: fp the whole rule)
    bot.py pause | resume               writes/removes .claude/state/oss-bot/PAUSE (an "INCIDENT " PAUSE from the
                                        scope-proxy audit needs: bot.py resume --ack-incident)
    bot.py drain | undrain              writes/removes oss-bot/DRAIN: no new job starts, running ones finish
    bot.py selfcheck                    offline: lib_scope, lib_policy, scope_proxy, ingest fixtures, db CHECK
    bot.py daemon                       the pm2 loop (Phase 2; OSS_BOT_DRY=1 -> jobs.py --dry)

State: .claude/state/oss-bot/bot.db (sqlite3 WAL). Output: targets/<p>/recon/oss-bot/. Never reports/.
NO LLM is used anywhere in this engine (config llm_triage is false and unimplemented here).
"""
from __future__ import annotations

import glob
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
from bbtools import lib_policy, lib_scope, lib_state  # noqa: E402
import ingest  # noqa: E402

ROOT = lib_scope.WS_ROOT
CFG = json.load(open(os.path.join(HERE, "config.json"), encoding="utf-8"))
SD = ingest.state_dir(ROOT)
PAUSE = os.path.join(SD, "PAUSE")
DRAIN = os.path.join(SD, "DRAIN")  # harmony phase 2: start no new job, let running ones finish
INCIDENT_PREFIX = "INCIDENT "      # ingest.py audit-fail latch; resume needs --ack-incident
STOP = os.path.join(ROOT, ".claude/state/hunt-loop/STOP")
HL = os.path.join(ROOT, ".claude/state/hunt-loop")
NET = ingest.NET_JOBS
JOBS = ("enum",) + NET + ("secrets",)
PY = sys.executable or "/usr/bin/python3"
_RUNNING: dict[tuple[str, str], dict] = {}
_STOPFLAG = {"v": False}


def iso(t=None):
    return ingest._iso(t)


def db():
    return ingest.db_connect(ROOT)


def halted():
    for f, why in ((STOP, "STOP"), (PAUSE, "PAUSE")):
        if os.path.exists(f):
            return f"{why} present ({os.path.relpath(f, ROOT)})"
    return None


def atomic_state(status, extra=None):
    os.makedirs(SD, exist_ok=True)
    st = {"ts": iso(), "pid": os.getpid(), "status": status,
          "running": [{"program": p, "job": j, "pid": r["proc"].pid, "run_dir": r["run_dir"]}
                      for (p, j), r in _RUNNING.items()]}
    st.update(extra or {})
    tmp = os.path.join(SD, "state.json.tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(st, fh, indent=1)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, os.path.join(SD, "state.json"))


# ------------------------------------------------------------------ tiers / programs
def _first_tokens(path):
    out = []
    for ln in ingest._read_lines(path):
        tok = ln.split("#", 1)[0].split()
        if tok:
            out.append(tok[0])
    return out


def _pid_alive(pid):
    try:
        os.kill(int(pid), 0)
        return True
    except (ValueError, ProcessLookupError):
        return False
    except PermissionError:
        return True


def tiers():
    """P0 = live fleet claims U global LOCK U fresh (<24 h) LOCK.<sid> U AUTO-HUNT (lib_state.active_programs,
    harmony 2.6: a dead session's lock no longer stays P0 forever); P1 = priority.txt U priority-vdp.txt;
    P2 = rest. no-yield programs are skipped unless P0."""
    tdir = os.path.join(ROOT, "targets")
    exists = lambda p: os.path.isdir(os.path.join(tdir, p))
    p0 = {p for p in lib_state.active_set(lib_state.active_programs(ROOT)) if exists(p)}
    p1 = []
    for f in ("priority.txt", "priority-vdp.txt"):
        for p in _first_tokens(os.path.join(HL, f)):
            if exists(p) and p not in p1 and p not in p0:
                p1.append(p)
    noy = set(_first_tokens(os.path.join(HL, "no-yield.txt")))
    return p0, p1, noy


def program_table():
    p0, p1, noy = tiers()
    rows = []
    tdir = os.path.join(ROOT, "targets")
    for p in sorted(os.listdir(tdir)):
        if not os.path.isdir(os.path.join(tdir, p)):
            continue
        if not ingest.is_valid_program_name(p):
            continue  # e.g. a local program-08 sandbox dir - never schedulable, not a real program
        has_scope = os.path.isfile(os.path.join(tdir, p, "SCOPE.txt"))
        pol = lib_policy.policy(p)
        tier = 0 if p in p0 else 1 if p in p1 else 2
        why = ""
        if not has_scope:
            why = "no SCOPE.txt"
        elif p in noy and tier != 0:
            why = "no-yield.txt (P2-skipped)"
        elif not pol["network_ok"]:
            why = f"network_ok=False ({pol['status']})"
        rows.append({"program": p, "tier": tier, "status": pol["status"], "rps": pol["rps"], "header": pol["header"],
                     "evidence": pol["evidence"], "network_ok": bool(has_scope and pol["network_ok"] and not
                                                                     (p in noy and tier != 0)),
                     "secrets_ok": has_scope and not (p in noy and tier != 0), "why": why})
    return rows


def refresh_programs(con):
    rows = program_table()
    now = time.time()
    for r in rows:
        hdr = f"{r['header'][0]}: {r['header'][1]}" if r["header"] else None
        con.execute("INSERT INTO programs VALUES(?,?,?,?,?,?,?) ON CONFLICT(program) DO UPDATE SET tier=excluded.tier,"
                    " status=excluded.status, rps=excluded.rps, header=excluded.header, evidence=excluded.evidence,"
                    " refreshed=excluded.refreshed", (r["program"], r["tier"], r["status"], r["rps"], hdr,
                                                      r["evidence"], now))
    con.commit()
    return rows


def cmd_plan(prog=None):
    rows = program_table()
    print("program\ttier\tstatus\trps\theader\tnetwork\tevidence / why excluded")
    for r in rows:
        if prog and r["program"] != prog:
            continue
        hdr = f"{r['header'][0]}: {r['header'][1]}" if r["header"] else "-"
        net = "yes" if r["network_ok"] else "NO"
        print(f"{r['program']}\tP{r['tier']}\t{r['status']}\t{r['rps']}\t{hdr}\t{net}\t"
              f"{r['why'] or '-'}{' | ' + r['evidence'] if r['evidence'] else ''}")
    return 0


# ------------------------------------------------------------------ running one job
def new_run_dir(program, job):
    d = os.path.join(ingest.out_dir(program, ROOT), "runs", f"{job}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}")
    n, base = 1, d
    while os.path.exists(d):
        n += 1
        d = f"{base}-{n}"
    ingest.gmkdir(d, program, ROOT)
    return d


def _probe_hosts_file(con, program, run_dir):
    """exact_hosts U newest enum hosts, filtered, rotated by the bot.db cursor to the probe cap."""
    items = list(lib_scope.exact_hosts(program))
    ef = sorted(glob.glob(os.path.join(ingest.out_dir(program, ROOT), "runs", "enum-*", "enum-hosts.txt")),
                key=os.path.getmtime, reverse=True)
    if ef:
        items += open(ef[0], encoding="utf-8").read().split()
    seen, keep = set(), []
    for h in items:
        if h.lower() not in seen and lib_scope.program_allows(h, program, ROOT)[0]:
            seen.add(h.lower())
            keep.append(h)
    cap = CFG["host_cap"]["probe"]
    r = con.execute("SELECT cursor FROM jobs WHERE program=? AND job='probe'", (program,)).fetchone()
    cur = (r[0] or 0) if r else 0
    if len(keep) > cap:
        cur %= len(keep)
        sel = (keep[cur:] + keep[:cur])[:cap]
        cur = (cur + cap) % len(keep)
    else:
        sel, cur = keep, 0
    con.execute("INSERT INTO jobs(program,job,cursor) VALUES(?,?,?) ON CONFLICT(program,job) DO UPDATE SET "
                "cursor=excluded.cursor", (program, "probe", cur))
    con.commit()
    f = os.path.join(run_dir, "hosts.list")
    ingest.gwrite(f, "".join(h + "\n" for h in sel), program, ROOT)
    return f


def start_job(con, program, job, tier, dry=False, hosts=None):
    run_dir = new_run_dir(program, job)
    if job == "probe" and not hosts:
        hosts = _probe_hosts_file(con, program, run_dir)
    argv = [PY, os.path.join(HERE, "jobs.py"), job, program, "--run-dir", run_dir, "--tier", str(tier)]
    if hosts:
        argv += ["--hosts", hosts]
    if dry:
        argv.append("--dry")
    now = time.time()
    cur = con.execute("INSERT INTO runs(program,job,started,run_dir) VALUES(?,?,?,?)",
                      (program, job, now, os.path.relpath(run_dir, ROOT)))
    run_id = cur.lastrowid
    log = open(os.path.join(run_dir, "jobs.log"), "w", encoding="utf-8")
    proc = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                            start_new_session=True, cwd=ROOT)
    con.execute("INSERT INTO jobs(program,job,last_start,pid,run_dir) VALUES(?,?,?,?,?) ON CONFLICT(program,job) DO "
                "UPDATE SET last_start=excluded.last_start, pid=excluded.pid, run_dir=excluded.run_dir",
                (program, job, now, proc.pid, os.path.relpath(run_dir, ROOT)))
    con.commit()
    _RUNNING[(program, job)] = {"proc": proc, "run_id": run_id, "run_dir": run_dir, "tier": tier, "log": log,
                                "dry": dry}
    return _RUNNING[(program, job)]


def finalize(con, program, job, r, rc, delta=False):
    r["log"].close()
    run_dir, tier = r["run_dir"], r["tier"]
    meta = ingest._load_meta(run_dir)
    res = {"audit": "-", "leads_new": 0, "new_hosts": [], "backoff": False}
    if rc in (0, 1) and not r["dry"]:
        res = ingest.ingest(program, run_dir, ROOT, tier=tier, cfg=CFG)
    elif r["dry"]:
        res["audit"] = "DRY"
    now = time.time()
    con.execute("UPDATE runs SET ended=?, rc=?, hosts_in=?, hosts_refused=?, leads_new=?, audit=? WHERE id=?",
                (now, rc, meta.get("inputs"), meta.get("refused"), res["leads_new"], res["audit"], r["run_id"]))
    if r["dry"]:
        # a dry run must not advance scheduling state: a clean dry hour pushing every job's next_due
        # out by a full cadence means going live fires almost nothing for days (2026-10-21 receipt).
        # pid still needs clearing - the dry subprocess has already exited.
        con.execute("UPDATE jobs SET pid=NULL WHERE program=? AND job=?", (program, job))
    else:
        cad = CFG["cadence_h"][job][min(tier, 2)]
        cad_s = (cad if cad is not None else 24 * 365) * 3600
        row = con.execute("SELECT fails, next_due FROM jobs WHERE program=? AND job=?", (program, job)).fetchone()
        fails = (row[0] or 0) if row else 0
        if rc == 0:
            fails, nd = 0, now + cad_s
        else:
            fails += 1
            nd = now + min(24 * 3600, cad_s * (2 ** fails))
        if res.get("backoff") and row and row[1]:
            nd = max(nd, row[1])
        con.execute("UPDATE jobs SET last_end=?, last_rc=?, fails=?, next_due=?, pid=NULL WHERE program=? AND job=?",
                    (now, rc, fails, nd, program, job))
    con.commit()
    if delta and job == "probe" and tier <= 1 and res.get("new_hosts"):
        ingest.gwrite(os.path.join(SD, f"delta-{program}.txt"),
                      "".join(f"https://{h}\n" for h in res["new_hosts"]), program, ROOT)
        con.execute("UPDATE jobs SET next_due=? WHERE program=? AND job='nuclei-fast'", (now, program))
        con.commit()
    ingest.render_status(program, ROOT, con, extra=res["audit"])
    _RUNNING.pop((program, job), None)
    return res


def _terminate_all(con, why):
    for (p, j), r in list(_RUNNING.items()):
        try:
            os.killpg(r["proc"].pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
    for (p, j), r in list(_RUNNING.items()):
        try:
            r["proc"].wait(timeout=20)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(r["proc"].pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        con.execute("UPDATE runs SET ended=?, rc=?, audit=? WHERE id=?", (time.time(), -15, f"KILLED {why}", r["run_id"]))
        con.execute("UPDATE jobs SET last_end=?, last_rc=-15, fails=fails+1, pid=NULL WHERE program=? AND job=?",
                    (time.time(), p, j))
        r["log"].close()
        _RUNNING.pop((p, j), None)
    con.commit()


HQ_DIR = os.path.join(ROOT, ".hunt-index")
HQ_REBUILD_STATE = os.path.join(SD, "hq-rebuild.json")
_HQ_REBUILD: dict = {"proc": None, "newdb": None}


def hq_rebuild_tick(con):
    """At most every 6h, and only when leads changed since the last rebuild: rebuild the hq index
    into a temp db and atomically swap it in (spec Phase 4.2). flock -n so this can never collide
    with a manual `scripts/hq reindex` (same lock file, same semantics). Non-blocking - starts a
    detached subprocess and polls it on later ticks, since a 1.5GB+ db rebuild can take minutes and
    must never stall job scheduling or delay STOP/PAUSE responsiveness."""
    if _HQ_REBUILD["proc"] is not None:
        rc = _HQ_REBUILD["proc"].poll()
        if rc is None:
            return  # still running; check again next tick
        newdb = _HQ_REBUILD["newdb"]
        if rc == 0 and os.path.isfile(newdb):
            os.replace(newdb, os.path.join(HQ_DIR, "hunts.db"))  # atomic; old-inode readers finish on their own
            json.dump({"ts": time.time()}, open(HQ_REBUILD_STATE, "w"))
        elif rc not in (0, 1):  # 1 = lock already held (a manual `hq reindex`) - not an error
            with open(os.path.join(SD, "bot.log"), "a", encoding="utf-8") as lf:
                lf.write(f"[{iso()}] hq rebuild rc={rc}\n")
        _HQ_REBUILD["proc"], _HQ_REBUILD["newdb"] = None, None
        return
    try:
        last = json.load(open(HQ_REBUILD_STATE)).get("ts", 0)
    except (OSError, ValueError):
        last = 0
    if time.time() - last < 6 * 3600:
        return
    if con.execute("SELECT count(*) FROM leads WHERE last_seen > ?", (last,)).fetchone()[0] <= 0:
        return
    newdb = os.path.join(HQ_DIR, "hunts.db.oss-new")
    lockf = os.path.join(HQ_DIR, ".rebuild.lock")
    try:
        proc = subprocess.Popen(["flock", "-n", lockf, "nice", "-n", "19", PY,
                                 os.path.join(ROOT, "scripts/hunt-index.py"), "--db", newdb],
                                cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                stdin=subprocess.DEVNULL, start_new_session=True)
        _HQ_REBUILD["proc"], _HQ_REBUILD["newdb"] = proc, newdb
    except Exception as e:
        with open(os.path.join(SD, "bot.log"), "a", encoding="utf-8") as lf:
            lf.write(f"[{iso()}] hq rebuild failed to start: {str(e)[:160]}\n")


def _install_signals(con):
    def h(signum, _f):
        _STOPFLAG["v"] = True
        _terminate_all(con, signal.Signals(signum).name)
        atomic_state("stopped", {"signal": signal.Signals(signum).name})
        sys.exit(0)
    signal.signal(signal.SIGTERM, h)
    signal.signal(signal.SIGINT, h)


def fresh_probe(program, hours=48):
    f = sorted(glob.glob(os.path.join(ingest.out_dir(program, ROOT), "runs", "probe-*", "httpx.raw")),
               key=os.path.getmtime, reverse=True)
    return bool(f) and time.time() - os.path.getmtime(f[0]) < hours * 3600


def cmd_run(program, job, dry=False):
    if job not in JOBS:
        print(f"unknown job {job}; one of {', '.join(JOBS)}")
        return 2
    h = halted()
    if h and not dry:
        print(f"REFUSED {program}/{job}: {h}. The bot honours STOP/PAUSE; it never removes them.")
        return 2
    # A scan is work a human asked for, so it is GATED on a live gnoc chat rather than refused
    # outright (GreyNOC, 2026-11-02). A dry run plans only and never reaches the network.
    if not dry:
        sys.path.insert(0, os.path.join(os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "scripts"))
        import gnoc_session
        ok, why = gnoc_session.require(f"oss-bot {job} on {program}")
        if not ok:
            print(why)
            return 3
    row = next((r for r in program_table() if r["program"] == program), None)
    if row is None:
        print(f"REFUSED: no targets/{program}")
        return 2
    if job != "secrets" and not row["network_ok"]:
        print(f"REFUSED {program}/{job}: {row['why']} {row['evidence']}")
        return 2
    if job == "secrets" and not row["secrets_ok"]:
        print(f"REFUSED {program}/secrets: {row['why']}")
        return 2
    con = db()
    _install_signals(con)
    seq = [job]
    if job in ("nuclei-fast", "nuclei-cve", "crawl") and not fresh_probe(program) and not dry:
        seq = ["probe", job]
        print(f"no probe < 48h for {program}: running probe first")
    rc_all = 0
    for j in seq:
        r = start_job(con, program, j, row["tier"], dry=dry)
        print(f"started {program}/{j} pid {r['proc'].pid} run {os.path.relpath(r['run_dir'], ROOT)}")
        rc = r["proc"].wait()
        res = finalize(con, program, j, r, rc)
        print(f"{program}/{j} rc={rc} audit={res['audit']} leads_new={res['leads_new']} "
              f"new_hosts={len(res.get('new_hosts') or [])} backoff={res.get('backoff')}")
        rc_all = rc_all or rc
        if rc not in (0, 1) or str(res["audit"]).startswith("AUDIT FAIL"):
            break
    atomic_state("idle")
    con.close()
    return rc_all


# ------------------------------------------------------------------ proxytest (V1.3)
def cmd_proxytest(program):
    import jobs
    pol = lib_policy.policy(program)
    R = min(float(CFG["rps_cap"]), float(pol["rps"]))
    D = new_run_dir(program, "proxytest")
    canary = "oos-canary.invalid"
    results, ok_all = [], True
    for tool in ("httpx", "nuclei", "katana"):
        sub = os.path.join(D, tool)
        ingest.gmkdir(sub, program, ROOT)
        if tool == "httpx":
            ingest.gwrite(os.path.join(sub, "hosts.in"), f"{canary}\n", program, ROOT)
        else:
            ingest.gwrite(os.path.join(sub, "urls.in"), f"https://{canary}/\nhttp://{canary}/\n", program, ROOT)
        px = jobs.Proxy(program, sub, R)
        try:
            argv = {"httpx": jobs.argv_httpx, "katana": jobs.argv_katana}.get(tool, jobs.argv_nuclei)(sub, R, px.url, pol)
            ingest.gwrite(os.path.join(sub, "cmd.txt"), " ".join(argv) + "\n", program, ROOT)
            t = jobs.run_tool(tool, argv, px.env(), 240)
        finally:
            px.stop()
        rows = list(ingest._jsonl(os.path.join(sub, "egress.jsonl")))
        denied = [x for x in rows if x.get("host") == canary and x.get("allowed") is False]
        allowed = [x for x in rows if x.get("allowed") is True]
        raw = os.path.join(sub, f"{tool}.raw")
        parser = {"httpx": ingest.parse_httpx, "nuclei": ingest.parse_nuclei, "katana": ingest.parse_katana}[tool]
        outs = list(parser(raw)) if os.path.isfile(raw) else []      # successful output rows, same parser as ingest
        if tool == "katana" and os.path.isdir(os.path.join(sub, "responses")):
            outs += [f for f in glob.glob(os.path.join(sub, "responses", "**", "*"), recursive=True)
                     if os.path.isfile(f) and os.path.getsize(f) > 0]
        ok = bool(denied) and not allowed and not outs
        ok_all &= ok
        other = sorted({f"{x.get('host')}:{x.get('reason')}" for x in rows if x.get("host") != canary})
        results.append((tool, ok, len(denied), len(allowed), len(outs), t["rc"], t["secs"], other))
    with open(os.path.join(D, "egress.jsonl"), "w", encoding="utf-8") as out:
        for tool in ("httpx", "nuclei", "katana"):
            for x in ingest._jsonl(os.path.join(D, tool, "egress.jsonl")):
                out.write(json.dumps(dict(x, tool=tool)) + "\n")
    print(f"proxytest {program} -> {os.path.relpath(D, ROOT)}")
    print("tool\tresult\tcanary_denied_rows\tallowed_rows\toutput_rows\ttool_rc\tsecs\tother_denied")
    for tool, ok, nd, na, no, rc, secs, other in results:
        print(f"{tool}\t{'PASS' if ok else 'FAIL'}\t{nd}\t{na}\t{no}\t{rc}\t{secs}\t{','.join(other) or '-'}")
    print("PROXYTEST PASS" if ok_all else "PROXYTEST FAIL")
    return 0 if ok_all else 1


# ------------------------------------------------------------------ status / leads / mark / pause
def cmd_status():
    con = db()
    rows = program_table()
    t = {0: 0, 1: 0, 2: 0}
    for r in rows:
        if r["network_ok"]:
            t[r["tier"]] += 1
    st = {}
    try:
        st = json.load(open(os.path.join(SD, "state.json"), encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        pass
    print(f"oss-bot status {iso()}  halted: {halted() or 'no'}  daemon state: {st.get('status', '-')} ({st.get('ts', '-')})")
    print(f"network-eligible programs: P0 {t[0]}  P1 {t[1]}  P2 {t[2]}  (excluded {sum(1 for r in rows if not r['network_ok'])})")
    run = con.execute("SELECT program,job,pid,run_dir FROM jobs WHERE pid IS NOT NULL").fetchall()
    print("running: " + (", ".join(f"{p}/{j} pid {pid}" for p, j, pid, _ in run if _pid_alive(pid)) or "none"))
    due = con.execute("SELECT program,job,next_due FROM jobs WHERE next_due IS NOT NULL ORDER BY next_due LIMIT 8").fetchall()
    print("due next: " + (", ".join(f"{p}/{j} {iso(n)}" for p, j, n in due) or "none scheduled"))
    print("last 10 runs:")
    for p, j, s, e, rc, hi, hr, ln, au in con.execute(
            "SELECT program,job,started,ended,rc,hosts_in,hosts_refused,leads_new,audit FROM runs ORDER BY id DESC LIMIT 10"):
        print(f"  {iso(s)} {p}/{j} rc={rc} hosts={hi} refused={hr} leads_new={ln} {au or '-'}")
    n24 = con.execute("SELECT count(*) FROM leads WHERE first_seen > ?", (time.time() - 86400,)).fetchone()[0]
    print(f"new leads 24h: {n24} (all LEAD-only)")
    bo = con.execute("SELECT program, job, next_due FROM jobs WHERE next_due > ? AND last_rc = 0", (time.time() + 20 * 3600,)).fetchall()
    print("deferred > 20h: " + (", ".join(f"{p}/{j}" for p, j, _ in bo[:10]) or "none"))
    con.close()
    return 0


def cmd_leads(prog=None, top=20, all_=False):
    con = db()
    q = "SELECT fp,program,tool,rule,severity,host,url,score,suppressed,state FROM leads"
    cond, args = [], []
    if prog:
        cond.append("program=?"); args.append(prog)
    if not all_:
        cond.append("state='LEAD' AND (suppressed IS NULL OR suppressed='')")
    if cond:
        q += " WHERE " + " AND ".join(cond)
    q += " ORDER BY score DESC, first_seen DESC LIMIT ?"
    args.append(top)
    for fp, p, tool, rule, sev, host, url, sc, sup, state in con.execute(q, args):
        print(f"{fp[:16]}\t{p}\t{state}\t{sc}\t{sev}\t{tool}\t{rule}\t{host or url}{'  [' + sup + ']' if sup else ''}")
    con.close()
    return 0


def cmd_mark(fp, kind, why, rule_level=False):
    states = {"fp": "FP", "dupe": "DUPE", "verified-elsewhere": "HUMAN-VERIFIED-ELSEWHERE"}
    if kind not in states:
        print("kind must be fp|dupe|verified-elsewhere")
        return 2
    con = db()
    rows = con.execute("SELECT fp, program, rule FROM leads WHERE fp LIKE ?", (fp + "%",)).fetchall()
    if len(rows) != 1:
        print(f"{len(rows)} leads match {fp!r}; give more of the fp")
        return 2
    full, program, rule = rows[0]
    con.execute("UPDATE leads SET state=?, mark_note=? WHERE fp=?", (states[kind], f"{iso()} {why}", full))
    con.commit()
    if kind == "fp" and rule_level:
        ingest.gappend(os.path.join(SD, "fp-templates.txt"), f"{rule}  # {iso()} {program}: {why}\n", program, ROOT)
    ingest.render_seeds(program, ROOT, con)
    con.close()
    print(f"marked {full[:16]} {states[kind]}{' (rule appended to fp-templates.txt)' if rule_level and kind == 'fp' else ''}")
    return 0


def _pause_text():
    try:
        with open(PAUSE, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def cmd_drain(on):
    """drain: the daemon starts no new job, lets running ones finish, reports status "draining". undrain removes it."""
    os.makedirs(SD, exist_ok=True)
    if on:
        lib_state.atomic_write_text(DRAIN, f"{iso()} drain by bot.py drain\n")
        print("draining: no new job starts; running jobs finish (bot.py status shows running; bot.py undrain to end)")
    else:
        if os.path.exists(DRAIN):
            os.remove(DRAIN)
        print("undrained: the daemon schedules jobs again")
    return 0


def cmd_pause(on, ack_incident=False):
    os.makedirs(SD, exist_ok=True)
    if not on and _pause_text().startswith(INCIDENT_PREFIX) and not ack_incident:
        print("REFUSED: PAUSE is a scope-incident latch, not an ordinary pause:\n  " + _pause_text().strip()
              + "\n  read .claude/state/hunt-loop/SCOPE-INCIDENTS.md, then: bot.py resume --ack-incident")
        return 2
    if on:
        with open(PAUSE, "w", encoding="utf-8") as fh:
            fh.write(f"{iso()} paused by bot.py pause\n")
        print("paused")
    else:
        if os.path.exists(PAUSE):
            os.remove(PAUSE)
        print("resumed (a hunt-loop STOP, if present, still halts the bot)")
    return 0


def cmd_selfcheck():
    checks = [("lib_scope", [PY, os.path.join(ROOT, "scripts/bbtools/lib_scope.py")], "ALL ASSERTIONS PASS"),
              ("lib_policy", [PY, os.path.join(ROOT, "scripts/bbtools/lib_policy.py"), "--selfcheck"], "PASS"),
              ("scope_proxy", [PY, os.path.join(HERE, "scope_proxy.py"), "--selftest"], "PASS"),
              ("ingest", [PY, os.path.join(HERE, "ingest.py"), "--selfcheck"], "PASS")]
    ok_all = True
    for name, argv, want in checks:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=300)
        ok = p.returncode == 0 and want in p.stdout
        ok_all &= ok
        last = (p.stdout.strip().splitlines() or [p.stderr.strip()[-300:]])[-1]
        print(f"{'PASS' if ok else 'FAIL'} {name}: {last}")
    # bot.db CHECK constraint: no lead state outside the four allowed values can ever be stored
    import tempfile
    tmp = tempfile.mkdtemp(prefix="oss-bot-dbcheck-")
    try:
        con = ingest.db_connect(tmp)
        con.execute("INSERT INTO leads(fp,program) VALUES('a','px')")
        assert con.execute("SELECT state FROM leads WHERE fp='a'").fetchone()[0] == "LEAD"
        for bad in ("FINDING", "CRITICAL-CANDIDATE", "lead"):
            try:
                con.execute("UPDATE leads SET state=? WHERE fp='a'", (bad,))
                raise AssertionError(f"db accepted state {bad}")
            except sqlite3.IntegrityError:
                pass
        assert con.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        con.close()
        print("PASS bot.db: default state LEAD, CHECK rejects FINDING/CRITICAL-CANDIDATE/lead, WAL on")
    except AssertionError as e:
        ok_all = False
        print(f"FAIL bot.db: {e}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # jobs.py refuses a run dir outside the oss-bot locations (never reports/)
    p = subprocess.run([PY, os.path.join(HERE, "jobs.py"), "secrets", "program-60", "--run-dir",
                        os.path.join(ROOT, "reports", "drafts", "oss-bot-selfcheck"), "--dry"],
                       capture_output=True, text=True, timeout=60)
    ok = p.returncode != 0 and "PathGuardError" in p.stderr and not os.path.exists(
        os.path.join(ROOT, "reports", "drafts", "oss-bot-selfcheck"))
    ok_all &= ok
    print(f"{'PASS' if ok else 'FAIL'} jobs.py --run-dir under reports/ raises PathGuardError")
    print("SELFCHECK PASS" if ok_all else "SELFCHECK FAIL")
    return 0 if ok_all else 1


# ------------------------------------------------------------------ daemon (Phase 2 runs it under pm2)
def _secrets_changed(program, since):
    import jobs
    repos, plain = jobs.secret_dirs(program)
    newest = 0.0
    for d in repos + plain:
        try:
            newest = max(newest, os.path.getmtime(d), *(e.stat().st_mtime for e in os.scandir(d)))
        except (OSError, ValueError):
            continue
    return newest > (since or 0)


def _prune(program):
    keep_n = CFG["retention_runs"]
    by_job = {}
    for d in glob.glob(os.path.join(ingest.out_dir(program, ROOT), "runs", "*")):
        by_job.setdefault(os.path.basename(d).rsplit("-2", 1)[0], []).append(d)
    for job, ds in by_job.items():
        for d in sorted(ds, key=os.path.getmtime, reverse=True)[keep_n:]:
            for f in glob.glob(os.path.join(d, "*")):
                if os.path.basename(f) in ("meta.json", "cmd.txt", "egress.jsonl"):
                    continue
                ingest.guard(f, program, ROOT)
                shutil.rmtree(f) if os.path.isdir(f) else os.remove(f)


def cmd_daemon():
    con = db()
    _install_signals(con)
    dry = os.environ.get("OSS_BOT_DRY", "0") == "1"
    last_refresh, rows = 0.0, []
    while not _STOPFLAG["v"]:
        h = halted()
        if h:
            if _RUNNING:
                _terminate_all(con, h)
            atomic_state("paused", {"why": h})
        else:
            now = time.time()
            if now - last_refresh > 1800:
                rows, last_refresh = refresh_programs(con), now
            for (p, j), r in list(_RUNNING.items()):
                rc = r["proc"].poll()
                if rc is not None:
                    finalize(con, p, j, r, rc, delta=True)
                    _prune(p)
            draining = os.path.exists(DRAIN)
            busy = {p for p, _ in _RUNNING}
            n_net = sum(1 for _, j in _RUNNING if j != "secrets")
            n_loc = sum(1 for _, j in _RUNNING if j == "secrets")
            cands = []
            for r in ([] if draining else rows):
                for j in JOBS:
                    if (j == "secrets" and not r["secrets_ok"]) or (j != "secrets" and not r["network_ok"]):
                        continue
                    cad = CFG["cadence_h"][j][r["tier"]]
                    if cad is None:
                        continue
                    jr = con.execute("SELECT next_due,last_end FROM jobs WHERE program=? AND job=?",
                                     (r["program"], j)).fetchone()
                    nd, le = (jr or (None, None))
                    if nd is None:
                        nd = 0 if le is None else le + cad * 3600
                    if j == "secrets" and nd > now and not _secrets_changed(r["program"], le):
                        continue
                    if nd > now:
                        continue
                    if j in ("nuclei-fast", "nuclei-cve", "crawl") and not fresh_probe(r["program"]):
                        continue
                    cands.append((r["tier"], -((now - nd) / (cad * 3600 or 1)), r["program"], j))
            for tier, _, p, j in sorted(cands):
                if p in busy:
                    continue
                if j == "secrets":
                    if n_loc >= CFG["max_local_jobs"]:
                        continue
                    n_loc += 1
                else:
                    if n_net >= CFG["max_network_jobs"]:
                        continue
                    n_net += 1
                hosts = None
                df = os.path.join(SD, f"delta-{p}.txt")
                if j == "nuclei-fast" and os.path.isfile(df):
                    hosts = os.path.join(SD, f"delta-{p}.in")
                    os.replace(df, hosts)
                try:
                    start_job(con, p, j, tier, dry=dry, hosts=hosts)
                except ingest.PathGuardError as e:
                    # belt-and-suspenders on top of the program_table() filter above: one bad
                    # candidate must never take the whole daemon down (2026-10-21 crash-loop receipt)
                    with open(os.path.join(SD, "bot.log"), "a", encoding="utf-8") as lf:
                        lf.write(f"[{iso()}] daemon: refused to start {p}/{j}: {e}\n")
                busy.add(p)
            if not draining:
                hq_rebuild_tick(con)
            atomic_state("draining" if draining else "running", {"dry": dry})
        for _ in range(60):
            if _STOPFLAG["v"]:
                break
            time.sleep(1)
    _terminate_all(con, "daemon exit")
    atomic_state("stopped")
    return 0


def main(a):
    if not a or a[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    c = a[0]
    if c == "status":
        return cmd_status()
    if c == "plan":
        return cmd_plan(a[1] if len(a) > 1 else None)
    if c == "run" and len(a) >= 3:
        return cmd_run(a[1], a[2], dry="--dry" in a)
    if c == "proxytest" and len(a) >= 2:
        return cmd_proxytest(a[1])
    if c == "leads":
        top = int(a[a.index("--top") + 1]) if "--top" in a else 20
        prog = a[1] if len(a) > 1 and not a[1].startswith("--") else None
        return cmd_leads(prog, top, "--all" in a)
    if c == "mark" and len(a) >= 4:
        return cmd_mark(a[1], a[2], a[3], "--rule" in a)
    if c in ("pause", "resume"):
        return cmd_pause(c == "pause", ack_incident="--ack-incident" in a)
    if c in ("drain", "undrain"):
        return cmd_drain(c == "drain")
    if c == "selfcheck":
        return cmd_selfcheck()
    if c == "daemon":
        # RETIRED 2026-11-02. GreyNOC, verbatim: "No more orch bot or oss bot. Lets just have the gnoc
        # chat orchistrate everything when requested." The daemon was the unattended half: it ticked on
        # its own and produced LEADs with nobody watching. The read-only commands above (status, leads,
        # plan, selfcheck) are untouched, so every LEAD already on disk stays queryable; only the
        # self-driving loop is refused. `run` is gated on a live chat rather than refused, because it is
        # a scan a human asks for. Kept, not deleted, so it can be revived deliberately.
        unretire = "GNOC_OSS_BOT_UNRETIRE"
        if not os.environ.get(unretire):
            sys.stderr.write(
                "oss-bot daemon is RETIRED (2026-11-02): scanning runs only when asked, "
                "inside a gnoc chat session.\n"
                "  existing leads:  python3 scripts/oss-bot/bot.py leads <program>\n"
                "  one scan:        python3 scripts/oss-bot/bot.py run <program> <repo>\n"
                f"  override once:   {unretire}=1 (deliberate, unattended, not the house default)\n")
            return 78  # EX_CONFIG: a configuration refusal, not a crash
        return cmd_daemon()
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
