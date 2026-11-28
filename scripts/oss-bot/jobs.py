#!/usr/bin/env python3
"""jobs - the exact, reviewable tool invocations for oss-bot.

    jobs.py <job> <program> --run-dir D [--hosts FILE] [--dry] [--tier N]
    jobs: enum probe nuclei-fast nuclei-cve crawl secrets

Every job writes D/cmd.txt (exact argv, one line per tool), D/meta.json (versions, templates HEAD, policy,
tier, inputs/refused, per-tool rc, start/end) and raw output to D/<tool>.raw (never indexed by hq).
Network jobs (probe, nuclei-*, crawl) start scope_proxy.py per job and point every tool at it with BOTH the
proxy env vars and the tool's own proxy flag; every input host was already filtered by
lib_scope.program_allows. enum talks only to third-party passive sources (no target traffic, no proxy).
secrets is LOCAL ONLY: no proxy, no network, must succeed under `unshare -rn`; --no-verification is
mandatory (verification = credential USE, a hunter decision under SPINE 4, never a bot action).
Safety-relevant flags (do not drop): httpx no -fr; nuclei -pt http -ni -dr -duc + intrusive -etags;
katana -fs fqdn, not headless. The rate R is lib_policy's rps capped by config rps_cap.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import select
import shlex
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
from bbtools import lib_policy, lib_scope  # noqa: E402
import ingest  # noqa: E402

WS_ROOT = lib_scope.WS_ROOT
CFG = json.load(open(os.path.join(HERE, "config.json"), encoding="utf-8"))
BINS = CFG["bins"]
NET_JOBS = ingest.NET_JOBS
JOBS = ("enum",) + NET_JOBS + ("secrets",)
DENY_TPL = os.path.join(WS_ROOT, ".claude/state/oss-bot/deny-templates.txt")
NUCLEI_ETAGS = "dos,fuzz,fuzzing,intrusive,bruteforce,brute-force,default-login,osint,dast,headless"
NUCLEI_TAGS = "exposure,misconfig,takeover,config,disclosure,backup,logs"
KATANA_EXT = "png,jpg,jpeg,gif,svg,woff,woff2,ttf,css,ico,mp4"
OK_RC = {"gitleaks": (0, 1), "semgrep": (0, 1), "trufflehog": (0, 183)}
NICE = ["nice", "-n", "19", "ionice", "-c3"]
_CHILDREN: list[subprocess.Popen] = []


def _iso(t=None):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t if t is not None else time.time()))


def _kill_children(*_):
    for p in list(_CHILDREN):
        try:
            os.killpg(p.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
    deadline = time.time() + 10
    for p in list(_CHILDREN):
        try:
            p.wait(timeout=max(0.1, deadline - time.time()))
        except subprocess.TimeoutExpired:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass


def _on_signal(signum, _frame):
    _kill_children()
    sys.exit(128 + signum)


# ------------------------------------------------------------------ helpers
def version(tool):
    arg = {"gitleaks": ["version"], "trufflehog": ["--version"], "semgrep": ["--version"], "gau": ["--version"]}
    try:
        p = subprocess.run([BINS[tool]] + arg.get(tool, ["-version"]), capture_output=True, text=True, timeout=30,
                           stdin=subprocess.DEVNULL)
        txt = (p.stdout + "\n" + p.stderr)
    except Exception as e:
        return f"error:{type(e).__name__}"
    m = re.search(r"[Vv]ersion:?\s*(v?\d[\w.\-]*)", txt) or re.search(r"\b(v?\d+\.\d+\.\d+[\w.\-]*)", txt)
    return m.group(1) if m else (txt.strip().splitlines() or ["?"])[-1][:60]


def templates_head():
    try:
        p = subprocess.run(["git", "-C", CFG["templates"], "rev-parse", "HEAD"], capture_output=True, text=True,
                           timeout=20)
        return p.stdout.strip() if p.returncode == 0 else f"not-a-git-repo (rc {p.returncode})"
    except Exception as e:
        return f"error:{type(e).__name__}"


def filter_hosts(program, items):
    keep, refused = [], []
    for it in items:
        it = it.strip()
        if not it:
            continue
        ok, why = lib_scope.program_allows(it, program)
        (keep if ok else refused).append(it if ok else f"{it}\t{why}")
    seen, out = set(), []
    for k in keep:
        if k.lower() not in seen:
            seen.add(k.lower())
            out.append(k)
    return out, refused


def newest(program, job, fname, max_age_h=None):
    runs = sorted(glob.glob(os.path.join(ingest.out_dir(program), "runs", f"{job}-*", fname)),
                  key=os.path.getmtime, reverse=True)
    for f in runs:
        if max_age_h is None or time.time() - os.path.getmtime(f) < max_age_h * 3600:
            return f
    return None


def probe_urls(program, max_age_h=48):
    f = newest(program, "probe", "httpx.raw", max_age_h)
    if not f:
        return None
    return [r["url"] for r in ingest.parse_httpx(f) if r["url"]]


class Proxy:
    def __init__(self, program, run_dir, rps):
        self.p = subprocess.Popen([sys.executable, os.path.join(HERE, "scope_proxy.py"), "--program", program,
                                   "--port", "0", "--log", os.path.join(run_dir, "egress.jsonl"), "--rps", str(rps),
                                   "--max-conn-per-host", "4"], stdout=subprocess.PIPE, stdin=subprocess.DEVNULL,
                                  start_new_session=True, text=True)
        _CHILDREN.append(self.p)
        r, _, _ = select.select([self.p.stdout], [], [], 15)
        line = self.p.stdout.readline().strip() if r else ""
        if not line.startswith("PORT "):
            self.stop()
            raise RuntimeError(f"scope_proxy did not start: {line!r}")
        self.port = int(line.split()[1])
        self.url = f"http://127.0.0.1:{self.port}"

    def env(self):
        e = dict(os.environ)
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            e[k] = self.url
        e["NO_PROXY"] = e["no_proxy"] = ""
        return e

    def stop(self):
        try:
            os.killpg(self.p.pid, signal.SIGTERM)
            self.p.wait(timeout=10)
        except Exception:
            try:
                os.killpg(self.p.pid, signal.SIGKILL)
            except Exception:
                pass
        if self.p in _CHILDREN:
            _CHILDREN.remove(self.p)


def run_tool(tool, argv, env, wall_s, stdout_path=None, raw_mode=None):
    t0 = time.time()
    out = None
    if stdout_path:
        fd = os.open(stdout_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, raw_mode or 0o644)
        out = os.fdopen(fd, "w")
    # stdout is captured (not discarded) so a flag/parse error is diagnosable; only the tail is kept, and only
    # on failure. trufflehog's stdout IS its raw output and goes straight to the 0600 file instead.
    p = subprocess.Popen(argv, env=env, stdout=out or subprocess.PIPE,
                         stderr=subprocess.PIPE if out else subprocess.STDOUT,
                         stdin=subprocess.DEVNULL, start_new_session=True)
    _CHILDREN.append(p)
    timed_out = False
    o = e = b""
    try:
        o, e = p.communicate(timeout=max(1, wall_s))
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(p.pid, signal.SIGTERM)
        try:
            o, e = p.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            o, e = p.communicate()
    finally:
        if out:
            out.close()
        if p in _CHILDREN:
            _CHILDREN.remove(p)
    ok = p.returncode in OK_RC.get(tool, (0,))
    tail = ((o or b"") + (e or b"")).decode("utf-8", "replace")[-400:] if not ok else ""
    return {"tool": tool, "rc": p.returncode, "ok": ok, "timed_out": timed_out, "secs": round(time.time() - t0, 1),
            "output_tail_on_fail": tail}


# ------------------------------------------------------------------ argv builders (THE reviewable flags)
def rate_args(tool, r):
    """The Go tools parse -rl as an INTEGER per second ("3.0" = parse error, exit 2). A whole rps -> -rl N;
    a fractional rps (stated-limit halving gives 1.5, 2.5, 0.5) -> the exact per-minute equivalent, rounded
    DOWN (never faster than R): httpx/katana -rlm, nuclei -rl N -rld 1m (its -rlm is deprecated)."""
    r = float(r)
    if r >= 1 and r == int(r):
        return ["-rl", str(int(r))]
    per_min = str(max(1, int(r * 60)))
    return ["-rl", per_min, "-rld", "1m"] if tool == "nuclei" else ["-rlm", per_min]


def hdr_args(flag, pol):
    return [flag, f"{pol['header'][0]}: {pol['header'][1]}"] if pol.get("header") else []


def argv_httpx(D, R, P, pol):
    return [BINS["httpx"], "-l", f"{D}/hosts.in", "-json", "-sc", "-cl", "-title", "-td", "-server", "-ip", "-cname",
            "-hash", "md5", *rate_args("httpx", R), "-t", "5", "-timeout", "10", "-retries", "1", *hdr_args("-H", pol),
            "-http-proxy", P, "-no-color", "-silent", "-o", f"{D}/httpx.raw"]


def _deny_template_args():
    ids, paths = [], []
    try:
        for ln in open(DENY_TPL, encoding="utf-8"):
            ln = ln.split("#", 1)[0].strip()
            if ln:
                (paths if ln.endswith((".yaml", ".yml")) or "/" in ln else ids).append(ln)
    except OSError:
        pass
    return (["-eid", ",".join(ids)] if ids else []) + (["-et", ",".join(paths)] if paths else [])


def argv_nuclei(D, R, P, pol, cve=False):
    if cve:
        sel = ["-as", "-s", "high,critical"]
        rate = [*rate_args("nuclei", min(R, 2)), "-c", "3"]
    else:
        sel = ["-tags", NUCLEI_TAGS, "-s", "low,medium,high,critical"]
        rate = [*rate_args("nuclei", R), "-c", "5", "-bs", "10"]
    return [BINS["nuclei"], "-l", f"{D}/urls.in", "-pt", "http", *sel, "-etags", NUCLEI_ETAGS,
            *_deny_template_args(), "-ni", "-dr", "-duc", "-ss", "host-spray", *rate, "-timeout", "10",
            "-retries", "1", "-mhe", "15", *hdr_args("-H", pol), "-proxy", P, "-ud", CFG["templates"], "-jsonl",
            "-or", "-silent", "-nc", "-o", f"{D}/nuclei.raw"]


def argv_katana(D, R, P, pol):
    return [BINS["katana"], "-list", f"{D}/urls.in", "-d", "2", "-jc", "-kf", "all", "-fs", "fqdn",
            *rate_args("katana", min(R, 2)), "-c", "2", "-p", "1", "-timeout", "10", "-ct", "600", *hdr_args("-H", pol),
            "-proxy", P, "-ef", KATANA_EXT, "-sr", "-srd", f"{D}/responses", "-j", "-silent", "-o", f"{D}/katana.raw"]


# ------------------------------------------------------------------ jobs
def secret_dirs(program):
    t = os.path.join(WS_ROOT, "targets", program)
    repos, plain = [], []
    for d in ("src", "oss/src", "recon/src", "recon/source"):
        p = os.path.join(t, d)
        if not os.path.isdir(p):
            continue
        if os.path.isdir(os.path.join(p, ".git")):
            repos.append(p)
            continue
        for c in sorted(os.listdir(p)):
            cp = os.path.join(p, c)
            if os.path.isdir(os.path.join(cp, ".git")):
                repos.append(cp)
            elif os.path.isdir(cp):
                plain.append(cp)
    for d in ("recon/js", "hunts/js", "hunts/bundles", "hunts/auto-exposure/raw"):
        p = os.path.join(t, d)
        if os.path.isdir(p) and any(os.scandir(p)):
            plain.append(p)
    plain += sorted(p for p in glob.glob(os.path.join(t, "evidence", "js-recon-*")) if os.path.isdir(p))
    plain += sorted(p for p in glob.glob(os.path.join(t, "recon", "oss-bot", "runs", "crawl-*", "responses"))
                    if os.path.isdir(p))
    return repos, plain


def prune_store(d, max_mb):
    files = sorted((os.path.getmtime(f), os.path.getsize(f), f) for f in glob.glob(os.path.join(d, "**", "*"),
                                                                                  recursive=True) if os.path.isfile(f))
    total = sum(s for _, s, _ in files)
    for _, s, f in files:
        if total <= max_mb * 1024 * 1024:
            break
        os.remove(f)
        total -= s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("job", choices=JOBS)
    ap.add_argument("program")
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--hosts")
    ap.add_argument("--dry", action="store_true")
    ap.add_argument("--tier", type=int, default=2)
    a = ap.parse_args()
    job, program = a.job, a.program
    D = ingest.guard(a.run_dir, program)          # raises outside oss-bot locations (never reports/)
    if job == "secrets":
        os.umask(0o077)
    os.makedirs(D, exist_ok=True)
    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)
    if not os.path.isfile(os.path.join(WS_ROOT, "targets", program, "SCOPE.txt")):
        print(f"REFUSED {program}: no SCOPE.txt", file=sys.stderr)
        return 2
    pol = lib_policy.policy(program)
    if job != "secrets" and not pol["network_ok"]:
        print(f"REFUSED {program}/{job}: policy {pol['status']} network_ok=False ({pol['evidence']})", file=sys.stderr)
        return 2
    R = round(min(float(CFG["rps_cap"]), float(pol["rps"] or CFG["rps_default"])), 3)
    wall = CFG["wall_min"][job] * 60
    meta = {"job": job, "program": program, "tier": a.tier, "dry": a.dry, "started": _iso(), "ended": None,
            "policy": pol, "rps": R, "inputs": 0, "refused": 0, "refused_sample": [], "tools": [], "versions": {},
            "templates_head": None, "proxy_port": None}
    cmds = []

    def save_meta():
        ingest.gwrite(os.path.join(D, "meta.json"), json.dumps(meta, indent=1), program)

    def write_cmds():
        ingest.gwrite(os.path.join(D, "cmd.txt"), "".join(shlex.join(c) + "\n" for c in cmds), program)

    rc = 0
    deadline = time.time() + wall
    if job == "enum":
        apexes, refused = filter_hosts(program, lib_scope.wildcard_apexes(program))
        meta.update(inputs=len(apexes), refused=len(refused), refused_sample=refused[:20])
        for i, apex in enumerate(apexes):
            cmds.append([BINS["subfinder"], "-d", apex, "-silent", "-json", "-t", "10", "-timeout", "30", "-max-time",
                         "15", "-o", f"{D}/subfinder-{i}.raw"])
            cmds.append([BINS["gau"], "--subs", "--threads", "2", "--timeout", "30", "--providers",
                         "wayback,commoncrawl,otx", "--json", "--o", f"{D}/gau-{i}.raw", apex])
        meta["versions"] = {t: version(t) for t in ("subfinder", "gau")}
        write_cmds(); save_meta()
        if not a.dry:
            env = {k: v for k, v in os.environ.items() if k.lower() not in ("http_proxy", "https_proxy", "all_proxy")}
            for c in cmds:
                tool = os.path.basename(c[0])
                meta["tools"].append(run_tool(tool, c, env, deadline - time.time()))
                save_meta()
    elif job in NET_JOBS:
        if job == "probe":
            if a.hosts:
                items = open(a.hosts, encoding="utf-8").read().split()
            else:
                items = list(lib_scope.exact_hosts(program))
                ef = newest(program, "enum", "enum-hosts.txt")
                if ef:
                    items += open(ef, encoding="utf-8").read().split()
            keep, refused = filter_hosts(program, items)
            keep = keep[:CFG["host_cap"]["probe"]]
            ingest.gwrite(os.path.join(D, "hosts.in"), "".join(h + "\n" for h in keep), program)
        else:
            items = open(a.hosts, encoding="utf-8").read().split() if a.hosts else probe_urls(program)
            if items is None:
                print(f"NEEDS-PROBE {program}: no probe run < 48h", file=sys.stderr)
                return 3
            keep, refused = filter_hosts(program, items)
            keep = keep[:CFG["host_cap"][job]]
            ingest.gwrite(os.path.join(D, "urls.in"), "".join(u + "\n" for u in keep), program)
        meta.update(inputs=len(keep), refused=len(refused), refused_sample=refused[:20])
        tool = {"probe": "httpx", "crawl": "katana"}.get(job, "nuclei")
        meta["versions"] = {tool: version(tool)}
        if tool == "nuclei":
            meta["templates_head"] = templates_head()
        placeholder = "http://127.0.0.1:<PORT>"

        def build(P):
            if tool == "httpx":
                return argv_httpx(D, R, P, pol)
            if tool == "katana":
                return argv_katana(D, R, P, pol)
            return argv_nuclei(D, R, P, pol, cve=(job == "nuclei-cve"))
        if a.dry or not keep:
            cmds.append(build(placeholder))
            write_cmds(); save_meta()
        else:
            px = Proxy(program, D, R)
            try:
                meta["proxy_port"] = px.port
                c = build(px.url)
                cmds.append(c)
                write_cmds(); save_meta()
                meta["tools"].append(run_tool(tool, c, px.env(), deadline - time.time()))
            finally:
                px.stop()
            if tool == "katana" and os.path.isdir(os.path.join(D, "responses")):
                prune_store(os.path.join(D, "responses"), CFG["katana_store_mb"])
    else:  # secrets: local only, no proxy, no network
        repos, plain = secret_dirs(program)
        meta.update(inputs=len(repos) + len(plain), dirs={"repos": repos, "plain": plain})
        n = 0
        for r in repos:
            cmds.append(NICE + [BINS["gitleaks"], "git", r, "--report-format", "json", "--report-path",
                                f"{D}/gitleaks-{n}.raw", "--no-banner"])
            n += 1
        for p in plain:
            cmds.append(NICE + [BINS["gitleaks"], "dir", p, "--report-format", "json", "--report-path",
                                f"{D}/gitleaks-{n}.raw", "--no-banner"])
            n += 1
        th = NICE + [BINS["trufflehog"], "filesystem", *repos, *plain, "--json", "--no-verification", "--no-update",
                     "--concurrency", "2"] if (repos or plain) else None
        if th:
            cmds.append(th)
        sg = NICE + [BINS["semgrep"], "scan", "--config", os.path.join(HERE, "semgrep-rules") + "/", "--json",
                     "--metrics=off", "--disable-version-check", "--timeout", "30", "--max-target-bytes", "5000000",
                     "-o", f"{D}/semgrep.raw", *plain] if plain else None
        if sg:
            cmds.append(sg)
        meta["versions"] = {t: version(t) for t in ("gitleaks", "trufflehog", "semgrep")}
        write_cmds(); save_meta()
        if not a.dry:
            env = {k: v for k, v in os.environ.items() if k.lower() not in ("http_proxy", "https_proxy", "all_proxy")}
            env["SEMGREP_SEND_METRICS"] = "off"
            for c in cmds:
                tool = os.path.basename(c[len(NICE)])
                meta["tools"].append(run_tool(tool, c, env, deadline - time.time(),
                                              stdout_path=f"{D}/trufflehog.raw" if c is th else None, raw_mode=0o600))
                save_meta()
        for f in glob.glob(os.path.join(D, "*.raw")):
            os.chmod(f, 0o600)
    meta["ended"] = _iso()
    if any(not t["ok"] and not t["timed_out"] for t in meta["tools"]):
        rc = 1
    save_meta()
    print(json.dumps({"job": job, "program": program, "rc": rc, "inputs": meta["inputs"], "refused": meta["refused"],
                      "tools": [(t["tool"], t["rc"], t["timed_out"]) for t in meta["tools"]], "run_dir": D}))
    return rc


if __name__ == "__main__":
    sys.exit(main())
