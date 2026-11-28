#!/usr/bin/env python3
"""auto-target.py - pick the next program for auto-hunt, and intake it. No model, no cloud tokens.

  auto-target.py --remap <program>    rebuild the passive host map (subfinder, crt.sh, liveness)
  auto-target.py --pick [--write]     choose the best program; --write points AUTO-HUNT at it
  auto-target.py --intake <handle>    scope + policy pull (platform auto-detected), ban check, host map
  auto-target.py --rank               show the ranked candidates and why each is in or out

Ranking (first viable wins; both lists are already EV-ordered by hand or by the rank scripts), the
two lists INTERLEAVED so paid programs are never starved: VDP #1, paid #1, VDP #2, paid #2, ...
  .claude/state/hunt-loop/priority-vdp.txt   no-bounty VDPs (a verified finding can be auto-filed)
  .claude/state/hunt-loop/priority.txt       the paid rotation queue (findings are filed by hand)
A candidate is SKIPPED when it is in no-yield.txt, when its PROGRAM.md bans automation or AI agents
(T-156), when it is marked exhausted (every host swept), or when intake fails. Survivors keep the
hand-ranked list order, so a half-swept top program is finished before the next one is opened.

Intake dispatches by platform (h1-scope.sh / bugcrowd-scope.sh / intigriti-scope.sh) when SCOPE.txt
is missing, then, when the program has no host map yet, a PASSIVE map: certificate-transparency
names for each in-scope wildcard (crt.sh), resolved over DNS-over-HTTPS, RFC1918 answers dropped,
then ONE GET / per host (in-scope only, X-HackerOne header, no redirects) to record status and a
role guess. Output: targets/<program>/recon/unauth-map-auto-<date>/hosts.tsv, the format
auto-hunt.py consumes.

When both priority lists are exhausted, the rank-fallback re-ranks FRESH candidates straight from
the platforms (no token needed for Bugcrowd/Intigriti, an H1 API token for HackerOne) and auto-adds
the first one that survives every gate: H1 (uncapped, unchanged since before this platform
extension) -> Bugcrowd paid -> Intigriti paid -> Intigriti VDP (-> priority-vdp.txt; Bugcrowd has no
clean non-paying-only filter so it is paid-only here). The two new platforms are each capped to the
top RANK_TOPN ranked rows per refill (see the constant's comment) since, unlike H1's hand-tuned
~200-row list, Bugcrowd/Intigriti together surface ~490 raw public engagements and a failed
candidate's intake can be expensive (a full passive host-map build).
"""
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
STATE = os.path.join(WS, ".claude/state")
ORCH = os.path.join(STATE, "orch")
LISTS = [os.path.join(STATE, "hunt-loop/priority-vdp.txt"), os.path.join(STATE, "hunt-loop/priority.txt")]
NOYIELD = os.path.join(STATE, "hunt-loop/no-yield.txt")
RANK_COOLDOWN_S = 1800  # do not hit the ranking APIs more than once per 30 min when the lists are dry
RANKFB_STATE = os.path.join(ORCH, "rank-fallback.json")
# H1's own fresh-candidate list (api.hackerone.com/v1/hackers/programs) runs ~217 rows (verified
# 2026-10-21) and is left UNCAPPED below -- it already works fine in production because pick()
# returns on the FIRST candidate that survives intake, so the common case never walks far. Bugcrowd
# (298 public engagements) and Intigriti (191) are zero-auth, so a refill can reach them with no
# credential at all, but each failed candidate still costs a live scope-fetch call plus, when
# host_count()==0, a FULL passive host_map() build (subfinder/crt.sh enumeration + a GET per host).
# Capping each of these two NEW sources to its top RANK_TOPN ranked rows per refill bounds that
# worst case without changing H1's own (already-proven) uncapped behavior.
RANK_TOPN = 25
MAX_PER_DOMAIN, MAX_HOSTS = 250, 600
BAN_RE = re.compile(
    r"(automated (scanning|tools?|testing)|scanners?|bots?)[^.\n]{0,60}(prohibited|not (allowed|permitted)|forbidden|banned)"
    r"|(do not|don't|must not|may not)[^.\n]{0,30}(use )?(automated|scanners?|bots?)"
    r"|(prohibit|forbid|ban|not allow)[^.\n]{0,40}(ai agents?|llms?|large language|generative ai|third-party (llm|ai))"
    r"|(ai agents?|llms?|generative ai)[^.\n]{0,40}(prohibited|not (allowed|permitted)|forbidden|banned)", re.I)


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg):
    os.makedirs(ORCH, exist_ok=True)
    with open(os.path.join(ORCH, "orch.log"), "a") as f:
        f.write(f"[{now()}] auto-target: {msg}\n")
    print(msg, flush=True)


def inbox(kind, msg):
    with open(os.path.join(ORCH, "INBOX.md"), "a") as f:
        f.write(f"- [{now()}] **{kind}** {msg}\n")


def handles(path):
    out = []
    if os.path.isfile(path):
        for ln in open(path, encoding="utf-8", errors="replace"):
            ln = ln.strip()
            if ln and not ln.startswith("#"):
                h = re.split(r"[\s#]", ln, maxsplit=1)[0]
                if re.fullmatch(r"[A-Za-z0-9_.-]+", h):
                    out.append(h)
    return out


def banned(program):
    p = os.path.join(WS, "targets", program, "PROGRAM.md")
    if not os.path.isfile(p):
        return None
    m = BAN_RE.search(open(p, encoding="utf-8", errors="replace").read())
    return m.group(0)[:120] if m else None


def auto_state(program):
    try:
        return json.load(open(os.path.join(ORCH, f"auto-{program}.json")))
    except (OSError, ValueError):
        return {"swept": {}}


def host_count(program):
    """Same host list auto-hunt sweeps (unauth map, else the exact SCOPE.txt hosts). The old TSV-only count returned 0
    for every program without an unauth map, so pick() marked them exhausted before a single host was swept."""
    if not os.path.isfile(os.path.join(WS, "targets", program, "SCOPE.txt")):
        return 0
    import importlib.util
    spec = importlib.util.spec_from_file_location("autohunt", os.path.join(WS, "scripts/auto-hunt.py"))
    ah = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ah)
    try:
        return len(ah.hosts(program))
    except Exception:
        return 0


# ---------- intake ----------

def scope_lib(program):
    import importlib.util
    spec = importlib.util.spec_from_file_location("ob", os.path.join(WS, "scripts/orch-bot.py"))
    ob = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ob)
    pats = ob.scope_patterns(program)
    return pats, (lambda h: ob.in_scope(h, pats))


def doh(name):
    from curl_cffi import requests
    try:
        r = requests.get("https://cloudflare-dns.com/dns-query", params={"name": name, "type": "A"},
                         headers={"accept": "application/dns-json"}, timeout=10)
        return [a["data"] for a in r.json().get("Answer", []) if a.get("type") == 1]
    except Exception:
        return []


def _keep(n, domain):
    n = n.strip().lower().lstrip("*.")
    return n if (n == domain or n.endswith("." + domain)) and re.fullmatch(r"[a-z0-9.-]+", n) else None


def crt(domain):
    """Subdomains for a domain: subfinder (passive, multi-source) when installed, else crt.sh (retried, it
    is often overloaded), else Cert Spotter (rate-limited without a key)."""
    from curl_cffi import requests
    names = set()
    sf = os.path.expanduser("~/go/bin/subfinder")
    if os.path.isfile(sf):  # the primary source when installed
        try:
            r = subprocess.run([sf, "-d", domain, "-silent", "-max-time", "4"], capture_output=True, text=True, timeout=300)
            names |= {k for k in (_keep(n, domain) for n in r.stdout.split()) if k}
            log(f"subfinder {domain}: {len(names)} names")
        except Exception as e:
            log(f"subfinder {domain}: {str(e)[:80]}")
    if names:
        return sorted(names)
    for attempt in range(3):
        try:
            r = requests.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=90,
                             impersonate="chrome124")
            for row in r.json():
                names |= {k for k in (_keep(n, domain) for n in str(row.get("name_value", "")).split("\n")) if k}
            break
        except Exception as e:
            log(f"crt.sh {domain} try {attempt + 1}: {str(e)[:80]}")
            time.sleep(10 * (attempt + 1))
    if not names:
        try:
            r = requests.get("https://api.certspotter.com/v1/issuances", timeout=60,
                             params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"})
            rows = r.json()
            if not isinstance(rows, list):  # an error object such as {"code": "rate_limited"}
                raise RuntimeError(f"HTTP {r.status_code} {str(rows)[:60]}")
            for row in rows:
                names |= {k for k in (_keep(n, domain) for n in row.get("dns_names", [])) if k}
            log(f"certspotter {domain}: {len(names)} names")
        except Exception as e:
            log(f"certspotter {domain}: {str(e)[:80]}")
    return sorted(names)


def role_of(host):
    h = host.lower()
    if re.search(r"(^|[.-])(api|gateway|gw|graphql|rest|bff)([.-]|\d)", h):
        return "api-gateway"
    if re.search(r"(admin|internal|corp|intranet|vpn|jira|confluence|jenkins|gitlab|grafana|kibana|sso|okta|auth)", h):
        return "internal-corporate"
    if re.search(r"(^|[.-])(dev|stg|stage|staging|uat|qa|test|preprod|sandbox|beta)([.-]|\d)", h):
        return "nonprod"
    if re.search(r"(partner|owner|vendor|supplier|merchant|b2b)", h):
        return "owner-partner"
    return "guest-booking/other"


def handle():
    for ln in open(os.path.expanduser("~/.config/gnoc/secrets.env"), encoding="utf-8"):
        if ln.strip().startswith(("HACKERONE_HANDLE", "export HACKERONE_HANDLE")):
            return ln.split("=", 1)[1].strip().strip("'\"")
    return "greynoc"


def host_map(program):
    pats, in_scope = scope_lib(program)
    names = set(p for p in pats if not p.startswith("*."))
    for p in pats:
        if p.startswith("*."):
            got = crt(p[2:])
            log(f"{program}: crt.sh {p} -> {len(got)} names")
            names |= set(got[:MAX_PER_DOMAIN]) | {p[2:]}
            time.sleep(3)
    tp = re.compile(r"(^|\.)(github\.com|githubusercontent\.com|gitlab\.com|bitbucket\.org|npmjs\.(org|com)|pypi\.org|"
                    r"docker\.(io|com)|amazonaws\.com|cloudfront\.net|googleapis\.com|hackerone\.com)$", re.I)
    names = sorted(n for n in names if in_scope(n) and not tp.search(n))[:MAX_HOSTS * 2]  # never map third parties
    from curl_cffi import requests
    rows = []
    hdr = {"X-HackerOne": handle()}
    for n in names:
        ips = doh(n)
        pub = [i for i in ips if not ipaddress.ip_address(i).is_private]
        if not pub:
            continue
        if len(rows) >= MAX_HOSTS:
            break
        status, ln, ctype, server = "0", "0", "", ""
        for scheme in ("https", "http"):
            try:
                r = requests.get(f"{scheme}://{n}/", headers=hdr, impersonate="chrome124", timeout=12, allow_redirects=False)
                status, ln = str(r.status_code), str(len(r.content))
                ctype, server = r.headers.get("content-type", ""), r.headers.get("server", "")
                break
            except Exception:
                continue
        role = role_of(n) if status != "0" else "no-answer"
        rows.append([n, role, scheme if status != "0" else "", status, ln, ctype, server, ",".join(pub)])
        time.sleep(0.5)
    out = os.path.join(WS, "targets", program, "recon", f"unauth-map-auto-{datetime.now(timezone.utc):%Y%m%d}")
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "hosts.tsv"), "w") as f:
        f.write("host\trole\tscheme\tstatus\tlen\tctype\tserver\tips\n")
        for r in rows:
            f.write("\t".join(x.replace("\t", " ") for x in r) + "\n")
    answering = sum(1 for r in rows if r[3] != "0")
    log(f"{program}: host map {len(rows)} public hosts, {answering} answering -> {os.path.relpath(out, WS)}/hosts.tsv")
    return answering


# platform -> the scope-fetch script that turns a handle/arg into targets/<program>/SCOPE.txt.
# "arg" is what gets passed on the command line: for h1/bugcrowd it equals the program key; for
# intigriti it is the full "company/program" pair (intigriti-scope.sh itself reduces that to the
# program segment for the directory name, matching the "program" key used everywhere else here).
SCOPE_SCRIPT = {"h1": "scripts/h1-scope.sh", "bugcrowd": "scripts/bugcrowd-scope.sh",
                "intigriti": "scripts/intigriti-scope.sh"}


def intake(program, platform="h1", arg=None):
    arg = program if arg is None else arg
    tdir = os.path.join(WS, "targets", program)
    if not os.path.isfile(os.path.join(tdir, "SCOPE.txt")):
        script = SCOPE_SCRIPT.get(platform, SCOPE_SCRIPT["h1"])
        log(f"{program}: intake via {os.path.basename(script)} ({platform})")
        rc = subprocess.run([os.path.join(WS, script), arg], cwd=WS,
                            capture_output=True, text=True, timeout=300)
        if rc.returncode != 0 or not os.path.isfile(os.path.join(tdir, "SCOPE.txt")):
            log(f"{program}: intake FAILED ({(rc.stdout + rc.stderr).strip()[-200:]})")
            return False
    why = banned(program)
    if why:
        log(f"{program}: policy bans automation/AI ({why!r}); never auto-hunted")
        inbox("AUTO-TARGET", f"{program} skipped: PROGRAM.md bans automation or AI agents: \"{why}\"")
        return False
    if host_count(program) == 0:
        log(f"{program}: no host map yet, building a passive one")
        if host_map(program) == 0:
            inbox("AUTO-TARGET", f"{program}: intake found no answering public hosts; skipped")
            return False
    return True


# ---------- rank fallback (when the hand-curated lists are exhausted) ----------

def ranked_candidates():
    """Fresh HackerOne candidates beyond the hand-curated priority lists, via h1-rank-programs.sh
    --tsv (machine-readable: the pretty table's NOV column is multi-word and not safely
    whitespace-splittable). Returns handles best-first; caller still runs intake() on each (bans,
    rate, host map) - the ranker's EV score does not know about automation bans."""
    try:
        r = subprocess.run([os.path.join(WS, "scripts/h1-rank-programs.sh"), "--tsv"],
                           capture_output=True, text=True, timeout=120)
    except Exception as e:
        log(f"rank: h1-rank-programs.sh failed to run: {str(e)[:120]}")
        return []
    if r.returncode != 0:
        log(f"rank: h1-rank-programs.sh rc={r.returncode}: {(r.stdout + r.stderr).strip()[-200:]}")
        return []
    lines = r.stdout.splitlines()
    if not lines:
        return []
    header = lines[0].split("\t")
    try:
        hi = header.index("HANDLE")
    except ValueError:
        log("rank: --tsv header missing HANDLE column, cannot parse")
        return []
    out = []
    for ln in lines[1:]:
        cells = ln.split("\t")
        if len(cells) > hi and re.fullmatch(r"[A-Za-z0-9_.-]+", cells[hi]):
            out.append(cells[hi])
    return out


def _tsv_rows(cmd, col_name):
    """Run a rank script invoked with --tsv; return (column index, data lines) or (None, []) on any
    failure. Shared by the Bugcrowd/Intigriti rank-fallback sources below; mirrors the parsing
    ranked_candidates() already does for H1's own --tsv output (left untouched, not using this
    helper, so H1's behavior cannot regress from this change)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except Exception as e:
        log(f"rank: {os.path.basename(cmd[0])} failed to run: {str(e)[:120]}")
        return None, []
    if r.returncode != 0:
        log(f"rank: {os.path.basename(cmd[0])} rc={r.returncode}: {(r.stdout + r.stderr).strip()[-200:]}")
        return None, []
    lines = r.stdout.splitlines()
    if not lines:
        return None, []
    header = lines[0].split("\t")
    try:
        hi = header.index(col_name)
    except ValueError:
        log(f"rank: {os.path.basename(cmd[0])} --tsv header missing {col_name} column, cannot parse")
        return None, []
    return hi, lines[1:]


def bugcrowd_ranked_candidates(top_n=RANK_TOPN):
    """Fresh Bugcrowd candidates via bugcrowd-rank-programs.sh --tsv. Zero auth. The ranker's own
    default filters (no --all) already hard-require cash-paying + open + not banned/demo, so every
    row here is a paid candidate (see scripts/BUGCROWD.md) - no VDP split exists or is attempted.
    Returns (program, arg) pairs best-first, program == arg (single-segment handle), capped to
    top_n (see the RANK_TOPN comment for why this source is capped and H1 is not)."""
    hi, lines = _tsv_rows([os.path.join(WS, "scripts/bugcrowd-rank-programs.sh"), "--tsv"], "CODE")
    if hi is None:
        return []
    out = []
    for ln in lines:
        cells = ln.split("\t")
        if len(cells) > hi and re.fullmatch(r"[A-Za-z0-9_.-]+", cells[hi]):
            out.append((cells[hi], cells[hi]))
        if len(out) >= top_n:
            break
    return out


def intigriti_ranked_candidates(vdp=False, top_n=RANK_TOPN):
    """Fresh Intigriti candidates via intigriti-rank-programs.sh --tsv. Zero auth for
    confidentialityLevel=4 (fully public) programs. The ranker's default filter already requires
    confidentialityLevel=4 + maxBounty>0 (a paid candidate); --vdp INVERTS that last predicate to
    confidentialityLevel=4 + maxBounty==0, Intigriti's own equivalent of H1's offers_bounties==false
    - the one case where this platform cleanly distinguishes bounty vs non-paying the way H1 does,
    so it gets routed separately (see pick()). Returns (program, "company/program") pairs best-first,
    capped to top_n; program is the bare program segment, matching intigriti-scope.sh's own
    targets/<program>/ directory normalization (the directory is never targets/<company>/<program>/)."""
    cmd = [os.path.join(WS, "scripts/intigriti-rank-programs.sh")]
    if vdp:
        cmd.append("--vdp")
    cmd.append("--tsv")
    hi, lines = _tsv_rows(cmd, "COMPANY/PROGRAM")
    if hi is None:
        return []
    out = []
    for ln in lines:
        cells = ln.split("\t")
        if len(cells) <= hi or "/" not in cells[hi]:
            continue
        company, _, program = cells[hi].partition("/")
        if re.fullmatch(r"[A-Za-z0-9_.-]+", program) and re.fullmatch(r"[A-Za-z0-9_.-]+", company):
            out.append((program, cells[hi]))
        if len(out) >= top_n:
            break
    return out


def rank_cooldown_ok():
    try:
        last = json.load(open(RANKFB_STATE)).get("ts", 0)
    except (OSError, ValueError):
        last = 0
    return (time.time() - last) >= RANK_COOLDOWN_S


def rank_cooldown_touch():
    json.dump({"ts": time.time()}, open(RANKFB_STATE, "w"))


# ---------- pick ----------

def candidates():
    noy = set(handles(NOYIELD))
    seen, out = set(), []
    for rank_list, path in enumerate(LISTS):
        for i, h in enumerate(handles(path)):
            if h in seen:
                continue
            seen.add(h)
            out.append({"program": h, "list": os.path.basename(path), "pos": i, "vdp": rank_list == 0,
                        "noyield": h in noy})
    return out


def score(c):
    st = auto_state(c["program"])
    hosts = host_count(c["program"])
    swept = len(st.get("swept", {}))
    c.update(hosts=hosts, swept=swept, exhausted=st.get("exhausted", False), parked=st.get("parked", False),
             banned=banned(c["program"]), has_scope=os.path.isfile(os.path.join(WS, "targets", c["program"], "SCOPE.txt")))
    # lower is better: VDP list first, then the hand-ranked list order; a program is left only when it is
    # exhausted, banned or no-yield, so a half-swept top program is finished before the next is opened
    # interleaved: VDP #1, paid #1, VDP #2, paid #2 ... so paid programs are hunted too, not starved
    return (c["pos"], 0 if c["vdp"] else 1)


def pick(write=False):
    cs = candidates()
    for c in sorted(cs, key=score):
        p = c["program"]
        if c["noyield"] or c["exhausted"] or c["banned"] or c["parked"]:
            continue
        if not intake(p):
            continue
        if host_count(p) - len(auto_state(p).get("swept", {})) <= 0:
            st = auto_state(p)
            st["exhausted"] = True
            json.dump(st, open(os.path.join(ORCH, f"auto-{p}.json"), "w"), indent=1)
            continue
        log(f"picked {p} ({c['list']} #{c['pos'] + 1}, {host_count(p)} hosts, {c['swept']} swept)")
        if write:
            with open(os.path.join(ORCH, "AUTO-HUNT"), "w") as f:
                f.write(f"{p} target\n")
            inbox("AUTO-TARGET", f"auto-hunt now on {p} ({c['list']} #{c['pos'] + 1}); chosen by auto-target.py")
        return p

    log("priority lists exhausted - ranking fresh candidates (paid-rotation fallback)")
    if not rank_cooldown_ok():
        log("rank: cooldown active (checked within the last 30 min), not re-querying the ranking APIs yet")
        return None
    rank_cooldown_touch()
    noy = set(handles(NOYIELD))
    known = {c["program"] for c in cs}  # already in either list, any status - never re-add a dupe

    def try_source(label, pairs, list_path, platform):
        """Walk one platform's ranked (program, arg) pairs; intake + gate-check each exactly like
        the hand-curated loop above (no-yield, PROGRAM.md ban, host_count); first survivor is
        appended to list_path and returned. Same gates for every platform - nothing here is looser
        for Bugcrowd/Intigriti than what H1 candidates already go through."""
        for h, arg in pairs:
            if h in known or h in noy:
                continue
            if not intake(h, platform=platform, arg=arg):  # screens bans (T-156) and builds the host map
                continue
            if host_count(h) == 0:
                continue
            with open(list_path, "a") as f:
                f.write(f"{h}  # auto-added {now()} by auto-target.py rank fallback"
                        f" ({label}, lists were exhausted)\n")
            log(f"rank fallback: intook and picked fresh {label} program {h}")
            inbox("AUTO-TARGET", f"priority lists were exhausted; ranked fresh {label} candidates and intook {h}")
            if write:
                with open(os.path.join(ORCH, "AUTO-HUNT"), "w") as f:
                    f.write(f"{h} target\n")
            return h
        return None

    # Phase order: H1 first (identical function/loop/target-list as before this change - its
    # ranking and gating cannot regress), then the two new zero-auth platforms. Bugcrowd and
    # Intigriti-paid both route to the paid queue (LISTS[1]); Intigriti-VDP (the one source that
    # cleanly distinguishes non-paying the way H1's offers_bounties flag does - see
    # intigriti_ranked_candidates()) routes to the VDP queue (LISTS[0]), the only place this
    # fallback ever touches priority-vdp.txt.
    for label, pairs, list_path, platform in (
        ("H1",            [(h, h) for h in ranked_candidates()], LISTS[1], "h1"),
        ("Bugcrowd",      bugcrowd_ranked_candidates(),           LISTS[1], "bugcrowd"),
        ("Intigriti",     intigriti_ranked_candidates(vdp=False), LISTS[1], "intigriti"),
        ("Intigriti VDP", intigriti_ranked_candidates(vdp=True),  LISTS[0], "intigriti"),
    ):
        picked = try_source(label, pairs, list_path, platform)
        if picked:
            return picked

    log("no viable program left even after ranking fresh H1/Bugcrowd/Intigriti candidates")
    inbox("AUTO-TARGET", "priority lists exhausted AND fresh ranking across H1, Bugcrowd and Intigriti "
                         "found nothing new/viable either; add handles by hand or check no-yield.txt / "
                         "PROGRAM.md bans.")
    return None


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    os.makedirs(ORCH, exist_ok=True)
    # HUNTING IS BOUND TO A LIVE gnoc chat (GreyNOC, 2026-11-02). --pick rotated the target on its own
    # for the retired orch-bot; --remap and --intake reach the network. --rank is read-only and open.
    if argv[0] in ("--pick", "--remap", "--intake"):
        sys.path.insert(0, os.path.join(WS, "scripts"))
        import gnoc_session
        ok, why = gnoc_session.require(f"auto-target {argv[0]}")
        if not ok:
            sys.exit(why)
    if argv[0] == "--rank":
        for c in sorted(candidates(), key=score):
            why = ("no-yield" if c["noyield"] else "exhausted" if c["exhausted"] else "parked (gnoc pivot)" if c["parked"] else
                   f"BANNED: {c['banned'][:60]}" if c["banned"] else "needs intake" if not c["has_scope"] else "ok")
            print(f"  {'VDP ' if c['vdp'] else 'paid'} {c['program']:<34} hosts={c['hosts']:<4} swept={c['swept']:<4} {why}")
        return 0
    if argv[0] == "--remap" and len(argv) > 1:  # passive OSINT refresh (subdomains + liveness) into a new host map
        if not os.path.isfile(os.path.join(WS, "targets", argv[1], "SCOPE.txt")):
            print(f"{argv[1]}: no SCOPE.txt")
            return 1
        n = host_map(argv[1])
        print(f"{argv[1]}: remap done, {n} answering hosts")
        return 0 if n else 1
    if argv[0] == "--intake" and len(argv) > 1:
        return 0 if intake(argv[1]) else 1
    if argv[0] == "--pick":
        return 0 if pick("--write" in argv) else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
