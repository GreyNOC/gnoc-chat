"""gnoc_scan.py - the three standard authorized web-bug-bounty scanners (nuclei, ffuf, sqlmap), each fenced in code.

These are WEB application security scanners for a researcher's OWN authorized in-scope testing. Every fence is here
in code, none is left to the model:
  - lib_policy must say network work is allowed for the program AND its PROGRAM.md must carry no line that bans
    scanners / fuzzing / brute force (scanner_ban() below; any doubt blocks)
  - ONE in-scope URL per run (the agent scope-gates it); no host lists, no CIDR ranges
  - the request rate is the program's stated rate (lib_policy rps); the identification header is attached
  - fixed detection-only arguments: nuclei excludes dos/intrusive/fuzz/brute templates; sqlmap runs level 1 risk 1
    with NO data-dump, file, OS or query options reachable; ffuf auto-calibrates and stops on errors
  - The user approves every run in gnoc chat (skip-perms and /auto included - see gnoc_agent)
  - output is raw files under targets/<program>/hunts/gnoc-scan-<ts>/; every hit is a LEAD to reproduce by hand
Bug-bounty programs commonly ban automated scanning; that is why the ban check blocks rather than warns.
"""
import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GO = os.path.expanduser("~/go/bin")
WORDLISTS = {"common": "/usr/share/seclists/Discovery/Web-Content/common.txt",
             "raft-small": "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
             "api": "/usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt"}
# a line restricts the scanners when it names a scanning activity AND a prohibition (either order); any doubt blocks
_SCAN_WORD = re.compile(r"\b(scanner|scanning|automated (tool|scan|test)|automation|fuzz|brute[- ]?forc|nuclei|"
                        r"sqlmap|dirb|gobuster|ffuf|burp (scanner|intruder)|mass (scan|request))", re.I)
# no trailing \b: the prohibition verbs must match their inflections too (prohibit->prohibited,
# forbid->forbidden, disallow->disallowed, ban->banned), which a trailing \b silently blocks. The
# co-required scan-word on the same line keeps false positives bounded, and this gate fails safe.
_BAN_WORD = re.compile(r"\b(no|not|never|prohibit|forbid|disallow|ban|must not|do not|don't|avoid|"
                       r"strictly|off[- ]limits|out of bounds|without (prior|written) (approval|permission))", re.I)


def _ban_line(ln):
    return bool(_SCAN_WORD.search(ln) and _BAN_WORD.search(ln))
MAX_S = 1200


def _bin(name):
    p = shutil.which(name) or os.path.join(GO, name)
    return p if p and os.path.isfile(p) else None


def scanner_ban(program):
    """PROGRAM.md lines that restrict scanning / fuzzing / brute force. Any match blocks the scanners for safety."""
    try:
        with open(os.path.join(WS, "targets", program, "PROGRAM.md"), encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return ["no PROGRAM.md: the policy was never read, so scanning is not cleared"]
    return [" ".join(ln.split())[:200] for ln in text.splitlines() if _ban_line(ln)]


def _out(program, tool):
    d = os.path.join(WS, "targets", program, "hunts", f"gnoc-scan-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}-{tool}")
    os.makedirs(d, exist_ok=True)
    return d


def _hdr(pol):
    return f"{pol['header'][0]}: {pol['header'][1]}" if pol.get("header") else None


def _run(argv, out, timeout):
    with open(os.path.join(out, "command.txt"), "w") as f:
        f.write(" ".join(argv) + "\n")
    try:
        pr = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        code, text = pr.returncode, (pr.stdout or "") + (pr.stderr or "")
    except subprocess.TimeoutExpired as e:
        got = e.stdout or b""
        code = 124
        text = f"stopped at the {timeout}s cap\n" + (got.decode("utf-8", "replace") if isinstance(got, bytes) else got)
    with open(os.path.join(out, "output.txt"), "w") as f:
        f.write(text)
    return code, text


def nuclei(program, pol, url, severity="medium,high,critical", tags=None):
    """nuclei with the intrusive template classes excluded: detection and misconfiguration templates only."""
    exe = _bin("nuclei")
    if not exe:
        return "nuclei not installed"
    out = _out(program, "nuclei")
    rps = max(1, int(float(pol.get("rps") or 1)))
    argv = [exe, "-u", url, "-jsonl", "-o", os.path.join(out, "results.jsonl"), "-rl", str(rps), "-c", "5",
            "-bs", "5", "-severity", re.sub(r"[^a-z,]", "", severity or "medium,high,critical"),
            "-etags", "dos,intrusive,fuzz,brute-force,bruteforce", "-duc", "-ni", "-silent", "-nc", "-timeout", "10",
            # -dr: a template that follows a redirect lands on whatever host the target names, scope or not (QAQC r2)
            "-dr"]
    if tags:
        argv += ["-tags", re.sub(r"[^a-z0-9,_-]", "", tags.lower())]
    if _hdr(pol):
        argv += ["-H", _hdr(pol)]
    _run(argv, out, MAX_S)
    rows = []
    try:
        with open(os.path.join(out, "results.jsonl")) as fh:
            for ln in fh:
                r = json.loads(ln)
                info = r.get("info", {})
                rows.append(f"[{info.get('severity', '?').upper()}] {r.get('template-id')}  {r.get('matched-at')}  "
                            + info.get("name", "")[:80])
    except (OSError, ValueError):
        pass
    head = f"nuclei on {url} at {rps} req/s ({severity}; dos/intrusive/fuzz/brute excluded): "
    return head + (f"{len(rows)} hit(s), each a LEAD to reproduce by hand\n" + "\n".join(rows[:40]) if rows
                   else "no hits") + f"\nraw: {os.path.relpath(out, WS)}/"


def ffuf(program, pol, url, wordlist="common", extensions=""):
    """Content discovery: which paths exist. A 200 is not a finding (check content-type, length, a nonsense control)."""
    exe = _bin("ffuf")
    if not exe:
        return "ffuf not installed"
    import urllib.parse
    sp = urllib.parse.urlsplit(url)
    if "FUZZ" in (sp.scheme + "://" + sp.netloc):
        # the scope gate checked the literal host ("fuzz.acme.com"); every word would be a DIFFERENT host, never
        # checked (QAQC r2). Content discovery fuzzes the path, query or a header value, never the host.
        return "refused: FUZZ in the scheme/host part fuzzes hostnames the scope gate never saw; put it in the path"
    if "FUZZ" not in url:
        url = url.rstrip("/") + "/FUZZ"
    wl = WORDLISTS.get(wordlist, wordlist)
    # checked on the RESOLVED path: '/usr/share/../../etc/hostname' starts with /usr/share/ as a string, and a
    # secrets file named as the wordlist would be sent to the target line by line
    wl = os.path.realpath(str(wl or ""))
    if wordlist not in WORDLISTS and not (os.path.isfile(wl) and wl.startswith("/usr/share/")):
        return f"wordlist must be one of {', '.join(WORDLISTS)} or a file under /usr/share/"
    out = _out(program, "ffuf")
    rps = max(1, int(float(pol.get("rps") or 1)))
    argv = [exe, "-u", url, "-w", wl, "-rate", str(rps), "-t", "5", "-ac", "-se", "-sf", "-noninteractive",
            "-mc", "200,201,204,301,302,307,308,401,403,405,500", "-of", "json",
            "-o", os.path.join(out, "results.json"), "-s", "-timeout", "10", "-maxtime", str(MAX_S - 30)]
    if extensions:
        argv += ["-e", ",".join("." + e.strip(". ") for e in extensions.split(",") if e.strip())[:60]]
    if _hdr(pol):
        argv += ["-H", _hdr(pol)]
    _run(argv, out, MAX_S)
    try:
        with open(os.path.join(out, "results.json")) as fh:
            res = json.load(fh).get("results", [])
    except (OSError, ValueError):
        res = []
    rows = [f"{r.get('status')} {r.get('url')}  len={r.get('length')} words={r.get('words')}"
            for r in sorted(res, key=lambda r: (r.get("status"), r.get("url")))]
    try:
        with open(wl, errors="replace") as fh:
            n = sum(1 for _ in fh)
    except OSError:
        n = 0
    return (f"ffuf {url} with {os.path.basename(wl)} ({n} words, ~{round(n / rps / 60, 1)} min at {rps} req/s, "
            f"auto-calibrated): {len(rows)} path(s)\n" + "\n".join(rows[:60])
            + f"\nraw: {os.path.relpath(out, WS)}/  (a 200 is not a finding: verify content-type, length-differs, "
              "and a nonsense-path 404 control)")


def sqlmap(program, pol, url, param=None, data=None, method=None, cookie_header=None):
    """DETECTION ONLY: is a parameter injectable, and of what type. The argument list is fixed - no data retrieval,
    no file read/write, no OS access, no arbitrary query option can be passed through this wrapper."""
    exe = _bin("sqlmap")
    if not exe:
        return "sqlmap not installed"
    out = _out(program, "sqlmap")
    rps = max(1, int(float(pol.get("rps") or 1)))
    argv = [exe, "-u", url, "--batch", "--level", "1", "--risk", "1", "--delay", f"{1 / rps:.2f}", "--threads", "1",
            "--output-dir", out, "--disable-coloring", "--flush-session", "--smart", "--timeout", "15",
            "--retries", "1", "--answers", "follow=N,crawl=N,dump=N"]
    if param:
        argv += ["-p", re.sub(r"[^\w.-]", "", param)]
    if data:
        argv += ["--data", data]
    if method:
        argv += ["--method", re.sub(r"[^A-Z]", "", method.upper())]
    hdrs = [h for h in (_hdr(pol), cookie_header) if h]
    if hdrs:
        argv += ["--headers", "\\n".join(hdrs)]
    _, text = _run(argv, out, MAX_S)
    keep = [ln for ln in text.splitlines()
            if re.search(r"(is vulnerable|injectable|Parameter:|Type:|Title:|Payload:|back-end DBMS|"
                         r"not injectable|all tested parameters|WAF/IPS|CRITICAL|\[ERROR\])", ln)]
    injectable = bool(re.search(r"(is vulnerable|sqlmap identified the following injection)", text))
    verdict = ("INJECTABLE (LEAD: confirm by hand with one benign boolean or time pair, then stop)" if injectable
               else "no injection detected at level 1 / risk 1")
    return (f"sqlmap detection on {url}" + (f" param {param}" if param else "") + f": {verdict}\n"
            + "\n".join(keep[:40]) + f"\nraw: {os.path.relpath(out, WS)}/")
