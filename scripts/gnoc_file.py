"""/file - the user's typed filing command inside gnoc chat. HUMAN ONLY.

The user 2026-11-25, verbatim: "yes build /file". The standing rule it serves (CLAUDE.md, SUBMISSION IS
APPROVAL-GATED): every report goes to them as the exact final text first and is filed only on their explicit
approval of that item. Here the approval is the phrase `FILE <slug>`, typed by them at a real terminal right
after the exact payload was printed.

THE MODEL CAN NEVER FILE. This module is not a tool (nothing here is in TOOLS), it has no __main__ entry,
BASH_DENY refuses any shell command that runs or imports it, run() refuses unless the caller asserts the line
was typed (gnoc_core.commands only asserts that for the exact line object the REPL read from the keyboard),
and the default confirmation reads a fresh line from a TTY after flushing anything already buffered (a pasted
block that carries the phrase is thrown away, not read as the answer).

Flow: resolve reports/drafts/<program>/<slug> -> filability first (venue, already filed, filing channel,
required custom fields T-249, signal gate T-254) -> local gates (HELD, GATES.md, unrun stamps, FORM.md vs
header, submit-qaqc on the sanitized text, attachments, raw Burp panels) -> credentials -> read-only H1
lookups (structured scope, weakness) -> self-dedup T-244 -> the exact payload -> `FILE <slug>` -> POST ->
reports/submitted/<program>/<id>-<slug>/ + RECEIPT.md -> read-back diff T-253 -> ships ledger.

The Hacker API create carries no attachments and no custom fields (scripts/H1-SUBMIT.md), so attachments and
Burp panels are listed for the user to add by hand right after filing; the read-back says what is missing.
"""
import base64
import contextlib
import datetime
import glob
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import time

WS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRAFTS = os.path.join(WS, "reports", "drafts")
SUBMITTED = os.path.join(WS, "reports", "submitted")
TARGETS = os.path.join(WS, "targets")
SECRETS = os.path.expanduser("~/.config/gnoc/secrets.env")
API = "https://api.hackerone.com/v1/hackers"
H1_SUBMIT = os.path.join(WS, "scripts", "h1-submit-report.py")
HUNT_STATE = os.path.join(WS, "scripts", "hunt-state.py")

DEFAULT_TOKEN_ENV = "HACKERONE_API_TOKEN"
DEFAULT_HANDLE_ENV = "HACKERONE_HANDLE"
ATTACH_CAP = 50 * 1024
USAGE = ("usage: /file <draft-dir | program/slug> [--dry-run] [--token-env NAME] [--allow-missing-panels]")

# the same split bundle-report.py makes: these files are ours, not the triager's
_INTERNAL = re.compile(r"^(GATES\.md|FORM\.md|KILLPASS.*|REPRO-CHECK.*|REPRO-RUN.*|PIPELINE\.md|SELFDUP.*|DRYRUN.*"
                       r"|AUTOFIX.*|.*-auto\.txt|HELD-REASON\.md|TODO-.*|SELF-DUP-OK\.txt|SUBMITTED\.md|RECEIPT.*"
                       r"|FILE-BY-HAND.*|H1-FORM-BODY.*|.*\.bak.*|.*\.part|report\.md)$", re.I)
_ATTACHABLE = re.compile(r"^(repro\.sh|capture\.log|attacker\.\w+|poc\.\w+|README\.md)$"
                         r"|\.(png|jpe?g|gif|webp|mp4|webm|mov)$", re.I)
_SECRET_NAME = re.compile(r"(^\.env(\..*)?$|secrets?\.env$|\.key$|\.pem$|\.p12$|\.pfx$|id_rsa|id_ed25519|"
                          r"^ACCOUNTS\.md$|\.token$|cookies?\.(txt|json)$|session.*\.json$|credentials?(\.|$)|"
                          r"storage[-_]?state.*\.json$|\.netrc$)", re.I)
_PANEL = re.compile(r"\.png$", re.I)
# T-249: a policy that names HackerOne form fields the API cannot fill. The ring/audible/acme "Custom Field
# `Bypass Reference`" is optional (bypass reports only), so a bare mention of a custom field is not enough.
_CUSTOM_FIELDS = re.compile(r"required custom fields?|custom fields?\b[^.\n]{0,60}\b(?:required|mandatory|must be "
                            r"(?:filled|completed))|\*\*Affected (?:URL|Version\(s\))s?:?\*\*|\bSandbox ID\b", re.I)
_STAMP = re.compile(r"^(Gate|Dedup):\s*(.+)$", re.M)     # gnoc_gates.claim_checks' unrun-stamp rule
_UNRUN = re.compile(r"NOT-YET-RUN", re.I)
_EXCUSED = re.compile(r"\s*\(")
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")

_SLEEP = time.sleep          # tests make the read-back retry instant


class Refused(Exception):
    """A gate said no. Nothing was sent."""


# ---------------------------------------------------------------- the shared H1 code (h1-submit-report.py)

_H1MOD = [None]


def _h1mod():
    """scripts/h1-submit-report.py as a module: its report parser, QAQC runner, scope resolver, self-dedup gate
    and Basic-auth session are reused, not rewritten. Its main() is never called."""
    if _H1MOD[0] is None:
        spec = importlib.util.spec_from_file_location("h1_submit_report", H1_SUBMIT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _H1MOD[0] = mod
    return _H1MOD[0]


def _quiet(fn, *a, **kw):
    """Run an h1-submit-report helper: its die() prints to stderr and exits. Both become a Refused with the
    message, and whatever it printed to stdout is returned for display."""
    out, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            res = fn(*a, **kw)
    except SystemExit:
        raise Refused((err.getvalue().strip() or out.getvalue().strip() or "aborted").replace("ABORT: ", ""))
    return res, out.getvalue()


def _make_h1(handle, token):
    return _h1mod().H1(handle, token)


# ---------------------------------------------------------------- secrets: names in, values never out

class _Creds:
    def __init__(self, handle, token, handle_env, token_env):
        self.handle, self.token, self.handle_env, self.token_env = handle, token, handle_env, token_env

    def forms(self):
        """Every spelling of the token that could leak: the value and the Basic header payload."""
        out = [self.token]
        with contextlib.suppress(Exception):
            out.append(base64.b64encode(f"{self.handle}:{self.token}".encode()).decode())
        return [f for f in out if f]


def _read_env_file(path):
    env = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for ln in fh:
                ln = ln.strip()
                if ln and not ln.startswith("#") and "=" in ln:
                    k, v = ln.split("=", 1)
                    env[k.replace("export ", "").strip()] = v.strip().strip("'\"")
    except OSError:
        pass
    return env


def _handle_env_for(token_env):
    if token_env == DEFAULT_TOKEN_ENV:
        return DEFAULT_HANDLE_ENV
    for suf in ("_API_TOKEN", "_TOKEN"):
        if token_env.endswith(suf):
            return token_env[:-len(suf)] + "_HANDLE"
    return token_env + "_HANDLE"


def load_creds(token_env=None):
    """(creds) from secrets.env (then the process environment). The handle variable for a non-default token is
    the token's name with _API_TOKEN/_TOKEN replaced by _HANDLE: a token for another account must never be sent
    with OUR handle."""
    token_env = token_env or DEFAULT_TOKEN_ENV
    handle_env = _handle_env_for(token_env)
    env = _read_env_file(SECRETS)
    token = env.get(token_env) or os.environ.get(token_env) or ""
    handle = env.get(handle_env) or os.environ.get(handle_env) or ""
    if not token:
        raise Refused(f"{token_env} is not set in secrets.env or the environment")
    if not handle:
        raise Refused(f"{handle_env} (the H1 handle for {token_env}) is not set in secrets.env or the environment")
    with contextlib.suppress(Exception):
        import gnoc_secrets
        gnoc_secrets.register_extra(token_env, token)   # every later redact() knows it too
    return _Creds(handle, token, handle_env, token_env)


def _scrub(text, creds=None, redact=True):
    """The H1 token (and its Basic-auth form) out of any text; redact=True also runs gnoc_secrets.redact, which is
    right for error text and wrong for the payload display (that must show the bytes that will be sent)."""
    t = str(text or "")
    if creds is not None:
        for f in creds.forms():
            t = t.replace(f, f"[REDACTED:{creds.token_env}]")
    if redact:
        with contextlib.suppress(Exception):
            import gnoc_secrets
            t = gnoc_secrets.redact(t)
    return t


# ---------------------------------------------------------------- arguments and the draft

def parse_args(rest):
    if "\n" in (rest or "") or "\r" in (rest or ""):
        raise Refused("one line only: a /file line with more lines under it is a paste, not a command")
    words = (rest or "").split()
    opts = {"target": None, "dry_run": False, "token_env": None, "allow_missing_panels": False}
    i = 0
    while i < len(words):
        w = words[i]
        if w == "--dry-run":
            opts["dry_run"] = True
        elif w == "--allow-missing-panels":
            opts["allow_missing_panels"] = True
        elif w == "--token-env" or w.startswith("--token-env="):
            if "=" in w:
                name = w.split("=", 1)[1]
            else:
                i += 1
                name = words[i] if i < len(words) else ""
            if not _ENV_NAME.match(name or ""):
                raise Refused(f"--token-env needs a variable NAME (A-Z, 0-9, _), got {name!r}")
            opts["token_env"] = name
        elif w.startswith("-"):
            raise Refused(f"unknown flag {w!r}. {USAGE}")
        elif opts["target"] is None:
            opts["target"] = w
        else:
            raise Refused(f"one draft per /file, got a second argument {w!r}. {USAGE}")
        i += 1
    if not opts["target"]:
        raise Refused(USAGE)
    return opts


def resolve_draft(arg):
    """(dir, program, slug) for a draft under reports/drafts/<program>/<slug>; anything else is refused."""
    cands = []
    a = os.path.expanduser(arg)
    if os.path.isabs(a):
        cands.append(a)
    else:
        cands += [os.path.join(WS, a), os.path.join(DRAFTS, a), os.path.join(os.getcwd(), a)]
    for c in cands:
        if os.path.isfile(c) and os.path.basename(c) == "report.md":
            c = os.path.dirname(c)
        if not os.path.isdir(c):
            continue
        real, root = os.path.realpath(c), os.path.realpath(DRAFTS)
        rel = os.path.relpath(real, root).split(os.sep)
        if real.startswith(root + os.sep) and len(rel) == 2 and ".." not in rel:
            if not os.path.isfile(os.path.join(real, "report.md")):
                raise Refused(f"no report.md in {os.path.relpath(real, WS)}")
            return real, rel[0], rel[1]
        raise Refused(f"{arg} is not a draft directory: /file takes reports/drafts/<program>/<slug> only")
    raise Refused(f"no draft {arg!r} (reports/drafts/<program>/<slug>, or program/slug)")


def _read(p):
    try:
        with open(p, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def read_form(d):
    """FORM.md's leading 'Key: value' block (Title, Asset, CWE, CVSS, Venue), or {}."""
    out = {}
    for ln in _read(os.path.join(d, "FORM.md")).splitlines():
        if not ln.strip():
            if out:
                break
            continue
        m = re.match(r"^([A-Za-z][A-Za-z ]{0,30}):\s*(.*)$", ln)
        if not m:
            break
        out[m.group(1).strip().lower()] = m.group(2).strip()
    return out


def _norm(s):
    return " ".join(str(s or "").split())


def attachments(d):
    """([(name, bytes)] top-level files a triager gets, [(relpath, bytes)] Burp panel PNGs, [secret-named files])."""
    att, secret = [], []
    for name in sorted(os.listdir(d)):
        p = os.path.join(d, name)
        if not os.path.isfile(p) or name.startswith("."):
            continue
        if _SECRET_NAME.search(name):
            secret.append(name)
            continue
        if _INTERNAL.match(name) or not _ATTACHABLE.search(name):
            continue
        att.append((name, os.path.getsize(p)))
    top = {n for n, _ in att}
    panels = []
    for dp, dn, fn in os.walk(d):
        dn[:] = sorted(x for x in dn if not x.startswith(".") and x not in ("__pycache__", "node_modules"))
        for f in sorted(fn):
            rel = os.path.relpath(os.path.join(dp, f), d)
            if _PANEL.search(f) and rel not in top:
                panels.append((rel, os.path.getsize(os.path.join(dp, f))))
    return att, panels, secret


def _severity_from_cvss(cvss):
    m = re.search(r"([0-9]+(?:\.[0-9])?)\b", re.sub(r"CVSS:(?:3\.[01]|4\.0)/[A-Z:/]+", "", cvss or ""))
    if not m:
        return None, None
    sc = float(m.group(1))
    return ("critical" if sc >= 9 else "high" if sc >= 7 else "medium" if sc >= 4 else "low"), sc


def _vector(cvss):
    m = re.search(r"CVSS:(?:3\.[01]|4\.0)/[A-Z:/]+", cvss or "")
    return m.group(0) if m else ""


def _section(text, name):
    """The '## <name>' section of the report, heading included, or ''."""
    m = re.search(rf"(?ms)^##\s*{name}\s*$.*?(?=^##\s|\Z)", text or "", re.I)
    return m.group(0).strip("\n") if m else ""


# ---------------------------------------------------------------- the gates

def _venue(program):
    import gnoc_pay
    return gnoc_pay._venue(program)


def _team(program):
    import gnoc_pay
    return gnoc_pay.h1_team(program, refresh=True) or {}


def _signal_gate(program):
    import gnoc_pay
    return gnoc_pay.filing_gate(program, offline=True)


def filability(program, slug, opts, out):
    """Can THIS account file THIS program at all? Checked before any local gate, credential or H1 call."""
    venue = _venue(program)
    if venue != "hackerone":
        raise Refused(f"{program} is not a confirmed HackerOne program (venue {venue!r}); /file only files to H1")
    done = sorted(glob.glob(os.path.join(SUBMITTED, program, f"*-{slug}", "RECEIPT.md"))
                  + glob.glob(os.path.join(SUBMITTED, program, slug, "SUBMITTED.md"))
                  + glob.glob(os.path.join(SUBMITTED, program, slug, "RECEIPT.md")))
    if done:
        raise Refused(f"already filed: {os.path.relpath(os.path.dirname(done[0]), WS)}")
    other_account = bool(opts.get("token_env")) and opts["token_env"] != DEFAULT_TOKEN_ENV
    channel = os.path.join(TARGETS, program, "FILING-CHANNEL.md")
    if os.path.isfile(channel):
        head = " ".join(_read(channel).split())[:260]
        if not other_account:
            raise Refused(f"targets/{program}/FILING-CHANNEL.md names another filing channel; this account does "
                          f"not file {program}. Pass --token-env <NAME> for that account's token if it is in "
                          f"secrets.env, otherwise file through that researcher. ({head})")
        out(f"  filing channel: targets/{program}/FILING-CHANNEL.md, filing with the account behind "
            f"{opts['token_env']}")
    for name in ("PROGRAM.md", "policy.md", "POLICY.md"):
        m = _CUSTOM_FIELDS.search(_read(os.path.join(TARGETS, program, name)))
        if m:
            raise Refused(f"{program} requires custom form fields the Hacker API cannot send (T-249: "
                          f"targets/{program}/{name} says {_norm(m.group(0))!r}). File by hand in the web form.")
    try:
        team = _team(program)
    except Exception as e:  # noqa: BLE001 - an unreadable platform is a note, the same as h1-submit-report
        team = {}
        out(f"  team flags not read ({type(e).__name__}); T-254 checked from the cache only")
    if team.get("submission_requirements"):
        raise Refused(f"{program} has HackerOne submission requirements enabled (custom fields, T-249). "
                      "File by hand in the web form.")
    try:
        ok, why = _signal_gate(program)
    except Exception as e:  # noqa: BLE001
        ok, why = True, f"signal gate not checked ({type(e).__name__})"
    if not ok:
        if other_account and os.path.isfile(channel):
            out(f"  signal gate (OUR account, informational for {opts['token_env']}): {why}")
        else:
            raise Refused(f"signal gate (T-254): {why}")
    else:
        out(f"  signal gate: ok - {why}")
    return team


def local_gates(d, program, opts, out):
    """Every file-only gate, all reported at once. Returns the parsed report and the attachment lists."""
    fails = []
    if os.path.isfile(os.path.join(d, "HELD-REASON.md")):
        unlock = re.search(r"\*\*Unlock:.*", _read(os.path.join(d, "HELD-REASON.md")))
        fails.append("HELD: HELD-REASON.md is present" + (f" ({_norm(unlock.group(0))[:140]})" if unlock else ""))
    if os.path.isfile(os.path.join(d, "FILE-BY-HAND.md")):
        fails.append("FILE-BY-HAND.md is present: the program needs custom fields (T-249), file by hand")
    panel_flags = []
    for ln in _read(os.path.join(d, "GATES.md")).splitlines():
        if "PENDING-PANELS" in ln or ("NOT-YET-RUN" in ln and re.search(r"panel|burp", ln, re.I)):
            panel_flags.append(_norm(ln)[:140])
        elif "NOT-YET-RUN" in ln:
            fails.append(f"GATES.md: a gate has not run: {_norm(ln)[:140]}")
    raw = _read(os.path.join(d, "report.md"))
    for k, v in _STAMP.findall(raw):
        for m in _UNRUN.finditer(v):
            if not _EXCUSED.match(v, m.end()):
                fails.append(f"report.md stamp says it never ran: {k}: {_norm(v)[:120]}")
    att, panels, secret = attachments(d)
    if secret:
        fails.append("credential-named file(s) in the package: " + ", ".join(secret))
    for name, n in att:
        if n > ATTACH_CAP:
            fails.append(f"attachment {name} is {n} bytes, over the {ATTACH_CAP // 1024}KB cap")
    if panel_flags and not opts["allow_missing_panels"]:
        fails.append("raw Burp panels not captured (GATES.md: " + panel_flags[0]
                     + "); capture them, or type --allow-missing-panels")
    if len(panels) < 2 and not opts["allow_missing_panels"]:
        fails.append(f"raw Burp panels: {len(panels)} PNG(s) in the package, need a request+response pair "
                     "(or type --allow-missing-panels)")
    rep = None
    try:
        rep, _ = _quiet(_h1mod().parse_report, os.path.join(d, "report.md"))
    except Refused as e:
        fails.append(f"report.md: {e}")
    if rep:
        hdr = rep["header"]
        sev, _ = _severity_from_cvss(hdr.get("CVSS", ""))
        if not sev:
            fails.append("no parseable CVSS score in the CVSS: header")
        form = read_form(d)
        for key, have in (("title", rep["title"]), ("asset", hdr.get("Asset", "")), ("cwe", hdr.get("CWE", "")),
                          ("cvss", hdr.get("CVSS", ""))):
            if key in form and form[key] and _norm(form[key]) != _norm(have):
                fails.append(f"FORM.md {key} differs from report.md: {form[key][:80]!r} vs {have[:80]!r}")
        try:
            (ok, why), qa_out = _quiet(_h1mod().run_qaqc, rep["clean_text"], False)
        except Refused as e:
            ok, why, qa_out = False, str(e), ""
        if not ok:
            fails.append(f"submit-qaqc: {why}")
            out("\n".join(l for l in qa_out.splitlines() if l.strip().startswith(("FAIL", "BLOCKED"))))
    if fails:
        raise Refused("pre-filing gates failed:\n" + "\n".join(f"    - {f}" for f in fails))
    return rep, att, panels


def _resolve_weakness(h1, program, cwe_header):
    weaknesses, _ = _quiet(h1.get_all, f"{API}/programs/{program}/weaknesses")
    m = re.search(r"CWE-(\d+)", cwe_header or "", re.I)
    if not m:
        raise Refused("no CWE-<n> in the CWE: header")
    want = f"cwe-{m.group(1)}"
    hit = [w for w in weaknesses if (w.get("attributes", {}).get("external_id") or "").lower() == want]
    if len(hit) != 1:
        raise Refused(f"{want} matches {len(hit)} weaknesses in {program} (of {len(weaknesses)}); "
                      "fix the CWE: header or file by hand")
    return hit[0]


def _dedup(report_path, program, asset_ident, cwe_ext):
    return _quiet(_h1mod().dedup_gate, report_path, program, asset_ident, cwe_ext)[0]


def build_payload(program, rep, scope, weakness, severity):
    vuln = rep["summary"] + "\n\n" + rep["poc"]
    att_sec = _section(rep["clean_text"], "Attachments")
    if att_sec:
        vuln += "\n\n" + att_sec
    return {"data": {"type": "report", "attributes": {
        "team_handle": program, "title": rep["title"], "vulnerability_information": vuln,
        "impact": rep["impact"], "severity_rating": severity,
        "weakness_id": int(weakness["id"]), "structured_scope_id": int(scope["id"])}}}


def payload_sha256(payload):
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def show_payload(out, payload, vector, weakness, scope, att, panels, creds):
    a = payload["data"]["attributes"]
    wa, sa = weakness.get("attributes", {}), scope.get("attributes", {})
    bar = "=" * 78
    out(bar)
    out(f"  EXACT PAYLOAD  POST {API}/reports  as {creds.handle} ({creds.token_env})")
    out(bar)
    out(f"team_handle:          {a['team_handle']}")
    out(f"title:                {a['title']}")
    out(f"severity_rating:      {a['severity_rating']}")
    out(f"CVSS vector:          {vector or '(none)'}   (NOT sent: the API takes the rating only; set the vector "
        "in the UI)")
    out(f"weakness_id:          {a['weakness_id']}  ({wa.get('external_id')} {wa.get('name') or ''})".rstrip())
    out(f"structured_scope_id:  {a['structured_scope_id']}  ({sa.get('asset_identifier')}, "
        f"{sa.get('asset_type')}, eligible_for_bounty={sa.get('eligible_for_bounty')})")
    out("-" * 30 + " vulnerability_information " + "-" * 21)
    out(a["vulnerability_information"])
    out("-" * 30 + " impact " + "-" * 40)
    out(a["impact"])
    out("-" * 78)
    out("attachments (NOT sent: the Hacker API create has no attachment field; add these by hand right after):")
    for name, n in att:
        out(f"    {name}  {n} bytes")
    for name, n in panels:
        out(f"    {name}  {n} bytes  (Burp panel)")
    if not att and not panels:
        out("    (none)")
    out(f"payload sha256: {payload_sha256(payload)}")
    out(bar)


# ---------------------------------------------------------------- confirmation, POST, receipt, read-back

def _default_confirm(prompt):
    """A fresh line from a real terminal, or None. Anything typed or pasted before the prompt is discarded."""
    try:
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            return None
    except (AttributeError, ValueError):
        return None
    with contextlib.suppress(Exception):
        import termios
        termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        return None


def _ledger_append(row):
    r = subprocess.run([sys.executable, HUNT_STATE, "append-ship"], input=json.dumps(row), capture_output=True,
                       text=True, cwd=WS, timeout=60)
    return r.returncode == 0, (r.stderr or r.stdout).strip()[:300]


def _get_report(h1, rid):
    r = h1.s.get(f"{API}/reports/{rid}", timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"HTTP {r.status_code}")
    return r.json().get("data") or {}


def _rel_data(data, name):
    return ((data.get("relationships") or {}).get(name) or {}).get("data")


def post_file_diff(data, payload, vector, att, panels):
    """(mismatches, ui_followups) between what was sent and what HackerOne holds (T-253)."""
    sent = payload["data"]["attributes"]
    a = data.get("attributes") or {}
    mism, todo = [], []
    if _norm(a.get("title")) != _norm(sent["title"]):
        mism.append(f"title: filed {a.get('title')!r}, sent {sent['title']!r}")
    sev = _rel_data(data, "severity") or {}
    sa = sev.get("attributes") or {}
    rating = sa.get("rating") or a.get("severity_rating")
    if str(rating or "").lower() != sent["severity_rating"]:
        mism.append(f"severity: filed {rating!r}, sent {sent['severity_rating']!r}")
    filed_vec = sa.get("cvss_vector_string") or ""
    if vector and _norm(filed_vec) != _norm(vector):
        todo.append(f"CVSS vector: filed {filed_vec or '(none)'}, draft {vector}: set it in the UI")
    w = _rel_data(data, "weakness") or {}
    if str(w.get("id")) != str(sent["weakness_id"]):
        mism.append(f"weakness: filed {w.get('id')!r} {(w.get('attributes') or {}).get('external_id')}, "
                    f"sent {sent['weakness_id']}")
    sc = _rel_data(data, "structured_scope") or {}
    if sc and str(sc.get("id")) != str(sent["structured_scope_id"]):
        mism.append(f"structured scope: filed {sc.get('id')!r}, sent {sent['structured_scope_id']}")
    filed_att = sorted((x.get("attributes") or {}).get("file_name") or "" for x in (_rel_data(data, "attachments")
                                                                                    or []))
    if filed_att:
        mism.append(f"attachments: filed {filed_att}, sent none")
    want = [n for n, _ in att] + [os.path.basename(n) for n, _ in panels]
    missing = [n for n in want if n not in filed_att]
    if missing:
        todo.append("attach by hand now: " + ", ".join(missing))
    return mism, todo


def _write_receipt(d, program, slug, rid, url, status, payload, creds, att, panels):
    dest = os.path.join(SUBMITTED, program, f"{rid}-{slug}")
    if os.path.exists(dest):
        raise RuntimeError(f"{dest} already exists")
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    shutil.copytree(d, dest, ignore=shutil.ignore_patterns("__pycache__"))
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(os.path.join(dest, "RECEIPT-payload.json"), "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    lines = ["# RECEIPT - FILED, FROZEN, DO NOT EDIT", "",
             f"Report id: {rid}", f"URL: {url}", f"Filed: {ts}", f"Program: {program}",
             f"Account: {creds.handle} ({creds.token_env})", f"HTTP status: {status}",
             f"Payload sha256: {payload_sha256(payload)} (RECEIPT-payload.json)",
             f"Source draft: {os.path.relpath(d, WS)}",
             "Filed by: gnoc chat /file, typed by the user, confirmed with the typed phrase",
             "Attachments to add by hand: " + (", ".join([n for n, _ in att] + [n for n, _ in panels]) or "none"), ""]
    with open(os.path.join(dest, "RECEIPT.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return dest, ts


def run(rest, out=print, typed=False, confirm=None):
    """Handle one /file line. Returns REFUSED | DRY-RUN | ABORTED | FAILED | FILED. Never raises."""
    creds = None

    def emit(t=""):
        out(_scrub(t, creds) if creds is not None else str(t))

    try:
        if typed is not True:
            raise Refused("/file runs only from a line the user typed at the gnoc chat prompt")
        opts = parse_args(rest)
        d, program, slug = resolve_draft(opts["target"])
        form = read_form(d)
        venue_named = _norm(form.get("venue")).lower()
        if venue_named and venue_named != program.lower():
            raise Refused(f"FORM.md Venue {form.get('venue')!r} differs from the draft's program {program!r}")
        emit(f"  /file {program}/{slug}" + ("  (dry run)" if opts["dry_run"] else ""))
        filability(program, slug, opts, emit)
        rep, att, panels = local_gates(d, program, opts, emit)
        emit("  local gates: ok (HELD, GATES.md, stamps, FORM.md, submit-qaqc, attachments, panels)")
        if opts["allow_missing_panels"]:
            emit("  !! --allow-missing-panels typed: filing without the raw Burp panel pair")
        creds = load_creds(opts["token_env"])
        hdr = rep["header"]
        severity, _ = _severity_from_cvss(hdr.get("CVSS", ""))
        vector = _vector(hdr.get("CVSS", ""))
        h1 = _make_h1(creds.handle, creds.token)
        scopes, _ = _quiet(h1.get_all, f"{API}/programs/{program}/structured_scopes")
        asset = (hdr.get("Asset", "").split() or [""])[0]
        if not asset:
            raise Refused("no Asset: header")
        (scope, how), _ = _quiet(_h1mod().resolve_scope, scopes, asset)
        if (scope.get("attributes") or {}).get("eligible_for_submission") is False:
            raise Refused(f"scope row {scope.get('id')} ({asset}) is not eligible_for_submission")
        weakness = _resolve_weakness(h1, program, hdr.get("CWE", ""))
        dok, dlines = _dedup(os.path.join(d, "report.md"), program,
                             (scope.get("attributes") or {}).get("asset_identifier") or "",
                             (weakness.get("attributes") or {}).get("external_id") or "")
        if not dok:
            raise Refused("self-dedup (T-244) is not CLEAR:\n" + "\n".join(dlines[:12]))
        emit("  self-dedup (T-244): CLEAR")
        payload = build_payload(program, rep, scope, weakness, severity)
        blob = json.dumps(payload, ensure_ascii=False)
        if any(f in blob for f in creds.forms()):
            raise Refused(f"the report text contains the {creds.token_env} value; remove it")
        with contextlib.suppress(Exception):
            import gnoc_secrets
            names = gnoc_secrets.find(blob)
            if names:
                emit(f"  !! the payload contains the value of secret(s) {', '.join(names)}: confirm that is the "
                     "test-account token the PoC needs before typing the phrase")
        # the payload is shown EXACTLY (the token cannot be in it: refused above); only error text is redacted
        show_payload(lambda t="": out(_scrub(t, creds, redact=False)), payload, vector, weakness, scope, att, panels,
                     creds)
        if opts["dry_run"]:
            emit("  dry run: nothing sent")
            return "DRY-RUN"
        phrase = f"FILE {slug}"
        answer = (confirm or _default_confirm)(f"  type {phrase} to file it (anything else aborts) > ")
        if answer != phrase:
            emit("  not filed: the confirmation did not match exactly" if answer is not None
                 else "  not filed: no answer from a terminal")
            return "ABORTED"
        try:
            r = h1.s.post(f"{API}/reports", json=payload, headers={"Content-Type": "application/json"}, timeout=30)
        except Exception as e:  # noqa: BLE001 - the create may or may not have landed
            emit(f"  !!!!! the POST raised {type(e).__name__}: {_scrub(str(e), creds)[:300]}. It MAY have been "
                 "filed: check your HackerOne report list before running /file again.")
            return "FAILED"
        if r.status_code not in (200, 201):
            emit(f"  FILING FAILED: HTTP {r.status_code}  {_scrub((r.text or '')[:1500], creds)}")
            return "FAILED"
        rid = str((r.json().get("data") or {}).get("id") or "")
        if not rid.isdigit():
            emit(f"  !! HTTP {r.status_code} but no report id in the answer: {_scrub((r.text or '')[:600], creds)}")
            return "FAILED"
        url = f"https://hackerone.com/reports/{rid}"
        emit(f"  FILED: report {rid}  {url}  (HTTP {r.status_code})")
        try:
            _after_filing(emit, h1, d, program, slug, rid, url, r.status_code, payload, creds, att, panels, rep,
                          severity, vector)
        except Exception as e:  # noqa: BLE001 - it IS filed; say so whatever the bookkeeping did
            emit(f"  !!!!! report {rid} IS FILED ({url}) but the receipt step failed: {type(e).__name__}: "
                 f"{_scrub(str(e), creds)[:300]}. Write the receipt and run the read-back by hand.")
        return "FILED"
    except Refused as e:
        emit("  /file refused: " + _scrub(str(e), creds))
        return "REFUSED"
    except Exception as e:  # noqa: BLE001 - the REPL survives; the error is the message, without the token
        emit(f"  /file error: {type(e).__name__}: {_scrub(str(e), creds)[:600]}  (nothing was sent)")
        return "FAILED"


def _after_filing(emit, h1, d, program, slug, rid, url, status, payload, creds, att, panels, rep, severity, vector):
    """Receipt, read-back diff (T-253) and ledger, once a report id exists."""
    dest, _ = _write_receipt(d, program, slug, rid, url, status, payload, creds, att, panels)
    emit(f"  receipt: {os.path.relpath(dest, WS)}/RECEIPT.md")
    data, err = None, None
    for attempt in range(2):
        try:
            data = _get_report(h1, rid)
            break
        except Exception as e:  # noqa: BLE001
            err = f"{type(e).__name__}: {e}"
            if attempt == 0:
                _SLEEP(3)
    if data is None:
        diff_text = [f"READ-BACK FAILED ({_scrub(err, creds)}): check {url} by hand now (T-253)"]
        emit("  !!!!! " + diff_text[0])
    else:
        mism, todo = post_file_diff(data, payload, vector, att, panels)
        diff_text = ([f"MISMATCH {m}" for m in mism] + [f"UI FOLLOW-UP {t}" for t in todo]) or ["none"]
        if mism:
            emit("  " + "!" * 70)
            for m in mism:
                emit(f"  !!!!! POST-FILE MISMATCH (T-253): {m}")
            emit("  " + "!" * 70)
        else:
            emit("  post-file diff (T-253): title, severity, weakness, scope match what was sent")
        for t in todo:
            emit(f"  !! UI FOLLOW-UP: {t}")
    with open(os.path.join(dest, "RECEIPT.md"), "a", encoding="utf-8") as fh:
        fh.write("## Post-file read-back diff (T-253)\n" + "\n".join(f"- {x}" for x in diff_text) + "\n")
    row = {"ts": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "program": program, "kind": "submission", "status": "filed", "path": dest, "report_id": rid,
           "url": url, "title": rep["title"], "severity": severity, "slug": slug, "via": "gnoc chat /file"}
    try:
        ok, why = _ledger_append(row)
    except Exception as e:  # noqa: BLE001
        ok, why = False, f"{type(e).__name__}: {e}"
    emit("  ships ledger: kind submission, status filed" if ok else f"  !! ships ledger NOT written: {why}")
    emit(f"  the draft stays in {os.path.relpath(d, WS)}; the filed copy is frozen in "
         f"{os.path.relpath(dest, WS)}")
