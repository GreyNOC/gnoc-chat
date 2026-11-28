#!/usr/bin/env python3
"""gnoc_collab.py - collaborator engagements: the initial handoff document IS the scope.

A collaborator project is a directory - a repo, a paperwork folder, a private hosted program - that
carries the partner's initial handoff document. That document, not a bug-bounty program page, names
the assets that may be touched and the rules that apply. This module finds it, reads it (Markdown,
text, PDF, DOCX), parses the in-scope and out-of-scope hosts, and imports them into a local
engagement profile under ``targets/<handle>/`` so the existing gates (lib_scope, lib_policy, the bash
scope hook, _send, the hunt ledger) keep working unchanged.

The profile is a CACHE of the handoff, never a replacement for it:

    targets/<handle>/SCOPE.txt      in-scope hosts, generated from the handoff
    targets/<handle>/NOSCOPE.txt    explicit exclusions from the handoff
    targets/<handle>/PROGRAM.md     provenance + the handoff verbatim + supporting paperwork
    targets/<handle>/COLLAB.json    project, handoff path, sha256, imported time, host lists

Re-importing is idempotent: the profile is rewritten only when the handoff bytes changed. Nothing
here sends traffic, and no host is ever authorized merely because a file mentions it: a host is
in scope only when it appears in the handoff's explicit scope material, and the existing refusal
paths (internal IPs, third-party platforms, public suffixes) still apply downstream.

CLI: python3 scripts/gnoc_collab.py status|import|refresh [dir|handle]
"""
from __future__ import annotations

import contextlib
import hashlib
import html
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
import zipfile
from urllib.parse import urlsplit

# The workspace root. GNOC_WS lets tests and alternate installs point at a throwaway tree.
WS = os.path.abspath(os.environ.get("GNOC_WS") or
                     os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DOC_EXTS = (".md", ".markdown", ".txt", ".rst", ".pdf", ".docx", ".rtf")
COMMON_DIRS = ("", "docs", "doc", "paperwork", "papers", "handoff", "handoffs", "intake",
               "contracts", "legal", "engagement", "engagements")
META = "COLLAB.json"
SCOPE = "SCOPE.txt"
NOSCOPE = "NOSCOPE.txt"
PROGRAM = "PROGRAM.md"
MAX_DOC_BYTES = 25_000_000
MAX_TEXT = 200_000
MAX_PAPERWORK = 8

# The workspace's own append-only handoff series is not a partner handoff. Only exact harness names
# are refused, and only at the top of a candidate's stem, so a partner's "HANDOFF.md" still wins.
_SKIP_EXACT = {"handoff-current.md", "handoff-current", "handoff.md.bak", "readme.md"}
_SKIP_PREFIX = ("claude-handoff", "claude-handoff-", "handoff-current.", "hunt-handoff")

_HANDOFF = re.compile(r"(?:hand[\s_-]?off|kick[\s_-]?off|onboard(?:ing)?)", re.I)
# what is FOUND on its own when a chat opens: a file named handoff/kickoff. An "ONBOARDING.md" for new developers or
# a rental "agreement" in ~ was imported as an authorized engagement (QAQC 2026-11-19); any other document is
# imported only by naming it (/collab import <file>), and nothing becomes scope without a yes.
_AUTO_HANDOFF = re.compile(r"(?:hand[\s_-]?off|kick[\s_-]?off)", re.I)
PARSER_VERSION = 2   # bump when parse_scope changes: profiles parsed by an older parser are re-parsed
_NEGATED = re.compile(r"\b(?:never|do\s+not|don'?t|must\s+not|may\s+not|prohibited|forbidden|not\s+allowed|"
                      r"not\s+permitted|not\s+authori[sz]ed|excluded?)\b", re.I)
_OUT_ANY = re.compile(r"out[\s_-]*of[\s_-]*scope|\bexclu|do[\s_-]+not[\s_-]+test|\bforbidden\b|"
                      r"not[\s_-]+in[\s_-]+scope|ineligible|not[\s_-]+eligible|\bno[\s_-]+test", re.I)
_LINE_LEAD = re.compile(r"^(?:[-*+>]\s+|\d+[.)]\s+|#{1,6}\s+|\*\*|__)*")
_PAPERWORK = re.compile(r"(?:authori[sz]ation|statement\s+of\s+work|\bsow\b|rules?\s+of\s+engagement|"
                        r"\broe\b|engagement|contract|agreement|\bnda\b|scope|kick[\s_-]?off)", re.I)
_SCOPE_HINT = re.compile(r"\b(?:in[\s-]*scope|scope|authori[sz]|engagement|rules?\s+of\s+engagement|"
                         r"targets?|assets?|permitted|allowed\s+to\s+test)\b", re.I)

# Heading / inline markers. OUT-OF-SCOPE is tested before IN-SCOPE everywhere: a heading like
# "Out of scope assets" must never open the allowlist.
_OUT = re.compile(r"^(?:out[\s_-]*of[\s_-]*scope|oos\b|exclusions?\b|not[\s_-]+in[\s_-]+scope|"
                  r"do[\s_-]+not[\s_-]+test|forbidden|not[\s_-]+eligible|ineligible)\b", re.I)
_IN = re.compile(r"^(?:in[\s_-]*scope|scope\b|targets?\b|assets?\b|authori[sz]ed\b|permitted\b|"
                 r"surface\b|attack\s+surface)\b", re.I)
_STOP = re.compile(r"^(?:rules?\b|ground\s+rules?\b|objective\b|goals?\b|accounts?\b|methodology\b|"
                   r"report(?:ing)?\b|payment|payout|timeline|schedule|contacts?\b|background|notes?\b)", re.I)
_INLINE_OUT = re.compile(r"\b(?:out[\s_-]*of[\s_-]*scope|not[\s_-]+in[\s_-]+scope|excluded?|"
                         r"do[\s_-]+not[\s_-]+test|forbidden)\b\s*[:\-]", re.I)
_INLINE_IN = re.compile(r"\b(?:in[\s_-]*scope|authori[sz]ed|permitted|targets?|assets?|surface)\b\s*[:\-]", re.I)

_HOST_RE = re.compile(r"(?<![\w@.-])(?:\*\.)?(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
                      r"[A-Za-z]{2,24}(?![\w.-])")
_URL_RE = re.compile(r"https?://[^\s<>'\"`)\]]+", re.I)
_TABLE_SEP = re.compile(r"^:?-{2,}:?$")

_FILE_EXTS = {
    "md", "markdown", "txt", "rst", "pdf", "doc", "docx", "xls", "xlsx", "csv", "json", "yaml",
    "yml", "toml", "ini", "cfg", "conf", "py", "js", "ts", "tsx", "jsx", "html", "htm", "css",
    "scss", "png", "jpg", "jpeg", "gif", "svg", "webp", "zip", "tar", "gz", "tgz", "bz2", "log",
    "sh", "bash", "ps1", "go", "rs", "java", "rb", "php", "cs", "cpp", "c", "h", "exe", "dll",
    "so", "bin", "db", "sqlite", "pem", "key", "crt", "cer", "p12", "pfx", "lock", "bak", "tmp",
    "old", "orig", "env",
}
_PLACEHOLDERS = {"example.com", "example.org", "example.net", "localhost", "domain.com",
                 "yourdomain.com", "your-domain.com", "target.com", "target.example",
                 "test.example", "host.example"}

try:  # reuse the one scope parser's host normalisation and third-party list when available
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from bbtools import lib_scope as _lib_scope  # noqa: E402
except Exception:  # noqa: BLE001 - the parser still works without bbtools on the path
    _lib_scope = None


# --------------------------------------------------------------------- reading documents
def _raw_bytes(path: str) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(MAX_DOC_BYTES + 1)
    except OSError:
        return b""


def _docx_text(path: str) -> str:
    """Word's text without a dependency: word/document.xml, paragraphs as lines, tabs preserved.

    The XML read is CAPPED: a docx is a zip, and an untrusted one can decompress to gigabytes.
    """
    try:
        with zipfile.ZipFile(path) as z, z.open("word/document.xml") as fh:
            xml = fh.read(MAX_TEXT * 3).decode("utf-8", "replace")
    except (OSError, KeyError, zipfile.BadZipFile):
        return ""
    xml = re.sub(r"</w:p\s*>", "\n", xml)
    xml = re.sub(r"<w:tab[^>]*/>", "\t", xml)
    xml = re.sub(r"<w:br[^>]*/>", "\n", xml)
    text = html.unescape(re.sub(r"<[^>]+>", "", xml))
    return re.sub(r"\n{3,}", "\n\n", text)


def _pdf_text(path: str) -> str:
    """pdftotext -layout first (tables keep their shape), plain mode as the fallback."""
    for args in (["pdftotext", "-layout", path, "-"], ["pdftotext", path, "-"]):
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=45, errors="replace")
        except (OSError, subprocess.SubprocessError):
            continue
        if r.returncode == 0 and (r.stdout or "").strip():
            return r.stdout
    return ""


def doc_text(path: str, cap: int = MAX_TEXT) -> str:
    """Text of a handoff/paperwork file: Markdown/text as-is, PDF via pdftotext, DOCX via its XML."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".pdf":
        text = _pdf_text(path)
    elif ext == ".docx":
        text = _docx_text(path)
    else:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read(MAX_TEXT + 1)
        except OSError:
            text = ""
    text = text.replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+\n", "\n", text)
    return text[:cap]


def _safe_doc(path: str, project: str) -> bool:
    """A document gnoc may read into an engagement: a real file inside the project, never a symlink and never a
    secret. A symlinked "contract.md" -> ~/.aws/credentials was copied into PROGRAM.md, which read_file serves
    (QAQC 2026-11-19)."""
    if os.path.islink(path):
        return False
    rp, root = os.path.realpath(path), os.path.realpath(project)
    if not (rp == root or rp.startswith(root + os.sep)):
        return False
    try:
        import gnoc_secrets
        if gnoc_secrets.is_secret_path(rp):
            return False
    except Exception:  # noqa: BLE001 - without the secrets module, refuse nothing extra
        pass
    return True


def _candidate_docs(project: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for sub in COMMON_DIRS:
        d = os.path.join(project, sub) if sub else project
        if not os.path.isdir(d):
            continue
        try:
            names = sorted(os.listdir(d))
        except OSError:
            continue
        for name in names:
            if name.startswith("."):
                continue
            stem, ext = os.path.splitext(name)
            low = name.lower()
            if ext.lower() not in DOC_EXTS:
                continue
            if low in _SKIP_EXACT or low.startswith(_SKIP_PREFIX):
                continue
            path = os.path.join(d, name)
            if path in seen or not os.path.isfile(path) or not _safe_doc(path, project):
                continue
            try:
                if os.path.getsize(path) < 4 or os.path.getsize(path) > MAX_DOC_BYTES:
                    continue
            except OSError:
                continue
            seen.add(path)
            out.append(path)
    return out


def _doc_score(path: str, project: str) -> int:
    name = os.path.basename(path).lower()
    stem = os.path.splitext(name)[0]
    if re.fullmatch(r"hand[\s_-]?off(?:\.[a-z]{2,8})?", name):
        score = 120
    elif re.match(r"hand[\s_-]?off\b", stem):
        score = 100
    elif _HANDOFF.search(stem):
        score = 80
    elif _PAPERWORK.search(stem):
        score = 50
    else:
        score = 0
    if score == 0:
        return 0
    d = os.path.dirname(os.path.abspath(path))
    if os.path.realpath(d) == os.path.realpath(project):
        score += 15
    elif os.path.basename(d).lower() in ("paperwork", "papers", "contracts", "legal"):
        score += 10
    return score


def _looks_like_handoff(path: str, text: str) -> bool:
    """A document that merely DISCUSSES scope is not an authorization.

    A filename that says handoff/kickoff/onboarding is enough; otherwise the text needs engagement
    language (authorization, engagement, SOW/ROE, permission to test, bug bounty, confidential) or
    both an in-scope and an out-of-scope section. "Partner"/"client" alone is too common in ordinary
    docs, so it only counts next to test/security/assessment/engagement/scope language. That keeps an
    ordinary repo's SCOPE.md from being imported as a private engagement just because it says "scope".
    """
    stem = os.path.splitext(os.path.basename(path))[0]
    if _AUTO_HANDOFF.search(stem):
        return True
    if re.search(r"\b(?:authori[sz](?:ed|ation)?|engagement|statement\s+of\s+work|\bsow\b|"
                 r"rules?\s+of\s+engagement|\broe\b|confidential|permission\s+to\s+test|"
                 r"permitted\s+to\s+test|bug\s*bounty|penetration\s+test)\b", text, re.I):
        return True
    if re.search(r"\b(?:partner|client)\b", text, re.I) \
            and re.search(r"\b(?:test(?:ing)?|security|assessment|engagement|authori[sz]|scope)\b",
                          text, re.I):
        return True
    return bool(re.search(r"\bin[\s_-]*scope\b", text, re.I)
                and re.search(r"\bout[\s_-]*of[\s_-]*scope\b", text, re.I))


def find_handoff(project: str) -> str | None:
    """The partner's initial handoff document in a project, or None.

    Recognised by filename (handoff, kickoff, onboarding) and then by content: the document must
    actually talk about scope/authorization/targets. A strongly named handoff (HANDOFF*.pdf) whose
    text cannot be extracted (a scan with no text layer) is still RETURNED, so the chat can say out
    loud that the paperwork needs OCR instead of silently behaving as if there were no scope. The
    workspace's own `HANDOFF-CURRENT.md` and `CLAUDE-HANDOFF-*` series are excluded, so opening gnoc
    chat at the workspace root is unchanged.
    """
    project = os.path.realpath(os.path.expanduser(project or "."))
    if not os.path.isdir(project):
        return None
    ranked = []
    unreadable = []
    for path in _candidate_docs(project):
        score = _doc_score(path, project)
        if not score or not _AUTO_HANDOFF.search(os.path.splitext(os.path.basename(path))[0]):
            continue
        text = doc_text(path, 40_000)
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            mtime = 0
        if not text.strip():
            if score >= 90:   # a file actually named HANDOFF/kickoff, likely a scanned PDF
                unreadable.append((score, mtime, path))
            continue
        if not _SCOPE_HINT.search(text) or not _looks_like_handoff(path, text):
            continue
        ranked.append((score, mtime, path))
    if ranked:
        ranked.sort(key=lambda r: (-r[0], -r[1], r[2]))
        return ranked[0][2]
    if unreadable:
        unreadable.sort(key=lambda r: (-r[0], -r[1], r[2]))
        return unreadable[0][2]
    return None


def find_paperwork(project: str, primary: str | None = None) -> list[str]:
    """The supporting paperwork beside the handoff (SOW, authorization, ROE, contract, NDA, scope).

    Context and rules for PROGRAM.md; it is not parsed for scope - the initial handoff is.
    """
    project = os.path.realpath(os.path.expanduser(project or "."))
    primary = os.path.realpath(primary) if primary else None
    out, seen = [], set()
    for path in _candidate_docs(project):
        rp = os.path.realpath(path)
        if rp == primary or rp in seen:
            continue
        stem = os.path.splitext(os.path.basename(path))[0].lower()
        if not _PAPERWORK.search(stem):
            continue
        seen.add(rp)
        out.append(path)
    out.sort(key=lambda p: (-_doc_score(p, project), os.path.basename(p).lower()))
    return out[:MAX_PAPERWORK]


# --------------------------------------------------------------------- scope parsing
def _clean_host(token: str) -> str | None:
    token = (token or "").strip().strip("`'\"<>[](){}.,;:!?")
    token = token.lstrip("=").rstrip(".")
    low = token.lower()
    if not low or "@" in low:
        return None
    if "*" in low and not low.startswith("*."):
        return None
    if not re.fullmatch(r"(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}", low):
        return None
    tld = low.rsplit(".", 1)[-1]
    if tld in _FILE_EXTS:
        return None
    if low in _PLACEHOLDERS or low.endswith(".example") or low.startswith("www.") and low[4:] in _PLACEHOLDERS:
        return None
    if _lib_scope is not None and _lib_scope.THIRD_PARTY.search(low):
        return None
    try:  # a public IP is a legitimate exact asset; private/internal addresses never are
        ip = ipaddress.ip_address(low.lstrip("*."))
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return None
    except ValueError:
        pass
    return low


def _hosts_in(line: str) -> list[str]:
    out: list[str] = []
    urls = list(_URL_RE.finditer(line))
    for m in urls:
        raw = m.group(0).rstrip(".,;:)]}>")
        try:
            host = (urlsplit(raw).hostname or "").lower().rstrip(".")
        except ValueError:
            host = ""
        host = _clean_host(host)
        if host:
            out.append(host)
    # Bare domains, but not the domain part of a URL we already read and not an email address.
    stripped = _URL_RE.sub(" ", line)
    for m in _HOST_RE.finditer(stripped):
        host = _clean_host(m.group(0))
        if host:
            out.append(host)
    return list(dict.fromkeys(out))


def _heading(line: str) -> str | None:
    m = re.match(r"^\s{0,3}#{1,6}\s+(.*?)\s*#*\s*$", line)
    if m:
        return m.group(1).strip()
    m = re.match(r"^\s*\*\*(.+?)\*\*\s*:?\s*$", line)
    if m:
        return m.group(1).strip()
    m = re.match(r"^\s*([A-Za-z][A-Za-z0-9 /&()'-]{2,70})\s*:\s*$", line)
    if m:
        return m.group(1).strip()
    return None


def _add(seq: list[str], hosts: list[str]) -> None:
    for h in hosts:
        if h not in seq:
            seq.append(h)


def parse_scope(text: str) -> dict:
    """Split a handoff into in-scope and out-of-scope host lists.

    Understands the shapes a partner handoff actually uses: a `## Scope` section, `In scope:` and
    `Out of scope:` lines, bullet lists, and tables with a Yes/No column. A host seen in an explicit
    out-of-scope line is never returned as in scope. If no explicit scope section exists, only URLs
    written anywhere in the document are considered (a bare domain in prose is not authorization).
    """
    in_hosts: list[str] = []
    out_hosts: list[str] = []
    state = "unknown"
    saw_scope = False
    saw_out = False
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        body = _LINE_LEAD.sub("", line)
        # an explicit inline marker wins over heading detection ("In scope: a.com, b.com"), but only at the START
        # of a line or bullet: "- Third-party assets: cdn.vendor.net" under Out of scope opened the allowlist
        if _INLINE_OUT.match(body):
            state, saw_out = "out", True
            _add(out_hosts, _hosts_in(line))
            continue
        if _INLINE_IN.match(body) and not _NEGATED.search(line):
            state, saw_scope = "in", True
            _add(in_hosts, _hosts_in(line))
            continue
        if _NEGATED.search(line) and _hosts_in(line):
            # "Never attack these production targets: prod.acme.com" is a prohibition, whatever section it is in
            _add(out_hosts, _hosts_in(line))
            continue
        head = _heading(line)
        if head:
            if _OUT.search(head) or _OUT_ANY.search(head):   # "### Partner systems (do not test)"
                state, saw_out = "out", True
                continue
            if _IN.search(head):
                state, saw_scope = "in", True
                continue
            if state == "in" and _STOP.search(head) and not _hosts_in(line):
                state = "unknown"
                continue
        if line.startswith("|") and line.count("|") >= 2:
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if cells and all(_TABLE_SEP.fullmatch(c) for c in cells if c):
                continue
            hosts = _hosts_in(" ".join(cells))
            if not hosts:
                continue
            joined = " ".join(cells).lower()
            out_cell = bool(re.search(r"\b(?:no|out|excluded?|denied|forbidden|false)\b", joined))
            in_cell = bool(re.search(r"\b(?:yes|included?|allowed|permitted|authori[sz]ed|true)\b", joined))
            if out_cell:
                # "| admin.acme.com | No | allowed only after written approval |": a row that says no anywhere is
                # out, even when another cell also says allowed; ambiguity never authorizes
                _add(out_hosts, hosts)
            elif in_cell:
                _add(in_hosts, hosts)
            elif state == "in":
                _add(in_hosts, hosts)
            elif state == "out":
                _add(out_hosts, hosts)
            continue
        hosts = _hosts_in(line)
        if state == "in":
            _add(in_hosts, hosts)
        elif state == "out":
            _add(out_hosts, hosts)
        # no scope section: a URL in prose is NOT authorization ("our old vendor https://shop.othercorp.com was
        # breached" became in scope); the profile then says no hosts were parsed
    # An out-of-scope row always beats an in-scope wildcard.
    out_set = set(out_hosts)
    in_hosts = [h for h in in_hosts if h not in out_set]
    return {"in": in_hosts, "out": out_hosts, "saw_scope": saw_scope, "saw_out": saw_out}


# --------------------------------------------------------------------- profile import
def _slug(text: str, limit: int = 72) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", (text or "").strip()).strip("-._").lower()
    return s[:limit].rstrip("-._")


def _choose_handle(project: str, handoff: str, ws: str) -> str:
    base = _slug(os.path.basename(os.path.realpath(project).rstrip(os.sep)))
    if not base or base in ("home", "desktop", "tmp", "downloads", "documents", "project",
                            "workspace", "work", "dev", "src"):
        base = _slug(os.path.splitext(os.path.basename(handoff))[0]) or "engagement"
    candidate = "collab-" + base if not base.startswith("collab-") else base
    candidate = candidate[:80].rstrip("-._")
    tdir = os.path.join(ws, "targets")
    if not os.path.exists(os.path.join(tdir, candidate)):
        return candidate
    for n in range(2, 100):
        alt = f"{candidate[:77].rstrip('-._')}-{n}"
        if not os.path.exists(os.path.join(tdir, alt)):
            return alt
    return candidate + "-" + str(int(time.time()))


def _profile_dir(program: str, ws: str) -> str:
    return os.path.join(ws, "targets", program)


def profile(program: str, ws: str | None = None) -> dict | None:
    """The COLLAB.json of an engagement profile, or None for an ordinary bounty program."""
    ws = ws or WS
    if not program or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,80}", str(program)):
        return None
    path = os.path.join(_profile_dir(program, ws), META)
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("kind") != "collaborator":
        return None
    data["program"] = program
    return data


def is_profile(program: str, ws: str | None = None) -> bool:
    return profile(program, ws) is not None


def _profile_for_project(project: str, ws: str) -> tuple[str, dict] | tuple[None, None]:
    tdir = os.path.join(ws, "targets")
    try:
        names = sorted(os.listdir(tdir))
    except OSError:
        return None, None
    rp = os.path.realpath(project)
    for name in names:
        data = profile(name, ws)
        if data and os.path.realpath(str(data.get("project") or "")) == rp:
            return name, data
    return None, None


def _atomic_write(path: str, text: str) -> None:
    """Private (0600 in a 0700 folder: a handoff is confidential) and race-free (one tmp file per writer: two
    chats importing at once collided on a shared ".tmp")."""
    import tempfile
    d = os.path.dirname(path)
    os.makedirs(d, mode=0o700, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    fd, tmp = tempfile.mkstemp(dir=d, prefix="." + os.path.basename(path) + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


@contextlib.contextmanager
def _import_lock(ws: str):
    """One import at a time across chats: choosing a handle and writing its profile are one step."""
    import fcntl
    tdir = os.path.join(ws, "targets")
    os.makedirs(tdir, exist_ok=True)
    with open(os.path.join(tdir, ".collab.lock"), "a") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lk, fcntl.LOCK_UN)


def _scope_txt(handoff_rel: str, digest: str, parsed: dict) -> str:
    lines = [
        f"# COLLABORATOR ENGAGEMENT SCOPE - generated from {handoff_rel}",
        f"# Source sha256: {digest}",
        "# This is NOT a bug-bounty program. The handoff document is the authorization.",
        "# Edit the handoff, then run `gnoc collab refresh <handle>` or restart gnoc chat in the project.",
        "# In-scope entries:",
    ]
    if parsed["in"]:
        lines += parsed["in"]
    else:
        lines += ["# WARNING: no in-scope hosts were parsed from the handoff.",
                  "# No request will pass the scope gate until the handoff has an explicit scope section."]
    lines.append("")
    lines.append("# === OUT OF SCOPE === (enforced from NOSCOPE.txt; they beat any wildcard)")
    lines.append("# No exclusion is listed in this file on purpose: every reader of SCOPE.txt sees only")
    lines.append("# the allowlist, while lib_scope still denies the NOSCOPE.txt rows.")
    return "\n".join(lines) + "\n"


def _program_md(handle: str, project: str, handoff: str, digest: str, parsed: dict,
                handoff_text: str, paperwork: list[dict]) -> str:
    lines = [
        f"# {handle} - collaborator engagement",
        "",
        "This is a private collaborator engagement, not a public bug-bounty program. The initial",
        "handoff document is the scope and the authorization; there is no platform scope export to",
        "fetch and no program handle to look up.",
        "",
        f"- project: {project}",
        f"- handoff: {handoff}",
        f"- sha256: {digest}",
        f"- imported: {time.strftime('%Y-%m-%d %H:%MZ', time.gmtime())}",
        f"- in-scope hosts parsed: {len(parsed['in'])}",
        f"- out-of-scope hosts parsed: {len(parsed['out'])}",
        "",
        "## Primary handoff (the scope and authorization, verbatim)",
        "",
        handoff_text.strip() or "(the handoff had no extractable text)",
    ]
    if paperwork:
        lines += ["", "## Supporting paperwork (context and rules; not parsed for scope)"]
        for row in paperwork:
            lines += ["", f"### {os.path.basename(row['path'])}", "", row["text"].strip()]
    return "\n".join(lines) + "\n"


def import_handoff(project: str, ws: str | None = None, handle: str | None = None,
                   force: bool = False, handoff_path: str | None = None, consent: str | None = None) -> dict:
    """See _import_handoff; this one holds the import lock. consent: how the human agreed ("asked", "explicit")."""
    ws = os.path.realpath(ws or WS)
    with _import_lock(ws):
        return _import_handoff(project, ws, handle, force, handoff_path, consent)


def _import_handoff(project: str, ws: str, handle: str | None = None,
                    force: bool = False, handoff_path: str | None = None, consent: str | None = None) -> dict:
    """Find the partner handoff in `project` and import/refresh its local engagement profile.

    `handoff_path` imports a SPECIFIC document (a file the partner sent, kept anywhere); its parent
    directory becomes the engagement's project. Returns a dict with ok, program, project, handoff,
    sha256, hosts, out, paperwork, created, unchanged and reason. It never raises for a
    missing/unreadable handoff: the caller gets ok=False and a reason it can show.
    """
    ws = os.path.realpath(ws or WS)
    if handoff_path:
        handoff = os.path.realpath(os.path.expanduser(str(handoff_path)))
        if not os.path.isfile(handoff):
            return {"ok": False, "reason": f"no such handoff file: {handoff}"}
        project = os.path.dirname(handoff)
    else:
        project = os.path.realpath(os.path.expanduser(project or "."))
        if not os.path.isdir(project):
            return {"ok": False, "reason": f"no such directory: {project}"}
        handoff = find_handoff(project)
    if not handoff:
        return {"ok": False, "reason": ("no partner handoff document found (looked for HANDOFF*.md, "
                                        "kickoff/onboarding docs, SCOPE/AUTHORIZATION/ROE/SOW paperwork)")}
    raw = _raw_bytes(handoff)
    digest = hashlib.sha256(raw).hexdigest()
    text = doc_text(handoff)
    if not text.strip():
        return {"ok": False, "handoff": handoff,
                "reason": f"handoff found but no text could be read: {handoff}"}
    parsed = parse_scope(text)
    olds = find_paperwork(project, handoff)
    paperwork = []
    for path in olds:
        body = doc_text(path, 120_000)
        if body.strip():
            paperwork.append({"path": path, "sha256": hashlib.sha256(_raw_bytes(path)).hexdigest(),
                              "text": body})
    found_handle, _found = _profile_for_project(project, ws)
    chosen = handle or found_handle
    if not chosen:
        chosen = _choose_handle(project, handoff, ws)
    pdir = _profile_dir(chosen, ws)
    if os.path.isdir(pdir) and not os.path.isfile(os.path.join(pdir, META)) and chosen != found_handle:
        # never write an engagement profile over an ordinary programme's folder
        chosen = _choose_handle(project, handoff, ws)
        pdir = _profile_dir(chosen, ws)
    existing = profile(chosen, ws)
    if existing and not force and existing.get("sha256") == digest and not handle \
            and existing.get("parser") == PARSER_VERSION and not existing.get("revoked") \
            and (existing.get("consent") or {}).get("sha256") == digest:
        return {"ok": True, "program": chosen, "project": project, "handoff": handoff,
                "handoff_rel": os.path.relpath(handoff, project), "sha256": digest,
                "hosts": list(existing.get("hosts") or []), "out": list(existing.get("out") or []),
                "paperwork": list(existing.get("paperwork") or []), "created": False,
                "unchanged": True, "scope_ok": bool(existing.get("hosts")),
                "imported": existing.get("imported") or "",
                "reason": "handoff unchanged since the last import"}
    os.makedirs(pdir, mode=0o700, exist_ok=True)
    handoff_rel = os.path.relpath(handoff, project)
    _atomic_write(os.path.join(pdir, SCOPE), _scope_txt(handoff_rel, digest, parsed))
    if parsed["out"]:
        _atomic_write(os.path.join(pdir, NOSCOPE),
                      "# Explicitly out of scope in " + handoff_rel + "; these beat any in-scope wildcard.\n"
                      + "\n".join(parsed["out"]) + "\n")
    elif os.path.isfile(os.path.join(pdir, NOSCOPE)):
        os.remove(os.path.join(pdir, NOSCOPE))  # a stale exclusion list would be worse than none
    _atomic_write(os.path.join(pdir, PROGRAM),
                  _program_md(chosen, project, handoff, digest, parsed, text, paperwork))
    meta = {
        "kind": "collaborator",
        "program": chosen,
        "project": project,
        "handoff": handoff,
        "handoff_rel": handoff_rel,
        "sha256": digest,
        "imported": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "hosts": parsed["in"],
        "out": parsed["out"],
        "scope_ok": bool(parsed["in"]),
        "paperwork": [{"path": p["path"], "sha256": p["sha256"]} for p in paperwork],
        "generator": "gnoc_collab.py",
        "parser": PARSER_VERSION,
        # the human's yes, tied to these exact bytes: a changed handoff is asked about again
        "consent": ({"sha256": digest, "how": consent, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
                    if consent else (existing or {}).get("consent") or {}),
    }
    _atomic_write(os.path.join(pdir, META), json.dumps(meta, indent=2, sort_keys=True) + "\n")
    return {"ok": True, "program": chosen, "project": project, "handoff": handoff,
            "handoff_rel": handoff_rel, "sha256": digest, "hosts": parsed["in"], "out": parsed["out"],
            "paperwork": meta["paperwork"], "created": not bool(existing), "imported": meta["imported"],
            "unchanged": False, "scope_ok": bool(parsed["in"]), "reason": ""}


def refresh(program: str, ws: str | None = None) -> dict:
    """Re-import a profile from its project. Used by /collab refresh and `gnoc collab refresh` (typing it is the
    consent). A handoff that is gone revokes the profile instead of leaving its old scope in force."""
    data = profile(program, ws)
    if not data:
        return {"ok": False, "reason": f"{program} is not a collaborator engagement"}
    if not os.path.isfile(str(data.get("handoff") or "")):
        revoke(program, ws, "its handoff document is gone")
        return {"ok": False, "revoked": True,
                "reason": f"the handoff {data.get('handoff')} is gone: {program}'s scope is revoked"}
    return import_handoff(data.get("project") or "", ws or WS, handle=program, force=True,
                          handoff_path=data.get("handoff"), consent="explicit")


def revoke(program: str, ws: str | None = None, why: str = "") -> bool:
    """Take an engagement's scope away: no host passes its gate until the handoff is imported again. Used when the
    handoff disappears (a deleted HANDOFF.md kept *.acme.com in scope, QAQC 2026-11-19)."""
    ws = os.path.realpath(ws or WS)
    data = profile(program, ws)
    if not data:
        return False
    pdir = _profile_dir(program, ws)
    with _import_lock(ws):
        _atomic_write(os.path.join(pdir, SCOPE), f"# {program}: REVOKED ({why or 'revoked'}).\n"
                      "# No host is in scope. Import the handoff again (/collab import) to restore it.\n")
        data.update(revoked=why or "revoked", hosts=[], scope_ok=False,
                    revoked_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        data.pop("program", None)
        _atomic_write(os.path.join(pdir, META), json.dumps(data, indent=2, sort_keys=True) + "\n")
    return True


_TEXT_CACHE: dict = {}


def active_handoff(project: str, ws: str | None = None) -> tuple[str, str] | None:
    """(path, text) of the handoff of a CONSENTED, unrevoked engagement for this project, else None. This is what
    may ride the prompt as the repo's instructions: an unapproved document never does (it was injected on every
    turn, approved or not). The text is cached by (path, mtime, size): a PDF was re-extracted every turn."""
    name, data = _profile_for_project(project, os.path.realpath(ws or WS))
    if not data or data.get("revoked") or (data.get("consent") or {}).get("sha256") != data.get("sha256"):
        return None
    path = str(data.get("handoff") or "")
    try:
        st = os.stat(path)
    except OSError:
        return None
    key = (path, st.st_mtime_ns, st.st_size)
    if key not in _TEXT_CACHE:
        _TEXT_CACHE.clear()
        _TEXT_CACHE[key] = doc_text(path, 60_000)
    return path, _TEXT_CACHE[key]


def preview(project: str, handoff_path: str | None = None) -> dict | None:
    """What importing would authorize, written nowhere: {handoff, sha256, hosts, out, paperwork} or None."""
    if handoff_path:
        handoff = os.path.realpath(os.path.expanduser(str(handoff_path)))
        project = os.path.dirname(handoff)
        if not os.path.isfile(handoff) or os.path.islink(os.path.expanduser(str(handoff_path))):
            return None
    else:
        project = os.path.realpath(os.path.expanduser(project or "."))
        handoff = find_handoff(project)
    if not handoff:
        return None
    text = doc_text(handoff)
    parsed = parse_scope(text) if text.strip() else {"in": [], "out": []}
    return {"handoff": handoff, "project": project, "sha256": hashlib.sha256(_raw_bytes(handoff)).hexdigest(),
            "hosts": parsed["in"], "out": parsed["out"], "readable": bool(text.strip()),
            "paperwork": [os.path.basename(p) for p in find_paperwork(project, handoff)]}


def _declined_path(ws: str) -> str:
    return os.path.join(ws, ".claude", "state", "collab-declined.json")


def declined(project: str, digest: str, ws: str | None = None) -> bool:
    try:
        with open(_declined_path(os.path.realpath(ws or WS))) as fh:
            return json.load(fh).get(os.path.realpath(project)) == digest
    except (OSError, ValueError, AttributeError):
        return False


def decline(project: str, digest: str, ws: str | None = None) -> None:
    """Remember "this folder is not an engagement" for these exact handoff bytes (/collab off, or a no)."""
    p = _declined_path(os.path.realpath(ws or WS))
    try:
        with open(p) as fh:
            d = json.load(fh)
    except (OSError, ValueError):
        d = {}
    d = d if isinstance(d, dict) else {}
    d[os.path.realpath(project)] = digest
    _atomic_write(p, json.dumps(d, indent=1) + "\n")


def attach(ctx, project: str, ws: str | None = None, handoff_path: str | None = None, approve=None,
           explicit: bool = False) -> dict | None:
    """Import the handoff in `project` (or the specific `handoff_path`) and make it active.

    Sets session["program"], session["collab"] and session["program_src"]; never sets the hunt
    stance - opening a collaborator project is not an order to hunt. Returns the import dict, a
    dict with ok=False when a handoff exists but could not be imported, or None when the directory
    has no partner handoff at all.

    NOTHING becomes scope without the human: an import needs `explicit` (he typed /collab import), an earlier yes
    for these exact bytes, or approve(preview) returning True (the chat asks, showing the file and its hosts).
    With no approve callback (a one-shot, a pipe) it returns ok=False, pending=True and imports nothing.
    """
    ws = os.path.realpath(ws or WS)
    if handoff_path:
        project = os.path.dirname(os.path.realpath(os.path.expanduser(str(handoff_path))))
    else:
        project = os.path.realpath(os.path.expanduser(project or "."))
    if project == ws or project.startswith(os.path.join(ws, "targets") + os.sep):
        return None
    pv = preview(project, handoff_path)
    if not pv:
        # no handoff here any more: a profile made from one that is now gone loses its scope
        name, data0 = _profile_for_project(project, ws)
        if name and not os.path.isfile(str(data0.get("handoff") or "")) and not data0.get("revoked"):
            revoke(name, ws, "its handoff document is gone")
            if ctx.s.get("program") == name:
                for k in ("program", "collab", "program_src"):
                    ctx.s.pop(k, None)
            return {"ok": False, "revoked": True, "program": name,
                    "reason": f"the handoff behind {name} is gone, so its scope is revoked"}
        return None
    name, data0 = _profile_for_project(pv["project"], ws)
    agreed = bool(data0) and (data0.get("consent") or {}).get("sha256") == pv["sha256"]
    if not agreed:
        if explicit:
            agreed = True
        elif declined(pv["project"], pv["sha256"], ws):
            return None
        elif approve is None:
            # no human to ask (a one-shot, a pipe): nothing is imported and nothing becomes scope
            return {"ok": False, "pending": True, "handoff": pv["handoff"], "preview": pv,
                    "reason": "a handoff document is here; nothing was imported (it needs your yes: /collab import)"}
        elif approve(pv):
            agreed = True
        else:
            decline(pv["project"], pv["sha256"], ws)
            return None
    data = import_handoff(project, ws, handoff_path=handoff_path,
                          consent="explicit" if explicit else "asked")
    if not data.get("ok"):
        if data.get("handoff"):
            return {"ok": False, "reason": data.get("reason") or "the handoff could not be imported",
                    "handoff": data["handoff"]}
        return None
    ctx.s["program"] = data["program"]
    ctx.s["collab"] = {k: data.get(k) for k in
                       ("program", "project", "handoff", "handoff_rel", "sha256", "hosts", "out",
                        "paperwork", "scope_ok", "imported")}
    ctx.s["program_src"] = {"program": data["program"],
                            "how": f"collaborator handoff {os.path.basename(data['handoff'])}",
                            "sid": (ctx.s or {}).get("sid")}
    return data


def summary(program: str, ws: str | None = None) -> str:
    data = profile(program, ws)
    if not data:
        return f"{program}: not a collaborator engagement"
    hosts = data.get("hosts") or []
    out = data.get("out") or []
    lines = [
        f"collaborator engagement {program}",
        f"  project: {data.get('project')}",
        f"  handoff: {data.get('handoff')}  (sha256 {str(data.get('sha256') or '')[:12]})",
        f"  imported: {data.get('imported') or '?'}",
        f"  in scope: {len(hosts)} host(s)" + (": " + ", ".join(hosts[:8]) + (" ..." if len(hosts) > 8 else "")
                                              if hosts else " - NONE PARSED"),
        f"  out of scope: {len(out)} host(s)" + (": " + ", ".join(out[:6]) + (" ..." if len(out) > 6 else "")
                                                if out else ""),
    ]
    paper = data.get("paperwork") or []
    if paper:
        lines.append("  paperwork: " + ", ".join(os.path.basename(str(p.get("path"))) for p in paper[:6]))
    lines.append(f"  profile: targets/{program}/ (SCOPE.txt, NOSCOPE.txt, PROGRAM.md, COLLAB.json)")
    if not hosts:
        lines.append("  WARNING: no in-scope hosts were parsed; no request will pass the gate.")
        lines.append("  Add an explicit 'In scope:' section to the handoff, then `/collab refresh`.")
    lines.append("  the handoff is the authorization; there is no bounty program to fetch")
    return "\n".join(lines)


def all_profiles(ws: str | None = None) -> list[dict]:
    ws = ws or WS
    tdir = os.path.join(ws, "targets")
    out = []
    try:
        names = sorted(os.listdir(tdir))
    except OSError:
        return out
    for name in names:
        data = profile(name, ws)
        if data:
            out.append(data)
    return out


# --------------------------------------------------------------------- CLI
def _main(argv: list[str]) -> int:
    action = (argv[0] if argv else "status").lower()
    rest = argv[1:]
    if action in ("status", "list"):
        rows = all_profiles()
        if not rows:
            print("no collaborator engagements imported")
            return 0
        for row in rows:
            print(summary(row["program"]))
            print()
        return 0
    if action in ("import", "add"):
        project = rest[0] if rest else os.getcwd()
        got = import_handoff(project, consent="explicit")   # typing `gnoc collab import` is the consent
        if not got.get("ok"):
            print(f"collab import failed: {got.get('reason')}")
            return 1
        print(summary(got["program"]))
        if not got.get("hosts"):
            print("\nWARNING: the handoff had no explicit scope section; no request can pass yet.")
        return 0
    if action in ("refresh", "reload"):
        if not rest:
            print("usage: gnoc collab refresh <handle>")
            return 2
        got = refresh(rest[0])
        if not got.get("ok"):
            print(f"collab refresh failed: {got.get('reason')}")
            return 1
        print(summary(got["program"]))
        return 0
    print(__doc__.strip().splitlines()[-1])
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
