"""Workspace path resolution, secret/write guards, and long-output spill."""
import glob
import os
import re
import threading

import gnoc_secrets
from .state import STATE
from .util import _now, _read


TOOL_CHARS = 6000


DELIVERABLES = os.path.realpath(os.path.expanduser("~/Downloads"))


SECRET_NAME = re.compile(r"(^\.env($|\.)|^id_(rsa|ed25519|ecdsa|dsa)$|\.(pem|key|p12|pfx|keystore)$|^secrets?\.env$)")


WRITE_DENY = re.compile(r"^(reports/submitted/|\.claude/hooks/|harness/hooks/|\.claude/settings[^/]*\.json$|\.git/|salvage/"
                        # the hunt ledgers are append-only THROUGH hunt-state.py, which enforces the verdict
                        # enum and the SPINE 4 DEAD floor. A direct write skips every one of those checks.
                        r"|\.claude/state/(hunt-loop|learning)/(outcomes|ships)\.jsonl$"
                        r"|\.claude/state/hunt-loop/oracles/|\.claude/state/economy/"  # ORACLE: code settles, never a write
                        # the outbox: drafts are written by draft_outgoing, which checks for secrets; a write_file
                        # straight into it skipped that check (QAQC r2)
                        r"|\.claude/state/orch/outbox/"
                        # the linked machines: a record edited to another user@host made an approved name point
                        # at a different machine
                        r"|\.claude/state/orch/links\.json)")
# (harness/hooks/ is where a release ships the hooks that gnoc_setup.ensure_workspace copies into .claude/hooks/:
# editing the source is editing the scope gate one update later)


GOVERNING = re.compile(r"^(SPINE\.md$|CLAUDE\.md$|AGENTS\.md$|GNOC\.md$|HANDOFF-CURRENT\.md$|"
                       r"CLAUDE-HANDOFF-[\w.-]+\.md$|Manual/|patterns/|reports/REPORT-FORMAT\.md$|"
                       r"\.claude/agents/|\.claude/AGENT-[\w.-]+\.md$)")


SHRINK_KEEP = 0.4


# gnoc's own automation: the operator's hooks (they run on every tool call) and the list of trusted repo hooks.
# A model that could write them could install a hook that outlives the session, or trust a repo's hooks itself.
_GNOC_OWN = re.compile(r"(?:^|/)\.gnoc/(?:hooks\.json|trusted-hooks\.json)$")
# Skills and their trust list (Phase 3): a skill is written only by the user's typed /skills review. A model that
# could write_file one (a chat rooted at ~ has ~/.gnoc inside its repo) would save a procedure nobody approved,
# or forge a pending proposal, or trust a repo's skills itself. A repo's own .gnoc/skills/ is covered too: a write
# there would only switch the trusted set off, but nothing is gained by letting the model touch it.
_GNOC_SKILLS = re.compile(r"(?:^|/)\.gnoc/(?:skills(?:/|$)|trusted-skills\.json$)")


_MAGIC = ((b"\x89PNG", "PNG image"), (b"\xff\xd8\xff", "JPEG image"), (b"GIF8", "GIF image"), (b"%PDF", "PDF"),
          (b"PK\x03\x04", "zip/apk/jar archive"), (b"\x7fELF", "ELF binary"), (b"\x1f\x8b", "gzip archive"),
          (b"SQLite format 3", "SQLite database"), (b"RIFF", "RIFF (webp/wav) media"))


_ROOT_TL = threading.local()


def root():
    """The active repo. A builder bot working in its own git worktree sees that worktree instead, for the
    duration of its tool calls only (root_scope), so its reads, writes and test runs never touch the lead's
    checkout; every other thread keeps the real active root."""
    return getattr(_ROOT_TL, "root", None) or STATE.active_root[0]


class root_scope:
    """with root_scope(path): root() is `path` in this thread (None = no change)."""

    def __init__(self, path):
        self.path, self.prev = path, None

    def __enter__(self):
        self.prev = getattr(_ROOT_TL, "root", None)
        if self.path:
            _ROOT_TL.root = self.path
        return self

    def __exit__(self, *exc):
        _ROOT_TL.root = self.prev
        return False


def _inside_ws(path):
    """Resolve a path against the active repo; the active repo, the hunt workspace and the
    operator's ~/Downloads deliverables folder are reachable, nothing else."""
    # '~/.gnoc/SPINE.md' is how the docs and the prompt spell paths, so it is what the model
    # sends; unexpanded it matched nothing and a turn died flailing through read_file, list_dir and a bash
    # find before giving up with no answer (soak batch 1, 2026-10-25).
    if path.startswith("~"):
        path = os.path.expanduser(path)
    if not os.path.isabs(path) and (path.startswith("home/") or path.startswith("tmp/")) and \
            not os.path.exists(os.path.join(root(), path)):
        path = "/" + path  # 'home/alice/Desktop/...' is an absolute path with its slash lost by the model
    p = os.path.realpath(path if os.path.isabs(path) else os.path.join(root(), path))
    if not os.path.isabs(path) and not os.path.exists(p) and root().startswith(STATE.ws + os.sep):
        # working in a subfolder of the workspace (targets/<program>): 'SPINE.md' or 'targets/x/...' still resolve
        alt = os.path.realpath(os.path.join(STATE.ws, path))
        if os.path.exists(alt):
            p = alt
    rt = os.path.realpath(root())
    if os.path.isabs(path) and not os.path.exists(p) and rt != os.path.realpath(STATE.ws) and p.startswith(rt + os.sep):
        # the model glued the program folder onto a workspace path: targets/globex/reports/submitted/... for
        # reports/submitted/... (training run 2026-10-22: 24 calls of find on the refile question)
        alt = os.path.realpath(os.path.join(STATE.ws, os.path.relpath(p, rt)))
        if os.path.exists(alt):
            p = alt
    for r in {root(), STATE.ws, DELIVERABLES}:
        if p == r or p.startswith(r + os.sep):
            return p
    return None


def _is_secret(p):
    """Never hand a secret to a model or a transcript: .env files, private keys, keystores, credential stores."""
    if SECRET_NAME.search(os.path.basename(p)) or gnoc_secrets.is_secret_path(p):
        return True
    try:
        with open(p, "rb") as f:
            return b"PRIVATE KEY-----" in f.read(4096)
    except OSError:
        return False


def _rel(p):
    for r in (root(), STATE.ws):
        if p == r or p.startswith(r + os.sep):
            return os.path.relpath(p, r)
    return p


def _rel_home(p):
    h = os.path.expanduser("~")
    return "~" + p[len(h):] if p.startswith(h) else p


def _tmp_file(path):
    """A file under /tmp, checked on the RESOLVED path: '/tmp/..~/.bashrc' starts with /tmp/ as a
    string and resolves to the home dir."""
    p = os.path.realpath(str(path or ""))
    return p if p.startswith("/tmp" + os.sep) else None


def _near_paths(path, k=5, cap=4000):
    """The real files closest to a path that does not exist. A lead that guessed hunts/<slug>/STATUS.md spent ~15
    calls of one turn on misses, `find` and `cat 2>/dev/null` (the user's meta session, 2026-10-22); naming the real
    neighbours in the miss turns that into one call."""
    import difflib
    rel = str(path or "").strip()
    base = root() if not os.path.isabs(rel) else "/"
    d = os.path.dirname(os.path.normpath(os.path.join(base, rel)))
    while d and not os.path.isdir(d) and d != os.path.dirname(d):
        d = os.path.dirname(d)
    # a missing directory NAME is usually a real slug filed elsewhere (a held draft under reports/, a lane under hunts/)
    named = []
    for comp in os.path.normpath(rel).split(os.sep)[:-1]:
        if len(comp) >= 6 and not os.path.isdir(os.path.join(base, comp)):
            for pat in (f"reports/*/*/{comp}*", f"targets/*/hunts/*{comp}*", f"targets/*/{comp}*"):
                named += [os.path.relpath(x, STATE.ws) + ("/" if os.path.isdir(x) else "")
                          for x in sorted(glob.glob(os.path.join(STATE.ws, pat)))[:3]]
    if not d or not _inside_ws(d) or os.path.realpath(d) in (os.path.realpath(STATE.ws), "/"):
        return list(dict.fromkeys(named))[:k]   # walking the whole workspace from its root only names noise
    want = os.path.normpath(rel).lower()
    want_words = set(re.findall(r"[a-z0-9]{3,}", want))
    seen, scored = 0, []
    for dp, dirs, files in os.walk(d):
        dirs[:] = [x for x in dirs if not x.startswith(".") and x not in ("node_modules", "raw", "__pycache__")]
        if dp[len(d):].count(os.sep) > 4:
            dirs[:] = []
        for f in files:
            seen += 1
            if seen > cap:
                break
            full = os.path.join(dp, f)
            r = os.path.relpath(full, root() if _inside_root(full) else STATE.ws).lower()
            words = set(re.findall(r"[a-z0-9]{3,}", r))
            score = difflib.SequenceMatcher(None, want[-60:], r[-60:]).ratio() + 0.15 * len(want_words & words)
            scored.append((score, os.path.relpath(full, root() if _inside_root(full) else STATE.ws)))
        if seen > cap:
            break
    close = [p for s, p in sorted(scored, reverse=True)[:k] if s > 0.45]
    return list(dict.fromkeys(named + close))[:k]


def _binary_kind(p):
    """A short name for a binary file, or None for text: magic bytes first, then a NUL in the first 4 KB."""
    try:
        with open(p, "rb") as f:
            head = f.read(4096)
    except OSError:
        return None
    for magic, name in _MAGIC:
        if head.startswith(magic):
            return name
    return "binary" if b"\x00" in head else None


def _inside_root(p):
    r = os.path.realpath(root())
    return os.path.realpath(p).startswith(r + os.sep)


def _sandbox_fence(ctx, path, tool="this tool"):
    """The sandbox's reach for a file tool (gnoc_sandbox): on docker a path whose REALPATH (after every symlink)
    leaves the bind mount is refused, so a symlink the container planted cannot walk a host-side read or write out
    of the repo; on ssh the file tools are off (they would act on this machine). '' on the local backend."""
    s = getattr(ctx, "s", None)
    if not isinstance(s, dict) or "sandbox" not in s:
        return ""
    import gnoc_sandbox
    raw = os.path.expanduser(str(path or "."))
    real = _inside_ws(raw) or _tmp_file(raw) or os.path.realpath(raw if os.path.isabs(raw) else os.path.join(root(), raw))
    return gnoc_sandbox.file_refusal(s, tool, real)


def _fence(ctx, path):
    """A worker given one program read another program's hunt notes (the user's meta goal, 2026-10-22: program-83, pixelco,
    nba and 8x8 hypotheses out of hunt-archive/) and digested them as meta findings. The lead is not fenced."""
    why = _sandbox_fence(ctx, path, "this file tool")
    if why:
        return why
    prog = (getattr(ctx, "s", None) or {}).get("_program_fence")
    if not prog:
        return None
    r = os.path.relpath(os.path.realpath(_inside_ws(str(path or ".")) or str(path or ".")), os.path.realpath(STATE.ws))
    m = re.match(r"(?:targets|reports/[^/]+)/([^/]+)/", r + "/")
    # a folder that HOLDS other programs' material (targets, reports, reports/<kind>, hunt-archive) is refused
    # too: grep -r over it read every program (QAQC 2026-11-19); the program's own folders stay open
    holds = r in ("targets", "reports", "hunt-archive", "hunt-archive/hunt-state") or (
        bool(re.fullmatch(r"reports/[^/]+", r)) and os.path.isdir(os.path.join(STATE.ws, r)))   # not REPORT-FORMAT.md
    if (m and m.group(1) not in (prog, "_TEMPLATE")) or holds or r.startswith("hunt-archive/hunt-state/hypotheses"):
        return (f"refused: {r} belongs to another program, and this worker is on {prog}. Read targets/{prog}/ and "
                f"reports/*/{prog}/ instead.")
    return None


def _spill(text, tag):
    """Long tool output: the full text goes to disk, the model gets head + tail + the path. Redacted FIRST: the cut
    used to run on the raw text, so a secret straddling it kept a partial prefix, and the spill file on disk held
    every value in the clear (QAQC r2)."""
    text = gnoc_secrets.redact(text)
    if len(text) <= TOOL_CHARS:
        return text
    os.makedirs(STATE.out_dir, exist_ok=True)
    # EVIDENCE INTEGRITY: run_tools runs up to 4 tools at once, so a 1-second name with no unique part let two
    # outputs share one file and one host's bytes were served under the other host's result (audit B-04,
    # reproduced 2026-10-22). Microseconds + pid + thread, and an atomic write so a reader never sees a half file.
    path = os.path.join(STATE.out_dir, f"{_now():%Y%m%d-%H%M%S-%f}-{tag}-{os.getpid()}-{threading.get_ident()}.txt")
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.replace(tmp, path)
    rel = os.path.relpath(path, STATE.ws)
    half = TOOL_CHARS // 2
    return (f"{text[:half]}\n\n[... {len(text) - TOOL_CHARS} chars cut; full output: {rel} "
            f"(read_file with offset, or delegate the reading) ...]\n\n{text[-half:]}")


def _write_refusal(p, content=None, whole_file=False):
    if not p:
        return (f"refused: path outside the active repo ({_rel_home(root())}); write inside it, write a "
                "deliverable to ~/Downloads, or change_dir to the project first")
    # The protected names are relative to the workspace AND to the active repo, and both are checked: a root
    # INSIDE the workspace (targets/<p>) used to be judged only against the workspace, so its own
    # .claude/hooks/, settings and reports/submitted/ were writable (QAQC 2026-11-19). The harness can also work
    # in another repo (--repo, a collaborator project): a session rooted there once wrote
    # reports/submitted/x/report.md through this hole.
    rels = []
    for base in (STATE.ws, os.path.realpath(root())):
        if p.startswith(base + os.sep):
            rels.append(os.path.relpath(p, base))
    rel = rels[0] if rels else ""
    if any(WRITE_DENY.search(x) for x in rels) or "/.git/" in p + "/":
        return "refused: that path is protected (submitted reports, hooks, settings, .git, salvage)"
    if _GNOC_OWN.search(p):
        return ("refused: that is gnoc's own hook or trust file; the user edits it by hand (a hook runs on every "
                "tool call, and the trust list decides which repo hooks run)")
    if _GNOC_SKILLS.search(p):
        return ("refused: skills are saved only through propose_skill and the user's /skills review, and the "
                "trust list only by their /skills trust")
    try:   # the plugins folder (GNOC_HOME may move it, so it is resolved, not matched by name): see gnoc_plugins
        import gnoc_plugins
        if gnoc_plugins.protected(p):
            return ("refused: ~/.gnoc/plugins is the user's: a plugin runs inside gnoc with their rights, so it is "
                    "saved and enabled by hand (/plugins enable), never by the agent")
    except ImportError:
        pass
    if _is_secret(p) or SECRET_NAME.search(os.path.basename(p)):
        return "refused: secrets files are edited by the user by hand"
    if whole_file and any(GOVERNING.search(x) for x in rels) and os.path.isfile(p):
        return (f"refused: {rel} is one of the documents you are governed by. Change it with edit_file (an exact "
                "old -> new replacement), which keeps the rest of the file; a whole-file write would replace the "
                "rules with whatever this turn produced.")
    if whole_file and content is not None and os.path.isfile(p):
        old_n = len(_read(p))
        if old_n > 400 and len(content) < old_n * SHRINK_KEEP:
            return (f"refused: that write would cut {_rel(p)} from {old_n} to {len(content)} characters "
                    f"({100 * len(content) // max(old_n, 1)}% of it). If you mean to rewrite it, say so and use "
                    "edit_file for the part that changes; if you mean to truncate it, do it with bash so it is "
                    "deliberate.")
    return None
