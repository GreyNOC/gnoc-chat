"""gnoc_repo.py - open a project: a folder on disk, or a public remote cloned once into a private cache.

Why this exists. `gnoc chat --repo` and `/repo` only accepted a directory that already existed, so a public
repository meant leaving the chat, running `git clone` by hand, and coming back. A coding agent that cannot
open a public repo is not usable for the thing most people open it for. This module is the one intake path:

    parse_remote(spec)        a URL / git@host:owner/repo / owner/repo -> Remote, or None for a local path
    obtain(spec)              -> (path, note): an existing local dir, a cached clone, or a fresh shallow clone
    summary(path)             -> "git main @ 1a2b3c4 · clean · origin github.com/acme/widget" (never creds)
    cache_root()              ~/.gnoc/repos, or $GNOC_REPOS

Rules that came from the public-clone threat model:

- The clone is SHALLOW and single-branch (`--depth 1 --single-branch --no-tags`) and takes no submodules:
  opening a repo to read it should not pull its history or let its .gitmodules fetch more code.
- A URL carrying a username or password is refused. `git clone` writes that URL into `.git/config`, so a
  token pasted into the URL would be left on disk in a repo the agent was only asked to look at. Use a
  credential helper instead.
- The destination is keyed by host/owner/name under the cache. An existing directory is reused only when
  its `remote.origin.url` is the same repo; a different origin is never overwritten or deleted.
- Every subprocess has a timeout, stdin is /dev/null, and prompts are off (`GIT_TERMINAL_PROMPT=0`): a
  private or misspelled repo fails with a message instead of waiting forever for a username.
"""

from __future__ import annotations

import collections
import os
import re
import shutil
import subprocess
import time
import urllib.parse

CLONE_TIMEOUT = 300
DEFAULT_CACHE = os.path.join(os.path.expanduser("~"), ".gnoc", "repos")

# One path segment on a code host. GitHub/GitLab names use these characters; a bare `.` or `..` is refused
# so a name can never climb out of the cache directory.
_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,99}$")
_BRANCH_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._/-]{0,199}$")
_URL_RE = re.compile(r"^(?:https?|ssh|git|file)://", re.I)
_SCP_RE = re.compile(r"^git@([A-Za-z0-9.-]+):(.+)$")
_OWNER_REPO_RE = re.compile(r"^([A-Za-z0-9_][A-Za-z0-9._-]*)/([A-Za-z0-9_][A-Za-z0-9._-]*)(?:#(\S+))?$")

Remote = collections.namedtuple("Remote", "kind url host owner name branch network")


class RepoError(RuntimeError):
    """A repo could not be opened; the message is for the user, not a traceback."""


def cache_root():
    """Where public clones live. $GNOC_REPOS moves it (tests use a temp dir)."""
    raw = os.environ.get("GNOC_REPOS") or DEFAULT_CACHE
    return os.path.realpath(os.path.expanduser(raw))


def _clean(part, what="repo"):
    part = str(part or "").strip()
    if part.lower().endswith(".git"):
        part = part[:-4]
    if not part or part in (".", "..") or not _NAME_RE.match(part):
        raise RepoError(f"not a usable {what} name: {str(part)[:80]!r}")
    return part


def _branch(value):
    value = str(value or "").strip()
    if not value:
        return ""
    if value.startswith("-") or not _BRANCH_RE.match(value):
        raise RepoError(f"not a usable branch name: {value[:80]!r}")
    return value


def _safe_url(url):
    """The URL as a user may see it: credentials (if a URL somehow carries them) are removed."""
    try:
        u = urllib.parse.urlsplit(url)
    except ValueError:
        return str(url or "")
    if u.username or u.password:
        host = u.hostname or ""
        try:
            port = u.port
        except ValueError:       # a malformed port must not make the redacted path raise (and print the raw URL)
            port = None
        if port:
            host += f":{port}"
        return urllib.parse.urlunsplit((u.scheme, host, u.path, u.query, ""))
    return url


def _from_parts(kind, url, host, parts, branch="", network=True):
    parts = [p for p in parts if p]
    if len(parts) < 2:
        raise RepoError(f"{_safe_url(url)} does not name a repository (it needs an owner and a name)")
    name = _clean(parts[-1])
    owner = "-".join(_clean(p, "owner") for p in parts[:-1])
    host = re.sub(r"[^A-Za-z0-9._-]", "_", host or "local").strip("._-") or "local"
    return Remote(kind, url, host, owner, name, _branch(branch), bool(network))


def _parse_url(spec):
    frag = ""
    base = spec
    if "#" in base:
        base, frag = base.rsplit("#", 1)
    u = urllib.parse.urlsplit(base)
    scheme = (u.scheme or "").lower()
    if scheme not in ("http", "https", "ssh", "git", "file"):
        raise RepoError(f"{_safe_url(spec)} is not an http(s), ssh, git or file URL")
    if u.password or (scheme in ("http", "https") and u.username):
        raise RepoError("that URL carries a username/password: git would write it into .git/config. Use a "
                        "credential helper (or a URL without credentials) instead")
    if scheme != "file" and not u.hostname:
        raise RepoError(f"{_safe_url(spec)} has no host")
    path = urllib.parse.unquote(u.path or "")
    parts = [p for p in path.split("/") if p]
    branch = ""
    clone_path = path
    # A browser URL names a branch in the path: github.com/o/r/tree/main, gitlab.com/g/s/r/-/tree/main,
    # bitbucket.org/o/r/src/main. Find the marker only after at least owner/name, so a repository actually
    # named "tree" or "src" is not mistaken for one.
    marker = next((i for i, p in enumerate(parts) if i >= 2 and p in ("tree", "blob", "src")
                   and len(parts) > i + 1), None)
    if marker is not None:
        branch = parts[marker + 1]
        # GitLab puts a "-" before tree/blob; it is not part of the owner path.
        keep = marker - 1 if marker >= 3 and parts[marker - 1] == "-" else marker
        parts = parts[:keep]
        clone_path = "/" + "/".join(parts)
    elif frag:
        branch = frag
    url = urllib.parse.urlunsplit((u.scheme, u.netloc, clone_path, "", ""))
    return _from_parts("file" if scheme == "file" else "url", url, u.hostname or "local",
                       parts, branch, network=(scheme != "file"))


def parse_remote(spec):
    """A Remote for a public/remote repo spec, or None when `spec` is a local path.

    `owner/repo` means GitHub when no such local path exists. A URL fragment (`#branch`) is the branch.
    """
    s = str(spec or "").strip()
    if not s:
        return None
    if re.match(r"^[A-Za-z]:[\\/]", s) or s.startswith(("\\", "/", "~", "./", "../")):
        return None                    # a local path, including Windows drives and UNC
    if s.lower().startswith("github:"):
        s = s[len("github:"):].strip()
    if _URL_RE.match(s):
        return _parse_url(s)
    m = _SCP_RE.match(s)
    if m:
        branch = ""
        path = m.group(2)
        if "#" in path:
            path, frag = path.rsplit("#", 1)
            if frag:
                branch = frag
        return _from_parts("scp", s, m.group(1), path.split("/"), branch)
    m = _OWNER_REPO_RE.match(s)
    if m and not os.path.exists(s):
        owner, name = m.group(1), m.group(2)
        return Remote("github", f"https://github.com/{owner}/{name}.git", "github.com",
                      _clean(owner, "owner"), _clean(name), _branch(m.group(3)), True)
    return None


def looks_remote(spec):
    """True when `spec` names a remote repo rather than a local path (never raises on a bad URL)."""
    try:
        return parse_remote(spec) is not None
    except RepoError:
        return True                    # a malformed remote is still not a local path; obtain() explains it


def _git_env():
    env = dict(os.environ)
    try:
        import gnoc_worktree
        env = gnoc_worktree.git_env(env)   # no inherited GIT_DIR / GIT_INDEX_FILE
    except Exception:  # noqa: BLE001 - the helper may be absent in a trimmed install; the timeout still holds
        for k in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_COMMON_DIR",
                  "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_PREFIX", "GIT_NAMESPACE"):
            env.pop(k, None)
    env["GIT_TERMINAL_PROMPT"] = "0"   # never block on a username prompt
    env["GIT_ASKPASS"] = "echo"
    env["GCM_INTERACTIVE"] = "never"
    return env


def _git(cwd, *args, timeout=20):
    try:
        pr = subprocess.run(["git", "-C", cwd, *args], capture_output=True, text=True, timeout=timeout,
                            stdin=subprocess.DEVNULL, env=_git_env())
    except FileNotFoundError:
        return 127, "git is not installed"
    except subprocess.TimeoutExpired:
        return 124, f"git {' '.join(args[:2])} timed out after {timeout}s"
    return pr.returncode, (pr.stdout or "") + (pr.stderr or "")


def _norm_url(url):
    """The same repo named by https, ssh or scp must compare equal: (host, path), no scheme, no .git.

    An origin stored as `git@github.com:acme/widget.git` and the same repo opened as
    `https://github.com/acme/widget` are one checkout; comparing the raw strings made the second open
    refuse a cache entry it had just created.
    """
    raw = str(url or "").strip()
    m = _SCP_RE.match(raw)
    if m:
        host, path = m.group(1).lower(), m.group(2)
    else:
        try:
            u = urllib.parse.urlsplit(raw)
            host, path = (u.hostname or "").lower(), u.path
        except ValueError:
            return raw.rstrip("/").removesuffix(".git")
    path = path.rstrip("/")
    if path.lower().endswith(".git"):
        path = path[:-4]
    if path and not path.startswith("/"):
        path = "/" + path          # scp spells the path `acme/widget`, a URL spells it `/acme/widget`
    return f"{host}{path}"


def _origin(path):
    code, out = _git(path, "config", "--get", "remote.origin.url")
    return out.strip() if code == 0 else ""


def _dest(remote, branch=""):
    leaf = remote.name
    if branch:
        leaf += "@" + re.sub(r"[^A-Za-z0-9._-]+", "-", branch).strip("-")[:80]
    return os.path.join(cache_root(), remote.host, remote.owner, leaf)


def _clone(remote, dest, branch="", full=False, timeout=CLONE_TIMEOUT):
    parent = os.path.dirname(dest)
    os.makedirs(parent, exist_ok=True)
    tmp = f"{dest}.tmp-{os.getpid()}-{int(time.time() * 1000)}"
    args = ["clone", "--no-tags", "--no-recurse-submodules", "--quiet",
            "-c", "http.lowSpeedLimit=1000", "-c", "http.lowSpeedTime=60"]
    if not full:
        args += ["--depth", "1", "--single-branch"]
    if branch:
        args += ["--branch", branch]
    args += ["--", remote.url, tmp]
    try:
        pr = subprocess.run(["git", *args], capture_output=True, text=True, timeout=timeout,
                            stdin=subprocess.DEVNULL, env=_git_env())
    except FileNotFoundError:
        raise RepoError("git is not installed, so a remote repo cannot be cloned") from None
    except subprocess.TimeoutExpired:
        shutil.rmtree(tmp, ignore_errors=True)
        raise RepoError(f"cloning {_safe_url(remote.url)} timed out after {timeout}s; check the URL and the "
                        "network, then try again") from None
    if pr.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        err = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", (pr.stderr or pr.stdout or "")).strip()
        lines = [ln for ln in err.splitlines() if ln.strip()]
        detail = " / ".join(lines[-3:])[:600] if lines else f"git clone exit {pr.returncode}"
        raise RepoError(f"could not clone {_safe_url(remote.url)}: {detail}")
    if not os.path.isdir(tmp):
        raise RepoError(f"git clone reported success but {tmp} was not created")
    try:
        os.replace(tmp, dest)
    except OSError as e:
        # another chat may have finished the same clone between our check and this rename; reuse only if it
        # is the SAME repo. Never delete a directory we did not create.
        shutil.rmtree(tmp, ignore_errors=True)
        if os.path.isdir(dest) and _norm_url(_origin(dest)) == _norm_url(remote.url):
            return dest
        raise RepoError(f"could not put the clone at {dest}: {e}") from None
    return dest


def obtain(spec, branch="", full=False, timeout=CLONE_TIMEOUT):
    """Open `spec`: a local directory, a cached clone, or a fresh shallow clone. Returns (path, note)."""
    spec = str(spec or "").strip()
    if not spec:
        raise RepoError("give a folder, a repository URL, or owner/repo")
    if not looks_remote(spec):
        path = os.path.realpath(os.path.expanduser(spec))
        if os.path.isdir(path):
            return path, ""
        raise RepoError(f"no such directory: {spec}")
    remote = parse_remote(spec)
    branch = _branch(branch) or remote.branch
    dest = _dest(remote, branch)
    if os.path.isdir(dest):
        origin = _origin(dest)
        if not origin:
            raise RepoError(f"{dest} already exists but is not a git checkout; move it away or set GNOC_REPOS")
        if _norm_url(origin) == _norm_url(remote.url):
            return dest, "already cloned"
        raise RepoError(f"{dest} already exists for another repo ({_safe_url(origin)}); move it away or set "
                        "GNOC_REPOS to a different folder")
    if os.path.exists(dest):
        raise RepoError(f"{dest} already exists and is not a directory; move it away or set GNOC_REPOS")
    if remote.network:
        note = f"cloned {remote.owner}/{remote.name}" + (f" ({branch})" if branch else "") + " shallow"
    else:
        note = "cloned from the local file URL"
    path = _clone(remote, dest, branch, full=full, timeout=timeout)
    return path, note


def summary(path):
    """One line about a checkout for the repo banner. Never prints a credential and never raises."""
    path = str(path or "")
    if not os.path.isdir(path):
        return "no such folder"
    if not shutil.which("git"):
        return "git is not installed"
    code, _ = _git(path, "rev-parse", "--is-inside-work-tree")
    if code != 0:
        return "not a git checkout"
    _, head = _git(path, "rev-parse", "--short", "HEAD")
    branch_code, branch = _git(path, "rev-parse", "--abbrev-ref", "HEAD")
    head = head.strip().splitlines()[-1] if head.strip() else ""
    branch = branch.strip().splitlines()[-1] if branch.strip() else ""
    if branch_code != 0 or not head:
        state = "git (no commits yet)"
    elif branch == "HEAD":
        state = f"git detached @ {head}"
    else:
        state = f"git {branch} @ {head}"
    _, porcelain = _git(path, "status", "--porcelain", "--untracked-files=normal")
    changed = len([ln for ln in porcelain.splitlines() if ln.strip()])
    state += " · clean" if not changed else f" · {changed} changed file{'s' if changed != 1 else ''}"
    _, origin = _git(path, "config", "--get", "remote.origin.url")
    origin = origin.strip().splitlines()[-1] if origin.strip() else ""
    if origin:
        state += f" · origin {_safe_url(origin)}"
    return state[:400]
