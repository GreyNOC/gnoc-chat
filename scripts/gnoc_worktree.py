"""gnoc_worktree.py - a private git worktree for a builder bot, so parallel workers that WRITE code never share
one checkout with each other or with the lead.

    create(repo)          -> (path, base_commit): a new worktree on branch gnoc/build-<id>, starting from the
                             repo's CURRENT state (HEAD plus uncommitted changes to tracked files)
    diff(path, base)      -> the builder's whole change as one unified diff (new files included)
    remove(path)          -> the worktree and its branch, gone

The lead applies the returned diff with apply_patch (checked, checkpointed for /undo) or reads it and decides
not to. Untracked files in the lead's checkout are NOT copied into the worktree; the builder is told so.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
import uuid


# Variables that tell git WHICH repository to use. Inherited from a git hook (or a shell that set them), they
# override `git -C <path>`: under a pre-commit hook a worktree/commit meant for one repo landed in another
# (2026-11-19, the suite run by the workspace's own pre-commit hook moved its main branch). Every git call the
# harness makes names its repo with -C, so these never belong in its environment.
GIT_LOCATION_VARS = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_COMMON_DIR",
                     "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_PREFIX", "GIT_NAMESPACE")


def git_env(base=None):
    """The environment for a harness git call: the caller's, minus the repository-location variables."""
    env = dict(os.environ if base is None else base)
    for k in GIT_LOCATION_VARS:
        env.pop(k, None)
    return env


def _git(repo, *args, timeout=60):
    r = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, timeout=timeout,
                       stdin=subprocess.DEVNULL, env=git_env())
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def base_dir():
    d = os.environ.get("GNOC_WORKTREE_DIR") or os.path.join(os.path.expanduser("~"), ".gnoc", "worktrees")
    os.makedirs(d, exist_ok=True)
    return d


def create(repo):
    code, top = _git(repo, "rev-parse", "--show-toplevel")
    if code:
        raise RuntimeError(f"{repo} is not a git repo: an isolated builder needs git (git init first)")
    top = top.strip()
    # `git stash create` writes a commit of the working tree WITHOUT touching it or the stash list; empty output
    # means there is nothing uncommitted, so HEAD is the base.
    code, snap = _git(top, "stash", "create", "gnoc builder base")
    base = snap.strip().splitlines()[-1] if (not code and snap.strip()) else None
    if not base:
        code, head = _git(top, "rev-parse", "HEAD")
        if code:
            raise RuntimeError("the repo has no commit yet; commit once so a worktree has something to start from")
        base = head.strip()
    wid = f"{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    path = os.path.join(base_dir(), f"{os.path.basename(top)}-{wid}")
    branch = f"gnoc/build-{wid}"
    code, out = _git(top, "worktree", "add", "-b", branch, path, base, timeout=180)
    if code:
        raise RuntimeError(f"git worktree add failed: {out.strip()[:300]}")
    return path, base


def diff(path, base):
    _git(path, "add", "-A")
    code, out = _git(path, "diff", "--cached", base, timeout=120)
    return out if not code else ""


def changed_files(path, base):
    _git(path, "add", "-A")
    code, out = _git(path, "diff", "--cached", "--name-status", base)
    return out.strip() if not code else ""


def remove(path):
    branch = _git(path, "branch", "--show-current")[1].strip()
    # the MAIN worktree is the first entry of `worktree list`; dirname(git-common-dir) is wrong for a
    # --separate-git-dir repo or a submodule, and the branch then leaked (QAQC r2)
    code, listing = _git(path, "worktree", "list", "--porcelain")
    first = next((ln[len("worktree "):] for ln in listing.splitlines() if ln.startswith("worktree ")), "")
    main = first if not code and first and os.path.realpath(first) != os.path.realpath(path) else None
    if main:
        _git(main, "worktree", "remove", "--force", path)
        if branch.startswith("gnoc/build-"):
            _git(main, "branch", "-D", branch)
        _git(main, "worktree", "prune")
    if os.path.isdir(path):
        shutil.rmtree(path, ignore_errors=True)
