# Phase 11: public and local repositories

2026-11-27. A public clone is the normal way a coding agent meets code, and it is the one place the harness
had both a missing door and a real safety hole. Found by reading the code and driving the tools on a temp
clone; every item below has a test in `scripts/test_gnoc_repo_20261127.py`.

- Open a remote from the two places a person types: `/repo <url|owner/repo>` and `gnoc chat --repo <url>`
  now go through `gnoc_repo.obtain()`, a shallow single-branch clone into `~/.gnoc/repos/<host>/<owner>/<name>`.
  A local folder keeps its old path. Offline mode refuses a network clone before doing anything.
- Make the cache safe to reuse: `owner/repo` is GitHub only when no local path by that name exists; a URL
  with a username/password is refused (git writes it into `.git/config`); names that could climb out of the
  cache are refused; a directory is reused only when `remote.origin.url` is the same repo, and a different
  origin is reported, never overwritten or deleted. Clone prompts are off and every call has a timeout.
- Make `repo_map` safe on somebody else's tree: a symlink that resolves outside the repo is skipped and
  counted; a path in `sub=` that resolves outside the repo is refused; a file over the definition cap is
  listed without being parsed; the walk stops at the file cap instead of visiting every later directory.
- Stop one bad file from failing the map: `ast.parse` can raise RecursionError on a generated
  `x = 1+1+...` file, which used to escape `repo_map`; it is now an empty definition list, and the file is
  still listed.
- Tell the truth about a search that did not finish: a timed-out `find_symbol` used to say "not found"
  (a timeout produces no hits, so the old note never appended). It now says the search timed out and that
  absence is not established.

Security impact: the clone path never runs repo code and never fetches submodules; the map no longer reads
files outside the active repo through a symlink; a credentialed URL no longer lands in `.git/config`.
Rollback: remove `gnoc_repo.py` and the two `set_repo` branches; `repo_map`/`find_symbol` changes are local
to `gnoc_code.py`.
