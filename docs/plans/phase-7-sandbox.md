# Phase 7: execution backends (sandbox)

## Plan

- New `scripts/gnoc_sandbox.py`: one backend interface (`exec_argv`, `kill`, `prepare`, `file_refusal`,
  snapshot/restore) with `local` (today's Popen, unchanged), `docker` (one container per session: no network,
  non-root, read-only rootfs + tmpfs, `--cap-drop ALL`, `no-new-privileges`, only the repo bind-mounted at the
  same path) and `ssh` (key-only, `StrictHostKeyChecking=yes`, a configured remote directory).
- The backend is reached only from `_bash_run` and `t_bg` AFTER `_bash_gates`, and only after `_plan_call` has run
  its refusals and the approval engine, so the deny list, secrets check, scope gate and approvals stay identical.
  Undo checkpoints keep working: host-side on docker (same path), through the backend on ssh.
- File tools on docker refuse any path whose realpath leaves the mount; on ssh they are off (PARTIAL: they would
  act on this machine) and bash on the remote is the way. Tools that would run repo code on the HOST (run_tests,
  lint, typecheck, git, code_review, gnoc, claude_worker, isolated delegate) are refused on docker/ssh.
- Ctrl-C and per-work cancel events kill the command inside the container / on the remote (pidfile + process-group
  kill exec'd in the sandbox), not just the local client; the local backend gains the same Ctrl-C kill.
- `/sandbox [local|docker [--network] [--image X]|ssh <host> [dir]]`, typed-only for changes; a bash/bg/gnoc call
  naming /sandbox is refused like a schedule; `/auto on` with docker/podman available prints a one-line tip.

## What was built

- `scripts/gnoc_sandbox.py`: `LocalBackend` (byte-for-byte the old Popen), `DockerBackend` (docker or podman,
  container per conversation, pinned `run_argv`), `SshBackend` (key-only, known_hosts-only, remote directory),
  `BrokenBackend` (a setting that does not validate fails closed). Registry keyed on the session's sid + setting;
  workers share the lead's backend because they copy its session dict.
- `gnoc_tools/proc.py`: `_bash_run` and `t_bg start` go through the backend after `_bash_gates`; `_bash_run` polls
  `INTERRUPT` and the per-work cancel events so Ctrl-C kills the command (inside the container / on the host for
  the sandboxes); the shell checkpoint reads remote files through ssh. `gnoc_bg.start` takes a backend argv and a
  killer.
- `gnoc_core/paths.py` `_sandbox_fence`, called by `_fence` (read_file, list_dir, grep) and by find_file,
  write_file, edit_file, apply_patch. `gnoc_tools/fs.py` `/undo` restores ssh checkpoints through the same host.
- `gnoc_core/dispatch.py`: a call naming `/sandbox` is refused (bash, bg, gnoc, defend, mcp); host-only tools are
  refused while a sandbox is on. `gnoc_core/commands.py`: typed-only `/sandbox`, `/auto on` tip. Help updated.
- Tests: `scripts/test_gnoc_phase7_sandbox.py` (41 with fakes, 3 real-container tests behind `GNOC_TEST_DOCKER=1`,
  all 44 pass on podman 5.4.2 with python:3.12-slim).

## Security impact

Tightening only. No gate moved: the backend is reached after every existing refusal, deny list, secrets check,
scope gate and approval, and the same tests prove denied commands never reach docker or ssh. New refusals: tools
naming /sandbox; host-executing tools while sandboxed; file paths leaving the mount. The local backend behaves as
before except that Ctrl-C now kills a running bash command instead of leaving it to its timeout.

## Rollback

Revert the feature commit. The only persisted state is `s["sandbox"]` in the per-terminal settings file; with the
code reverted it is ignored (an unknown key). `/sandbox local` clears it without a revert.

## Left

- ssh file tools are PARTIAL (off, bash on the host instead). `/changes` skips remote files.
- A symlink swapped inside the container between the realpath check and a host-side write is not prevented.
- The ssh process-group kill assumes `/proc` (Linux remote).

## Release note

gnoc chat can now run its shell somewhere other than your computer. `/sandbox docker` gives each conversation its
own container (docker or podman) that sees only the repo you are in, with no network unless you type
`--network`, your own user id, a read-only system and no extra privileges; `/sandbox ssh <host>` runs commands on
another machine with key login only; `/sandbox local` comes back. Approvals, the deny list, the secret check and
`/undo` work the same everywhere, Ctrl-C stops the command inside the container too, and only you can switch.
Development: GreyNOC (Brad), with Claude (Anthropic) as a development contributor.
