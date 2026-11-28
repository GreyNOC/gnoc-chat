# Execution backends (`/sandbox`)

`scripts/gnoc_sandbox.py` decides WHERE the agent's shell runs. It never decides WHETHER a command runs.

## The order of checks

```
model tool call
  -> dispatch._plan_call      refusals (including: a tool naming /sandbox; a host-only tool while a sandbox is on),
                              standing deny rules, the approval engine
  -> t_bash / t_bg
       -> _bash_gates         BASH_DENY, secrets read, sudo, scope gate, target probes
       -> _shell_snapshot     /undo checkpoint material for files the command may delete or rewrite
       -> _bash_run           backend.prepare(cwd) -> backend.exec_argv(...) -> Popen -> wait / kill
       -> _shell_checkpoint
```

The backend object is only obtained inside `_bash_run` and `t_bg action=start`, both after `_bash_gates`. A
denied command is refused before any `docker exec` or `ssh` is built (pinned in
`test_gnoc_phase7_sandbox.py: GatesAreTheSameOnEveryBackend`).

## Backends

| | local | docker | ssh |
|---|---|---|---|
| bash, bg | this machine | `docker exec` into the session's container | `ssh host -- cd DIR && ...` |
| file tools | as before | refused when the realpath leaves the mount | off (PARTIAL), use bash there |
| run_tests, lint, typecheck, git, code_review, gnoc, claude_worker, isolated delegate | as before | refused | refused |
| /undo before rm, sed -i, `>`, truncate, mv | host snapshot | host snapshot (same path through the bind mount) | snapshot and restore through ssh |
| Ctrl-C / cancel / timeout | kill the process group | kill the group inside the container, then the client | kill the group on the host, then the client |

### docker

`DockerBackend.run_argv()` is the whole container definition and is pinned flag for flag by a test:
`--network none` (dropped only by a typed `/sandbox docker --network`), `--user <uid>:<gid>` (plus
`--userns=keep-id` on podman, so the user's id owns files on the mount), `--read-only`,
`--tmpfs /tmp:...`, `--cap-drop ALL`, `--security-opt no-new-privileges`, `--pids-limit 1024`, one
`-v <repo>:<repo>` and nothing else. The mount is refused when it is `/`, your home folder or one of
its parents, or holds `~/.config`, `~/.gnoc`, `~/.ssh`, `/run`, `/etc` and similar.

The container starts on the first command (or when you type `/sandbox docker`), is removed by `/sandbox local`
and when gnoc exits, and a container left by a crashed gnoc is removed the next time one starts. A missing
image is reported with its `pull` line; nothing is pulled during a turn. Only `GNOC_PLAIN`, `HUNT_TARGET`,
`PYTHONDONTWRITEBYTECODE`, `LANG`, `LC_ALL` and `TZ` are passed into the container; `HOME` is `/tmp`.

Why the host-only tools are refused: the repo is writable from inside the container, so code there can write a
`conftest.py`, a linter config or `.git/config` (`core.fsmonitor`, a filter, a hook path). The host would then
execute it the moment run_tests, lint, typecheck or git touched the repo.

### Ctrl-C

`docker exec` does not reliably forward signals, and killing the local client leaves the command running (measured
on podman 5.4). Every command is wrapped so its pid is written to a file in the container's `/tmp`; the kill path
execs a small POSIX script in the container that kills that pid's process group by walking `/proc` (dash, the
Debian `/bin/sh`, rejects `kill -- -PGID`). `_bash_run` now polls `INTERRUPT` and the per-work cancel events while
it waits, so Ctrl-C reaches a running command on every backend, including local.

### ssh

`ssh -T -o BatchMode=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no
-o StrictHostKeyChecking=yes -o ConnectTimeout=10 -o ForwardAgent=no -o ForwardX11=no -o ClearAllForwardings=yes
-o PermitLocalCommand=no -- <host> <command>`. The host must match `[user@]name` and may not start with `-`.
`/sandbox ssh` logs in once (`cd DIR && pwd -P`) before switching. The process-group kill uses `/proc`, so a
Linux host is assumed; on others the kill falls back to the recorded pid.

## Who can switch

Only a line typed at the prompt (`agent._typed_line`, the identity marker `/file` uses). A bash, bg, gnoc, defend
or mcp call whose arguments contain `/sandbox` is refused in dispatch. A session setting that does not validate
(hand-edited) fails closed: commands are refused, never run on the host instead.

## Known limits

- File tools on docker check the realpath and then act; a process in the container racing a symlink swap between
  the check and the write is not prevented (writes still need approval unless `/auto`).
- The ssh backend's file tools are off rather than remote; `/changes` does not show remote files (`/undo` restores
  them through the same host).
- Other host-side tools (web, browser, desktop, MCP servers, scans) are gnoc's own tools with their own gates and
  still run on this machine.
