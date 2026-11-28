# Hunt fleet - many agents, many targets, no collisions

Run several hunt agents in parallel, each pinned to a different program, without them
stepping on each other. Bulletproof by construction: an atomic filesystem mutex, per-process
target binding, and self-healing after a crash.

## Why it exists
The old loop had ONE global `LOCK` file naming ONE program. A second parallel session just
overwrote it, so two agents could not safely hunt two programs at once. The fleet gives every
agent its OWN target binding and an atomic claim.

## The model (three properties)
1. **Per-process pin.** The launcher exports `HUNT_TARGET=<handle>` for each agent. Hooks and
   `loop-select-target.sh` read that env var first, so "which target am I on" needs no shared
   file and cannot be clobbered by a sibling. No `HUNT_TARGET` set means fall back to the legacy
   global `LOCK` - a lone session behaves exactly as before.
2. **Atomic claim.** `hunt-fleet.sh claim` uses `mkdir` (one atomic syscall) as the mutex.
   Under N concurrent claimers on the same target, exactly one wins; the rest are refused. A
   claim mid-write (dir made, owner not yet stamped) is never stolen.
3. **Self-heal.** A claim is alive while its process is alive (`kill -0` on the same host) or its
   heartbeat is younger than `HUNT_FLEET_TTL` (default 1800s). A crashed agent goes stale and the
   next claimer steals its target. No program stays wedged.

## Launch and monitor
```
scripts/hunt-fleet-launch.sh zksync-os arm-oeth alchemix-1   # one agent per handle
scripts/hunt-fleet-launch.sh -n 4                            # top-4 from priority.txt
scripts/hunt-fleet-launch.sh --list                         # who owns what (alive/stale/stop)
scripts/hunt-fleet-launch.sh --attach                       # tmux attach to watch them
scripts/hunt-fleet-launch.sh --stop  zksync-os              # graceful: exits after current run
scripts/hunt-fleet-launch.sh --kill  zksync-os              # hard: kill window + release now
scripts/hunt-fleet-launch.sh --stop-all                     # flag every agent to stop
```
Each agent runs in its own tmux window inside session `huntfleet`, supervised: when a `claude`
session ends the supervisor relaunches it (indefinite hunt), with a crash-loop guard that gives
up after 5 fast failures so a broken setup never spins. A target with no `targets/<handle>/SCOPE.txt`
is skipped - onboard it first (`scripts/h1-scope.sh` / `ywh-scope.sh` / `immunefi-scope.sh`).

Overrides: `FLEET_MODEL` (default opus), `FLEET_CLAUDE_ARGS`, `FLEET_PROMPT`, `FLEET_TMUX`.

## Ownership primitives (used by hooks and the selector)
```
scripts/hunt-fleet.sh claim <target> [sid] [pid]   # atomic claim; exit 1 if a live sibling holds it
scripts/hunt-fleet.sh current [sid]                # the target this session should hunt
scripts/hunt-fleet.sh release [target] [sid]       # drop a claim
scripts/hunt-fleet.sh beat [target] [sid]          # refresh heartbeat
scripts/hunt-fleet.sh owned-by-others [sid]        # targets a live sibling holds (selector skips these)
scripts/hunt-fleet.sh list | gc | stop <t> | resume <t> | stopped [t]
scripts/hunt-fleet.sh selftest                     # 9 locking checks
```

## State on disk (`.claude/state/hunt-loop/fleet/`)
```
claims/<target>/{owner,pid,host,beat,since}   # one dir per claimed target (mkdir = the lock)
sessions/<sid>                                # reverse pointer: which target a session owns
stops/<target>                                # per-target graceful-stop flag
```
Every file is one small value; there is no read-modify-write on shared state, so nothing races.

## Verify it
```
scripts/hunt-fleet.sh selftest            # SELFTEST OK
scripts/hunt-fleet-launch.sh --selftest   # SELFTEST OK  (dry-run, no claude launched)
```

## Notes
- The global `LOCK` and `STOP` still work as the single-session controls. A global `STOP` file
  stops EVERY agent (kill switch); to stop just one, use `--stop <handle>` (per-target).
- `HUNT_FLEET_DIR` / `HUNT_FLEET_ROOT` / `HUNT_FLEET_TTL` env vars relocate state and tune the TTL
  (used by the self-tests to run against a temp dir).
