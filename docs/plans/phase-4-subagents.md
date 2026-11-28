# Phase 4: concurrent subagents

- `delegate(tasks=[...])` runs several children through ONE process-wide bounded pool (`gnoc_subagents.POOL`,
  cap from `GNOC_DELEGATE_CAP` or `~/.gnoc/settings.json`, default 3), on the existing `_parallel` threads and
  cancel chain; `delegate(task=...)` keeps working and takes a pool slot too, so parallel delegate calls in one step
  never exceed the cap in total.
- Each child: fresh history, a read-only toolset (write tools only for `isolated` children, inside their own
  worktree via the builder's `root_override`), its own wall clock and a token budget counted from real usage
  (`gnoc_monitor` sink; chars/4 only when a call reported none) and charged to the turn's tally.
- Children never approve, spawn, schedule or widen scope: one refusal in `dispatch._plan_call` for every worker,
  no inherited `/auto`, and an approval-needing call comes back to the lead as a `needs_approval` request.
- Children end with a JSON summary `{result, evidence, files, open_questions}` parsed tolerantly; the harness adds
  `needs_approval`, `tokens` and `status`.
- `claude_worker` says plainly when the `claude` CLI is missing (it is already not offered then), keeps its
  `always` approval, and Ctrl-C now kills the claude workers this chat started (their process groups).

## What was built

- `scripts/gnoc_subagents.py` (new, stdlib, no facade lookups): `ChildPool`/`POOL`, the settings readers
  (`delegate_cap`, `child_token_budget`, `child_seconds`, `clamp_budget`), `CHILD_READ_TOOLS`, `child_refusal`,
  `needs_approval_line`, the summary schema (`SUMMARY_NOTE`, `parse_summary`, `status_of`, `summary`, `render`) and
  the claude-worker registry with `kill_claude_workers` (every process group in the worker's session).
- `t_delegate` takes `tasks=[...]` (strings or `{task, isolated, tokens, seconds}`), validates every task before any
  child starts, runs them on `_parallel` threads that each take a `POOL` slot (interruptible wait), and renders one
  JSON summary per child. `task=` keeps its digest; it now also takes a slot, uses the read-only toolset and appends
  any held request.
- `run_worker` / `_run_worker_body`: `_child` contexts drop the inherited `/auto`; a per-child token budget read
  from a `gnoc_monitor.tally` sink (real usage via `MON.record`, a chars/4 `calls=0` estimate only for a call that
  booked nothing); `worker hit its token limit` digest. Also fixed: default workers died on `KeyError:
  'site_status'` in the public edition (WORKER_TOOLS names a tool the edition drops).
- `dispatch._plan_call`: `child_refusal` for every worker before the allow-list check; a `_child`'s
  approval-needing call is returned as `not run: held for the lead (needs approval: ...)` and recorded.
- `gnoc_monitor.record(..., calls=1)` and `tally()`; `rails._tool_limit` gives a queued `tasks` call
  rounds x wall; the delegate schema, approval rule (any isolated task asks) and copy-gate cover `tasks`.
- `t_claude_worker`: names the missing CLI and its install command; registers the worker; Ctrl-C (both turn
  handlers and the REPL's) calls `_stop_claude_workers`.

## Security impact

Tighter, nowhere looser. Children lose the lead's `/auto`, lose the state-writing worker tools, and are refused
spawn / schedule / scope / policy tools in dispatch whatever list they are handed. An approval a child needs is
surfaced to the lead instead of being silently declined; it is never queued or granted in the child's name. The
pool cap and budgets live only in the user's home (`GNOC_HOME`), so a repo cannot widen them, and a per-task
budget can only lower them. `claude_worker` keeps its `always` approval. `-s-p` (skip-perms) is a launch-wide user
choice and still applies to children, as before.

## Rollback

Revert the feature commit. `delegate(task=...)` callers are unaffected either way; `tasks=` disappears. No stored
state or file format changes (settings.json is optional and only read).

## What is left

- `gnoc_session._kill_lanes` (chat close) very likely has the same process-group gap the Ctrl-C path had (by reading, not tested): it TERMs the
  wrapper's group, and `timeout` moved `claude` into its own group. Not changed here (it is the chat-close path,
  outside this phase); the session-walk in `gnoc_subagents._session_groups` is the fix to reuse.
- Ctrl-C kills every claude worker this chat started, including one started in an earlier turn (the spec says
  Ctrl-C cancels every child). If that proves too broad, scope it to the current turn's workers.
- fan_out and team still use their own width (`/reasoning`) and WORKER_TOOLS; they do not take POOL slots.

## Release note

`delegate` can now hand several jobs to helper workers at once: `tasks=[...]` runs them through one shared pool
(3 at a time by default, `GNOC_DELEGATE_CAP`), each with a fresh conversation, a read-only toolset, its own time
and token budget, and a JSON report (result, evidence, files, open questions, held approvals, tokens, status).
Helpers never approve, spawn, schedule or change scope; what they needed approved comes back to you. Ctrl-C stops
every helper and any Claude Code worker the chat started, and `claude_worker` explains how to install the CLI
when it is missing. Development: GreyNOC (Brad), with Claude (Anthropic) as a development contributor.
