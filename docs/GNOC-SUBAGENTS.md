# Subagents: how delegate runs children

`delegate` hands work to child workers. This page is the reference; the README has the short version.

## Calling it

```
delegate(task="read src/store.py and list its public methods")
delegate(tasks=["read src/a.py and ...", "read src/b.py and ...", {"task": "fix the off-by-one in c.py and run its tests", "isolated": true}])
```

- `task=` (one child) returns that child's digest, as it always did. A call the child could not make because
  it needs approval is appended under `HELD FOR APPROVAL`.
- `tasks=[...]` runs every task at once through the pool and returns one JSON summary per child:

  ```json
  {"result": "...", "evidence": ["file:line", "..."], "files": ["..."], "open_questions": ["..."],
   "needs_approval": ["needs approval: http_request POST https://..."], "tokens": 18342, "status": "done"}
  ```

  `result`, `evidence`, `files` and `open_questions` come from the child's closing JSON (read tolerantly: fenced or
  bare, prose around it, a trailing comma; with no JSON at all, `result` is the child's whole answer).
  `needs_approval`, `tokens` and `status` are filled in by gnoc, never by the child. `status` is one of `done`,
  `failed`, `cancelled`, `time_limit`, `token_limit`, `step_limit`.
- A task can be an object: `{"task": ..., "isolated": true, "tokens": 20000, "seconds": 120}`. `tokens` and
  `seconds` can only LOWER the configured budget, never raise it.
- Every task is validated before any child starts; one bad task refuses the whole call.

## The pool

One pool for the whole process (`gnoc_subagents.POOL`). Every child of every delegate call takes a slot, so two
delegate calls in the same step (the lead's tool calls run side by side) still run at most the cap at once; the
rest wait in the queue. The cap is `GNOC_DELEGATE_CAP`, else `"cap"` in the `"delegate"` block of
`~/.gnoc/settings.json` (`GNOC_HOME` moves it), default 3, at most 8. A repo cannot set it.

```json
{"delegate": {"cap": 3, "child_tokens": 150000, "child_seconds": 210}}
```

## What a child gets

- A fresh conversation: its system prompt and its task, nothing from the lead's history.
- A read-only toolset: reading and searching files, past hunts and the web, and the GET probe tools. The tools
  that write files or harness state (graph upserts, saved identities, oracle commits) are not in it.
- `isolated: true` makes it a builder: write and test tools, confined to its own git worktree, returning a patch
  the lead reviews and applies with `apply_patch` (that apply asks for approval like any edit). Starting an
  isolated child asks for approval, as `delegate(isolated=true)` always did.
- Its own wall clock (`child_seconds`, default `GNOC_WORKER_WALL` or 210 s; builders 900 s) and token budget
  (`child_tokens`, default 150000). Tokens are counted from the usage the model server reports for each call;
  only a call that reports none is estimated at characters/4. Past either limit the child stops taking steps and
  writes its digest; that one closing call is allowed past the token budget.
- Its tokens are booked on the turn's tally (the footer and `/usage`) as well as its own.

## What a child can never do

Refused in `dispatch._plan_call` for every worker bot, whatever tool list it was handed:

| | tools |
|---|---|
| start another child | `delegate`, `fan_out`, `team`, `claude_worker`, `second_opinion`, `escalate` |
| set a schedule, goal or background job | `goal`, `tasks`, `defend`, `gnoc`, `bg` |
| widen its scope | `set_program`, `pick_target`, `change_dir` |
| write standing policy | `learn`, any `propose_*` |

It cannot approve anything either. A child does not inherit the lead's `/auto`; a call that needs approval is not
run and not queued in its name: it comes back in `needs_approval`, and the lead runs it itself, which asks the
user the ordinary way. (`gnoc chat -s-p` is a launch-wide choice the user made and still applies.)

## Ctrl-C

Ctrl-C sets the process-wide interrupt and cancels every child's chain: running children stop at their next
streamed chunk, queued ones never start, and the call returns them as `cancelled`. It also kills the process
groups of the `claude` CLI workers this chat started (they already stopped when the chat closed). The worker runs
under coreutils `timeout`, which moves `claude` into a process group of its own, so gnoc kills every group in the
worker's session, not only the wrapper's.

## claude_worker

Optional. Without the `claude` CLI on PATH it is not offered to the model, and a call made from memory gets a
message naming the install command. Its approval rule is unchanged: it asks every time, auto mode included.
