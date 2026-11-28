# Phase 8: in-process Python plugins

- New `scripts/gnoc_plugins.py`: load `~/.gnoc/plugins/<name>/plugin.py` or `<name>.py` only (never a repo or
  cwd), under a namespaced module name, from the same bytes that were hashed; refuse symlinks out of the folder
  and group/world-writable files; load only what `/plugins enable <name>` (typed-only, like `/file`) pinned by
  sha256, so a changed plugin stops loading until it is enabled again.
- Events `pre_tool`, `post_tool`, `pre_llm`, `post_llm`, `approval_request`, `approval_response`,
  `session_start`, `session_end`; a handler passes (None), blocks or rewrites. Each handler has a time budget;
  a raise or a timeout fails CLOSED for `pre_tool`, `pre_llm` and `approval_request`, OPEN for the rest.
- Core gates own every decision: a `pre_tool` rewrite goes through `_plan_call` and the tool's own gates again,
  and approval is required if the ORIGINAL or the REWRITTEN call needs it; `approval_request` can only add a
  requirement; `approval_response` only observes; `pre_llm` runs before redaction and the privacy switch.
- Plugin tools and commands cannot shadow built-ins; plugin tools always ask unless the user saved a
  `/permissions allow <tool>` rule. The model cannot write `~/.gnoc/plugins/` (write tools and shell).
- Shell hooks (`gnoc_hooks.py`) are untouched. Tests in `scripts/test_gnoc_phase8_plugins.py`.

## What was built

- `scripts/gnoc_plugins.py`: discovery, integrity (tree sha256 of every plugin file, one read of the entry file
  for hash and exec), mode/owner/symlink refusals, `enabled.json`, a registry that reloads when `enabled.json`
  changes, the eight events with per-handler time budgets, plugin tools (`sync_tools`) and commands, `/plugins`
  listing, the model-write refusal, and `~/.gnoc/plugins.log`.
- Wiring: `dispatch.run_tools` (pre_tool before planning; `_plugin_force` judges approval on the original call),
  `dispatch._plan_call` (force_approval, approval_request/approval_response, the plugins-folder refusal),
  `dispatch._exec` (post_tool before the provenance fence and redaction), `llm.llm_chat` (pre_llm before
  `_llm_chat_once`, which applies privacy and redaction; post_llm on the answer), `approval._approval_required`
  (plugin tools ask unless a `/permissions` rule allows them), `gnoc_perms` (a registered plugin tool can get a
  whole-tool allow rule), `paths._write_refusal` (defence in depth), `cli.repl` (session_start / session_end and
  tool registration), `commands.handle_slash` (`/plugins`, typed-only enable/disable, plugin commands after every
  built-in), help text.
- Docs: README "Plugins" paragraph and table row; `docs/GNOC-PLUGINS.md` (API, enforcement, failures, limits).
- Tests: `scripts/test_gnoc_phase8_plugins.py`, 38 tests.

## Security impact

New surface: user-installed Python runs in-process. It is reachable only from `~/.gnoc/plugins`, only after a
typed `/plugins enable`, only while every file matches the recorded sha256, and never when group/world-writable
or symlinked out. Every plugin effect goes through the existing gates: a rewrite is re-planned and approval is the
union of original and rewritten; approval_request can only tighten; approval_response is observe-only; pre_llm
precedes redaction and the privacy switch; plugin tools always ask unless the user saves a rule; names cannot
shadow built-ins; the agent's write tools and shell refuse the plugins folder. Guards fail closed, observers fail
open. Not a sandbox: a plugin is the user's own code with the user's rights (documented).

## Rollback

Revert the feature commit. With no `~/.gnoc/plugins/enabled.json` present every hook is a no-op (one `stat` per
event), so disabling all plugins (`/plugins disable <name>` or deleting `enabled.json`) is the runtime rollback.
Shell hooks were not changed.

## What is left

- The shell-side refusal is pattern based (a seat belt). A determined shell command the user APPROVED could still
  write the folder and `enabled.json` itself (as it could edit `~/.bashrc`); the sha256 pin stops a plugin file
  dropped there from running unless `enabled.json` also names its hash, and stops a changed enabled plugin.
- A pre_tool handler that times out keeps running in a daemon thread (Python cannot stop threads).
- post_llm cannot rewrite tool calls (deliberately); only text.
- Plugin tools enabled from another open chat appear in this chat at its next start.

## Release note

gnoc chat now supports Python plugins. Put a plugin in `~/.gnoc/plugins/` and type `/plugins enable <name>`: it
can watch, block or rewrite tool calls and model calls, observe approvals and sessions, and add its own tools and
slash commands. A plugin can make gnoc stricter but never looser: a rewritten action is checked again and still
asks for approval if the original did, only you approve, rewritten messages are still scrubbed of secrets before
a cloud model, and plugin tools ask every time until you allow them. A plugin stops running if its files change,
and gnoc refuses plugin files that other users can write. Shell hooks work exactly as before.
Development: GreyNOC (Brad), with Claude (Anthropic) as a development contributor.
