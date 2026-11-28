# Hermes gap audit on the synced 2026.11.26 tree

Phase 0, 2026-11-26. The gap list in the brief was written against GitHub d2c33ff (2026.11.25.1). Each item was
re-checked here against the synced 2026.11.26 tree. Paths are relative to `scripts/`; line numbers are those
of 2026.11.26. Verdicts: CONFIRMED (the gap is real), PARTIAL (some of it exists), ALREADY DONE.

## Plan (Phase 0)

- Verify every gap against the code and record file:line evidence (this file).
- Settle the brief's two `RealTurnsRunEndToEnd` failures: an environment cause or a regression.
- Fix the 2026.11.26 tests that pass only on the operator's machine (provenance).
- Make every reference to a file the public build does not ship either work or degrade with a message
  (`docs/plans/phase-0-missing-refs.md`).
- Pin a contract (AGENTS.md) and lint settings (ruff.toml, mypy.ini) so later phases share one standard.

## Verdicts

| # | Gap | Verdict |
|---|---|---|
| 1 | Native providers, prompt caching, real usage | PARTIAL: no native adapter or caching; real usage is read but never billed (bug) |
| 2 | Summarizing compaction with lineage | CONFIRMED |
| 3 | Skills (procedural memory) | CONFIRMED; the trust and scanning parts to reuse already exist |
| 4 | Concurrent subagents | PARTIAL: `fan_out`/`team` already run in parallel; `delegate` takes one task |
| 5 | Messaging gateway | CONFIRMED |
| 6 | General scheduled tasks | CONFIRMED; also a second scheduler the refusal does not cover |
| 7 | Execution backends | CONFIRMED |
| 8 | In-process plugin API | CONFIRMED |
| 9 | Native Termux | CONFIRMED; one Android detector already exists in the engine |
| 10 | Trajectory export | CONFIRMED |

### 1. Providers: PARTIAL

- Every cloud model and the split server go through `gnoc_core/llm.py:870` `_openai_chat`; the body is built at
  `:885-896`, URL and headers come from `gnoc_cloud.endpoint()` (`gnoc_cloud.py:290-307`). Ollama uses `/api/chat`
  (`llm.py:1244-1269`). Cloud routing is at `llm.py:1213-1233`: `gnoc_privacy.why_not("cloud")` first, then
  `gnoc_cloud.redact_messages`, then `_cloud_call` retries (`:1170-1196`).
- Stream and tool-call parsing for the OpenAI wire: `llm.py:912-968` (`MALFORMED_ARGS` marker on bad JSON).
- History is kept in Ollama shape and converted by `gnoc_core/llmwire.py:82` `_to_openai`: the natural seam for
  a provider adapter.
- No Anthropic Messages or Gemini code; `cache_control` appears nowhere. `PROVIDERS` holds only deepseek
  (`gnoc_cloud.py:57-60`).
- Usage: `llmwire.py:267` `_approx_tokens` (chars/4) is the fallback at `llm.py:1229-1230`, `:1237-1238`,
  `:1372`. Ollama reads real counts (`:1333`).
- **Bug the list missed:** `_openai_chat` captures `usage` (`:930`) and hands it only to `MON.record` (`:955`);
  the dict it returns (`:957-969`) has no `usage` key, so `out.get("usage")` at `:1228` and `:1236` is always
  empty. `/usage` shows real tokens, but the economy (`gnoc_economy.debit_llm`, `gnoc_economy.py:536`) is
  always charged chars/4 for cloud and split calls. Phase 1 fixes it.
- Keys: `~/.config/gnoc/secrets.env` (`gnoc_cloud.py:50`, `save_key` `:204`, chmod 600) and inline keys in
  `~/.config/gnoc/cloud-providers.json` (`:54`, `_write_custom` `:147`). Lookup order inline, env, secrets.env
  (`key_for` `:118-129`). Redaction: `gnoc_secrets.redact` (`gnoc_secrets.py:317`), outgoing cloud messages
  `gnoc_cloud.redact_messages` (`:336-367`), tool results `gnoc_core/dispatch.py:105`, activity log `:830`,
  exports `gnoc_core/promptline.py:215`. `GNOC_LLM_TRACE` writes unredacted by design (`llm.py:1398-1421`).

### 2. Compaction: CONFIRMED

- `gnoc_core/compact.py` is regex-only: `_PATHS` `:9`, `_VERDICT` `:12` (hunt vocabulary in a general path),
  `_note_lines` `:24-50`, `_merge_notes` capped at 8000 chars (`:6`, `:53-70`). Folded turns become one user
  message tagged `NOTES_TAG` (`gnoc_core/session.py:26`).
- History is rewritten in place (`_compact`, `compact.py:97-148`), and `Agent.save` (`gnoc_core/agent.py:264-280`)
  overwrites `sessions/<sid>.json`. No parent or child fields.
- Today's protections, which Phase 2 keeps: the newest tool result is never trimmed (the loop is over
  `tool_idx[-6:-1]`, `:119-124`); the current turn (`keep_from`) is never folded (`:129`); an assistant message is
  dropped with all its tool results (`:136-139`).
- Call sites: `agent.py:893` (preflight over 88%), `:1487`, `:1601` (in turn), `:3095` (after the turn, just
  before save), `/compact` `commands.py:1294-1302`, workers `gnoc_tools/agents.py:1556`.
- Session search (`gnoc_recall.py`, FTS5 `msgs(sid, n, role, text)`, `:43-48`) re-indexes a changed session by
  deleting its rows first (`:79`), so once a compacted history is saved the originals are gone from search.

### 3. Skills: CONFIRMED

- No `SKILL.md`, `load_skill` or `/skills` anywhere. `gnoc_learn.py` keeps one-line lessons (`lessons.jsonl`,
  `:37`; `MAX_LIVE=200`; `add` `:304`; `recall_block` `:460`), written by the model via `t_learn`
  (`gnoc_tools/agents.py:168`).
- To reuse: the repo-hook trust model in `gnoc_hooks.py` (`trust` `:78-92` hashes the realpath into
  `~/.gnoc/trusted-hooks.json`; `repo_state` `:126-134`; `active` `:137-166` loads only on a hash match from one
  read, refuses symlinks; user-only `/hooks trust` `commands.py:1313-1322`), the injection scanner
  (`gnoc_comms.injection_signs` `:117-129`, `untrusted()` fence `:132-149`) and the lesson poisoning guard
  (`gnoc_learn._clean` `:375`, `_poisoned` `:384-395`).

### 4. Subagents: PARTIAL

- `t_delegate` (`gnoc_tools/agents.py:1115-1147`) runs one worker (`run_worker` `:1382`) or, `isolated=true`, one
  worktree builder (`run_builder` `:1348`). Builders cannot start builders (`:1133-1134`).
- Parallel workers already exist: `t_fan_out` (`:894`) and `t_team` (`:1072-1105`) use `_parallel`, and
  `run_tools` runs approved calls with `max_workers=4` (`dispatch.py:1098`). What is missing is a bounded pool
  inside `delegate`, per-child budgets and the structured return.
- `t_claude_worker` (`:485-536`) needs the `claude` CLI and runs it with `--permission-mode bypassPermissions`
  (`:519`); its only gate is the `"always"` approval rule (`gnoc_agent.py:1896-1903`).
- Children run `interactive=False`, so `_approve` returns False (`approval.py:469-470`); taint flows back to the
  lead (`agents.py:1398-1425`). Interrupt: process-global `INTERRUPT` plus per-worker cancel events
  (`gnoc_agent.py:373-440`). Claude workers are killed on chat close, not on Ctrl-C.

### 5. Messaging gateway: CONFIRMED

- `gnoc_discord.py` is read-only (`:1-55`), runs a non-interactive Agent on an isolated session (`:243-245`), with
  allowlists (`:126-129`) and an outbound scrubber (`:134-187`). It posts only to the channel of the triggering
  event (`:305-310`, `:352-371`).
- Outbound drafts: `t_draft_outgoing` (`gnoc_tools/comms.py:69-90`) lets the model fill `to`, but only `/send`
  (`commands.py:1181-1199`) sends, after a typed "yes" with a fingerprint match (`gnoc_comms.py:261-282`).

### 6. Scheduling: CONFIRMED

- Defender sweeps go through cron (`gnoc_defender.schedule`, `gnoc_defender.py:1130-1222`), reached only from
  `/defender schedule` (`gnoc_tools/defend.py:550-551`).
- The model refusal is `gnoc_core/dispatch.py:446-455` (bash/bg/gnoc/defend arguments matching
  `/defender schedule|schedule (hourly|every|daily)`).
- **Missed by the list:** `gnoc_vulnwatch.py:905-925` installs a systemd user timer, reachable from a model's
  `defend(action=vulnwatch, op=on)` behind ordinary approval only (`approval.py:56-58`). Phase 6 brings it under
  the same user-only rule.

### 7. Execution backends: CONFIRMED

- bash runs on the host: `t_bash` (`gnoc_tools/proc.py:181`) → `_bash_gates` (`:298-320`) → `_bash_run` (`:323+`).
  File tools are in `gnoc_tools/fs.py`. No docker or ssh backend.
- Gates every backend must keep: `dispatch.py:350` `_plan_call`, `:1057` `run_tools`, `approval.py:174`
  `_approval_required`, `:461` `_approve`; scope `shellsafe.py:597-622` `_scope_gate_bash`, `gnoc_tools/net.py:79`
  `_program_gate`; `BASH_DENY` `shellsafe.py:182`, `WRITE_DENY` `paths.py:21`; undo checkpoints `proc.py:232-278`
  into `session._checkpoint` (`session.py:267`).
- SSH plumbing to build on: `gnoc_link.py` (`ssh_base` `:233`, `run` `:242`).

### 8. Plugins: CONFIRMED

- `gnoc_hooks.py` reads `~/.gnoc/hooks.json` plus a trusted `<repo>/.gnoc/hooks.json` (`:44-49`); only `pre_tool`
  and `post_tool` (`_load` `:104-123`); a pre hook exiting 2 blocks (`:246`). Wired at `dispatch.py:110-140`.
- Permissions live only in `~/.gnoc/permissions.json` (`gnoc_perms.py:12-20`, `:60`).

### 9. Termux: CONFIRMED

- `install.sh` branches only on Darwin vs everything else (`:21-24`, `:53`) and suggests `sudo apt`.
  `gnoc_doctor.py` has no platform branch; `gnoc_setup.py:190-193` knows wsl, linux, darwin.
- To reuse: `gnoc_engine.py:1124-1127` `on_android()` (getandroidapilevel, `TERMUX_VERSION`,
  `/data/data/com.termux`).

### 10. Trajectory export: CONFIRMED

- `gnoc_learn.log_trajectory` (`gnoc_learn.py:817-835`) appends
  `{ts, program, outcome{ok, failed, verdict, receipt, good}, messages[{role, content[:4000], tool_calls?,
  tool_name?}]}` to `trajectories.jsonl` (`:41`). User text and tool-call arguments are not redacted at write.
- No export command. To build on: `/export` (`promptline.py:173`, redacted `:215`) and `gnoc_distill.py`
  (OpenAI tool-call SFT JSONL with redaction).

## Missed by the gap list

1. The economy is always billed chars/4 for cloud and split calls (gap 1).
2. Repo slash commands (`.gnoc/commands/*.md`, `.claude/commands/*.md`) load with no trust step and no injection
   scan, and a repo file overrides a user command of the same name (`gnoc_hooks.py:291-340`); running one marks
   its text as typed by the user (`commands.py:1393`). Skills must not copy this, and it should be brought under
   `/hooks trust` (not fixed in Phase 0: it changes user-visible behaviour, so it is the operator's call).
3. Repo instruction files (CLAUDE.md, AGENTS.md, GNOC.md, README) are injected after a scan only, with no trust
   step (`prompts.py:377-393`).
4. The vulnwatch systemd timer escapes the user-only schedule rule (gap 6).
5. `claude_worker` runs `bypassPermissions` behind one approval (gap 4).
6. The provenance guard of 2026.11.26 never engaged in a packaged install: it fixed its root to the install dir
   instead of the workspace. Fixed in Phase 0 (`fix(provenance)`).
7. `run_tests(name=...)` counted a Node 20 no-match as a pass. Fixed in Phase 0 (`fix(run_tests)`).
8. The 2026.11.26 package ships `VERSION` 2026.11.25 because the release builder (outside this repo) stamps the
   date per invocation. Fixed in the repo (`fix(release)`); the builder still needs the fix.
9. No contract or lint config existed. Added AGENTS.md, ruff.toml, mypy.ini.

## The brief's two failing tests

`RealTurnsRunEndToEnd::test_a_command_that_was_held_is_not_reported_as_run` and
`..._is_marked_unchecked` failed on d2c33ff "as root in a container". Results here, on both d2c33ff and this
tree:

| run | result |
|---|---|
| ordinary user, this machine | pass |
| uid 0 (podman user namespace) | pass |
| uid 0, `sudo` removed from PATH | pass |
| uid 0, empty HOME, clean environment, no sudo | pass |
| uid 0 in a `python:3.12-slim` container with git, full suite, with and without a git identity | pass |

Verdict: not reproducible on either tree in six environments, so no environment cause can be named and no skip
was added (a skip without a stated cause would hide a regression). If they fail again, the failing container's
`id`, `which sudo git node`, `git config -l` and the assertion text settle it.

The container run found three other environment-dependent failures, fixed in Phase 0:

- `bbtools/test_egress_redirect.py` (4 tests) crashed without `curl_cffi`, a declared requirement. They now
  skip with that reason.
- `ComputerUse20261123::test_locate_scales_the_models_box_back_to_the_screen` assumed ImageMagick or Pillow was
  present to resize the shot. The code is right without them (it scales by the shot's own size); the test now
  pins what the model sees and adds a test for the no-resizer path.

The bisection turned up two other environment-dependent results instead:

- `test_a_node_run_that_matched_no_test_is_not_a_pass` failed whenever `/usr/bin/node` (Node 20) came first on
  PATH. That is a real defect in `run_tests`, not the environment; fixed, with tests for both TAP shapes.
- `GnocNeverPausesItself20261123` failed when HOME was under `/tmp`, because `is_protected_proc` treats anything
  under `/tmp` as untrusted, including a llama-server under such a HOME. That is the test's environment (no real
  HOME lives under /tmp), so it is left as is.
