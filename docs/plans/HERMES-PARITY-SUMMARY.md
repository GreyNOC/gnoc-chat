# Hermes parity: what was built, how it was checked, what is left

2026-11-26. Development: GreyNOC (Brad), with Claude (Anthropic) as a development contributor.
Nothing here was pushed, tagged or published. Every phase is a local branch for review.

## Branches

All phase branches start at `7d6d6d6` (Phase 0 merged), which descends from the sync commit `f5a86d3`.
`hermes/integration` merges every phase and the later Phase 0 fix, so it shows that they work together.

| Branch | What | Suite on the branch (passed / skipped / failed) |
|---|---|---|
| `sync/2026.11.26` | verified 2026.11.26 tree, VERSION fix, /file regression tests | 905 / 10 / 3 (the 3 are fixed in Phase 0) |
| `phase-0/audit-baseline` | gap audit, provenance root fix, Node 20 run_tests fix, environment test fixes, missing-file references, AGENTS.md, ruff/mypy config, `_turn` NameError fix | 944 / 10 / 0, then the NameError fix and its test |
| `phase-1/providers` | adapter seam, native Anthropic + Gemini, prompt caching, real usage billing | 996 / 10 / 0 |
| `phase-2/compaction` | archive-first lineage, validated worker summary, recall over archives | 980 / 10 / 0 |
| `phase-3/skills` | SKILL.md store, load_skill, typed `/skills review`, repo trust | 995 / 10 / 1 (timing flake, see below) |
| `phase-4/subagents` | concurrent `delegate(tasks=[...])`, one bounded pool, child refusals | 985 / 10 / 0 |
| `phase-5/gateway` | Telegram, Slack, Signal, email, Discord on one core; owner-only approvals | 1037 / 10 / 0 |
| `phase-6/scheduler` | typed `/schedule`, systemd/cron/Termux crond, held actions reported | 984 / 10 / 0 |
| `phase-7/sandbox` | local / docker / ssh backends behind the same gates | 985 / 13 / 0; 44/44 against real podman |
| `phase-8/plugins` | in-process plugins that can tighten, never loosen | 982 / 10 / 0 |
| `phase-9/termux` | Termux detector, install dry run, doctor, setup, reduced defender | 990 / 10 / 0 |
| `phase-10/export` | redacted ShareGPT/OpenAI export, headless batch runner | 979 / 10 / 0 |
| `hermes/integration` | all of the above together | **1420 / 13 / 0** |

Each count above is the lead's own rerun, not the worker's report. The one flake,
`HeadlessBrowsersCloseWhenTheChatIsDone::test_the_persistent_hunt_profiles_are_never_touched`, waits a fixed
0.5 s for a real process. It failed only while several suites ran at once, and passed 3 of 3 alone on the branch,
the base and integration.

Each phase's plan, outcome, security impact, rollback and release note are in `docs/plans/phase-<n>-*.md`.

## Defects found and fixed along the way

1. The 2026.11.26 package's `VERSION` file says `2026.11.25`, so installs keep offering 2026.11.26. Fixed in the
   repo; the release builder that caused it (it stamps the date each time it runs) is outside this repo.
2. The 2026.11.26 provenance guard never engaged in a packaged install (its root was fixed to the install dir).
3. `run_tests(name=...)` read a Node 20 "nothing matched" as a pass.
4. A refused `record_outcome` in hunt mode raised NameError in `Agent._turn` (bare `re`), since 2026.11.25.1.
5. Cloud and split model calls were always billed at chars/4: real usage never reached the economy (Phase 1).
6. In the public edition every default worker crashed on `KeyError: 'site_status'` (Phase 4).
7. A hookless public install ran bash with no scope check while a programme was active (Phase 0).
8. The vulnwatch systemd timer could be turned on by a model through bash (Phase 6: now typed-only).

## Integration notes

- The gateway (Phase 5) and the scheduler (Phase 6) named the same Telegram settings differently. On integration
  the scheduler also reads `GNOC_TELEGRAM_OWNERS` / `GNOC_TELEGRAM_API`, with a test.
- The scheduler uses Phase 9's single Termux detector on integration.
- The approval block in `dispatch.py` was combined by hand: plugin "add only" check first, then the gateway's
  remote approver or the local prompt.

## Open items

- Slack, Signal, email and the native provider wires are tested only against in-process fakes built to the
  documented shapes, not live accounts.
- Repo slash commands (`.gnoc/commands/*.md`) still load with no trust step and can override a user command; repo
  instruction files are injected after a scan only. Bringing them under `/hooks trust` changes visible behaviour,
  so it is left for a decision.
- Chat close may leave a `claude` worker alive (same process-group cause Phase 4 fixed for Ctrl-C); not tested.
- Archived compaction segments are never pruned.
- `curl_cffi` has no Android wheel, so the Termux install may fail to build its environment; untested on a phone.
