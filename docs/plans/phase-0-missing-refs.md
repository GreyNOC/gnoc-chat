# Phase 0: references to files the public build does not ship

- Scan every `scripts/**/*.py` and the `gnoc` CLI for file names, `scripts/...` paths, imports and
  `spec_from_file_location` targets that do not exist in this tree, then read each hit in context and decide
  whether it is executed, imported or opened at runtime, and whether a public code path can reach it.
- Replace what is a general feature: the MCP `sse` transport (a stdlib SSE client in `gnoc_mcp.py`), the Burp
  history lookup on top of it, `gnoc models test` without the Model Lab, and the bash scope gate without its hook.
- Degrade the rest with one line that names what is missing and what to do instead (`gnoc_missing.note`), failing
  closed wherever the missing file was a safety control (bash scope gate, Discord scrubber).
- Leave hint text, comments, prompt examples, deny patterns and test fixtures alone; list them so the next pass
  can reword user-facing hints that name operator-only scripts.
- Pin each replacement and degrade with negative cases in `scripts/test_gnoc_public_refs_20261126.py`.

| reference | where | executed? | action taken |
|---|---|---|---|
| `burp-mcp-cli.py` | `gnoc_mcp.py` `_SseTransport` | imported for every `--transport sse` server | replaced: stdlib HTTP+SSE client (endpoint event, same-origin check, per-call timeouts) |
| `burp-mcp-cli.py` | `gnoc_web.py` `_burp` (Burp history check behind the panels tool) | imported | replaced: one `gnoc_mcp` SSE session per lookup, clear message when Burp is down |
| `mcp_sse_stdio_bridge.py`, `burp-mcp-cli.py` | `gnoc_mcp.py` docstring | no | example-only (docstring reworded) |
| `.claude/hooks/scope-gate.sh` | `gnoc_core/shellsafe.py` `_scope_gate_bash` | executed on every bash command | replaced: SCOPE.txt fallback via `lib_scope.program_allows`, fails closed (was: silently allowed) |
| `.claude/hooks/scope-gate.sh` | `bbtools/scope_proxy.py` `HOOK` | opened | already tolerant: no toolchain allowlist is stricter; proxy not started by public code |
| `scripts/hq` | `gnoc_tools/hunt.py` `t_hunt_search` | executed | degraded: names the index, points at grep / find_file (was FileNotFoundError) |
| `orch_brain` | `gnoc-models.py` `cmd_test_legacy` | imported by `gnoc models test` | replaced: JSON arithmetic smoke test, scored, latency per answer |
| `model-lab/lab.py` | `gnoc-models.py` `cmd_test` | executed when present | already guarded (isfile); now falls through to the smoke test |
| `intel/intake.py`, `h1-feedback/sync.sh`, `learn/consolidate.py`, `learn/pipeline-sweep.py`, `reports.sh`, `targets/.../p.py`, `orch_brain` | `gnoc_company.py` departments | executed as background jobs | degraded: `main` refuses in the public edition (`gnoc company` was already off the public CLI) |
| `intel.intake` | `gnoc_learn.py` `intel_recall` / `intel_block` | imported (no caller in tree) | degraded: documented empty result; a broken import inside the package still raises |
| `gnoc-dashboard.py` | `gnoc_discord.py` `load_scrubber` | imported | degraded fail-closed (RuntimeError with reason) and `main` refuses in the public edition |
| `gnoc-office.py` | `gnoc_tools/agents.py` `t_office_funnel` | executed | already gated: tool removed when `PUBLIC` |
| `gnoc_file` | `gnoc_core/commands.py` `/file` | imported | already gated: `OPERATOR_COMMANDS` |
| `server.js` (site dir) | `gnoc_redteam.py` | opened | already gated: `site_redteam` removed when `PUBLIC`; unreadable file already reported |
| `scripts/video/desktop/task.mjs` | `gnoc_image.py` `free_orphan_runners` | executed when present | already guarded (exists check, returns "") |
| `browser-budget.py` | `gnoc_panels.py` | executed when present | already guarded (advisory by design) |
| `desktop-link/link-desktop.ps1` | `gnoc-models.py` desktop | opened (isfile) | already guarded |
| `targets/<program>/LOGIN.py` | `gnoc_ident.py` | executed | user-authored per programme; already a clear refusal when absent |
| `scripts/h1-feedback/out` | `gnoc_pay.py`, `gnoc_economy.py` | opened | already tolerant (OSError / isdir) |
| `patterns/*`, `Manual/*`, `HANDOFF-CURRENT.md` | `gnoc_doctrine.py`, `gnoc_line.py`, `gnoc_dedup.py`, `gnoc_hunt.py` | opened | already tolerant (`_read` returns "") |
| `scripts/workbench/*`, `intel/intake.py`, `phone-link/*`, `gnoc-dashboard.py`, ... | `gnoc` CLI operator subcommands | executed | already gated: `PUBLIC_COMMANDS` |
| `desktop-link/traffic_proxy.py` | `test_gnoc_multimachine.py` | test | already skipped when absent |
| `h1-submit-report.py`, `gnoc_file.py` | `gnoc_core/shellsafe.py` | no | example-only (deny patterns, kept) |
| `reports.sh`, `venue-reports.py`, `public-dedup.sh`, `intake.sh`, `burp-start.sh`, `cdp-chrome.sh`, `h1-scope.sh`, `bugcrowd-scope.sh`, `convert_hf_to_gguf.py`, `gnoc pivot` | hint text in messages and docstrings | no | example-only; follow-up: reword the user-facing hints in the public edition |
| `store.py`, `report.py`, `pricing.py`, `slug.js`, `todo.py`, `server.js`, `lab.py`, ... | comments, prompt examples, incident notes | no | example-only |
| `gnoc-phone-setup.sh` | `gnoc_phone.py` | written by the code itself | n/a |

Counts: 26 rows. Replaced 4, degraded 4, already gated, guarded or tolerant 13, example-only 4, n/a 1.
