# gnoc models and the orch-bot brain

What exists as of 2026-10-21. Sources: the `scripts/gnoc-models.py` and `scripts/orch_brain.py` docstrings
and the `gnoc` help text. `gnoc` itself is `scripts/gnoc`; `~/.local/bin/gnoc` is a symlink to it.

## Roles

Three roles, stored in `.claude/state/orch/models.json` and read on every call:

| role | used by |
|---|---|
| `brain` | orch-bot decisions (`scripts/orch_brain.py`) |
| `chat` | `gnoc chat` |
| `hunter` | OpenCode lanes (written into `.opencode/agent/hunter.md` and `~/.config/opencode/opencode.json`) |

A role value of `model@desktop` runs on the linked Windows desktop and falls back to the laptop model
whenever the desktop is off (`scripts/llm_endpoints.py`).

## gnoc models

| command | what it does |
|---|---|
| `gnoc models` | installed models, which role uses each, whether it fits the GPU |
| `gnoc models search <words>` | Hugging Face GGUF repos, most downloaded first |
| `gnoc models files <owner/repo>` | quantisations in a repo with sizes (Q4_K_M is the usual 8 GB choice) |
| `gnoc models pull <owner/repo>[:QUANT] [--as NAME]` | download into the local model server (gnoc's engine, `gnoc engine`, or an Ollama) and build a 16k-context NAME (default `<repo>-oc`) |
| `gnoc models use <role> <model>` | give a model a role (brain, chat, hunter) |
| `gnoc models test <model> [n]` | Model Lab QUICK suite (`scripts/model-lab/lab.py bench <model> --suite quick`), scored 0..100; run before giving a new model a role. Falls back to n dry-run orch decisions if model-lab is missing |
| `gnoc models rm <model>` | remove (refused while a role uses it) |
| `gnoc models desktop` | linked desktop: tunnel up, its models, what is loaded |
| `gnoc models desktop vram <GB>` | tell the rig the desktop GPU size (for the fits-GPU column) |

`--on desktop` on list, files, pull, use, test, rm acts on the DESKTOP's Ollama through the reverse SSH
tunnel at `127.0.0.1:11436` (set up once with `scripts/desktop-link/link-desktop.ps1`). Role changes are
journaled to `.claude/state/orch/changes.jsonl`.

## gnoc orch brain

`gnoc orch brain on|off|why [n]|test|snapshot`

- `on` / `off`: toggles `.claude/state/orch/BRAIN.enabled`. `off` is how to disable it; orch-bot then
  runs its old fixed rules.
- `why [n]`: the last n decisions from the journal.
- `test`: dry run, executes nothing.
- `snapshot`: the compact hunt snapshot the model is shown.

orch-bot calls the brain only when IDLE (no job running, no hand-started lane, no STOP). The brain builds
a snapshot (focus program, unswept host families, recent sweeps and hits, escalations, lane queue, inbox,
candidate programs, its own last decisions and results), asks for ONE action as schema-constrained JSON,
VALIDATES it in code, executes it and journals it. If the model is down, slow or invalid, orch-bot falls
back to the fixed rules for that tick.

The 10-action menu (the model never gets a shell, never files, never edits a report):
`run_queue`, `sweep_host`, `sweep_next`, `skip_family`, `escalate`, `follow_up_lane`, `pivot`,
`pick_target`, `notify`, `wait`.

Hard limits stay in code, not in the model: SCOPE.txt on every URL, the program's automation ban
(auto-hunt refuses), STOP, GET only.

## Files (all under `.claude/state/orch/`)

- `BRAIN.enabled` - on/off switch.
- `brain.jsonl` - decision journal.
- `BRAIN-NOTES.md` - standing notes GreyNOC can edit; fed to the model every call.
- `changes.jsonl` - change journal (role changes, pivots, STOP), capped at 2000 lines by gnoc.
- `models.json` - the role table above.

## GPU limits

- 8 GB VRAM, ONE model loaded at a time (ollama-oc, `127.0.0.1:11435`, one slot).
- The brain shares the hunter model by default (qwen3-14b-oc) so a decision never forces a model swap.
  Override with `ORCH_BRAIN_MODEL` / `ORCH_BRAIN_URL`.
- qwen3-14b-oc (Q4_K_M, partly offloaded) is about 210 s per turn; 7-8B Q4_K_M fits fully on the GPU.
- NEVER point anything at the system Ollama on port 11434: it auto-picks num_parallel=2 and silently
  truncates prompts at about 8k.
