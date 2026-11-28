# gnoc dash - the redesigned hunt-control dashboard

`scripts/gnoc-dashboard.py` is a second renderer on top of the SAME data layer `gnoc watch` uses.
It imports `scripts/gnoc` read-only (the `gnoc-chair.py` SourceFileLoader pattern), runs its `Feed`
collectors, and never edits or monkeypatches anything in it. `gnoc watch` keeps working unchanged in
behavior; only its panel order (`Look.panels()`) and its timestamp rendering (the shared `_local()`
helper in `scripts/gnoc`, which `gnoc dash` also imports) were touched on 2026-10-21, see below, so
both renderers carry the same visual-flow grouping and the same local-time clock even though each
draws its own panel grid from its own code.

## 1. Panel -> data-source map (recon of scripts/gnoc, 2026-10-21)

Every panel of the classic dashboard reads `Feed.data[<job>]`; `Feed.JOBS` runs each collector on its own
daemon thread (`Feed.start`) or once in parallel (`Feed.once`). Collector -> source on disk:

| classic panel | group | Look method | Feed job -> collector | reads |
|---|---|---|---|---|
| header clock / uptime | - | `Look.header`, `Look.clock`, `Look.wordmark` | `services` -> `d_services` | `/proc/uptime` (host), `pm2 jlist` (orch-bot pm_uptime), `Feed.started` (view) |
| header mode chips | - | `Look.chips` | `hunt`, `system`, `brain`, `metrics`, `oss`, `lab` | `STOP`, `AUTO-HUNT`, `BRAIN.enabled`, global `LOCK`, oss state |
| OSS-BOT SCANNER | flow 1 scan | `p_oss` | `oss` -> `d_ossbot`; word from `oss_state()` | `.claude/state/oss-bot/state.json`, `PAUSE` (INCIDENT latch), `DRAIN`, `bot.db` (runs, leads; read-only sqlite), `review.json`, `triage.json` |
| HUNT | flow 2 hunt | `p_hunt` | `hunt` -> `d_hunt`; `totals` -> `_total_hosts` | `.claude/state/orch/state.json` (current job, heartbeat), `AUTO-HUNT`, `auto-<prog>.json` (swept/hits/leads/parked), `queue.txt`, `orch.log`, `.claude/state/opencode/<prog>-<lane>-*.log` mtime, `scripts/auto-hunt.py hosts()` (plan size) |
| ORCH BRAIN | flow 3 decide | `p_brain` | `brain` -> `d_brain` | `.claude/state/orch/brain.jsonl` (action, status, secs, reason, model), `BRAIN.enabled`, `models.json` roles |
| INBOX / REPORTS | flow 4 ship | `p_inbox` | `inbox` -> `d_inbox`, `reports` -> `d_reports` | `.claude/state/orch/INBOX.md` + `inbox-read.json` (grouped, ranked by `INBOX_RANK`), `reports/` walk (`count_reports`), `_verified_rows()` (READY) |
| MODEL LAB | infra | `p_lab` | `lab` -> `d_lab` | `scripts/model-lab` LAB_DIR `CURRENT`, `runs/<run>/meta.json`, `events.jsonl`, `summary.json` |
| GPU / OLLAMA | infra | `p_gpu` | `gpu` -> `d_gpu`, `desktop` -> `d_desktop` | `http://127.0.0.1:11435/api/ps` (laptop), desktop Ollama over the tunnel, `models.json` |
| DESKTOP | infra | `p_desktop` | `desktop` -> `d_desktop` | desktop `/api/version` + `/api/ps`, `desktop.json` (vram_gb), `desktop-traffic.jsonl` (5 min, 10 s buckets) |
| SYSTEM | audit | `p_system` | `system` -> `d_system`, `services`, `metrics` -> `d_metrics` | `STOP`, `LOCK`, `lib_state.active_programs()` session locks, `lib_policy` word, `HANDOFF-CURRENT.md` section 1 (critical count), running OpenCode drivers, pm2, Burp MCP port 9876, loadavg, `/proc/meminfo`, Ollama `size_vram` |
| OUTCOMES | audit | `p_outcomes` | `changes` -> `d_changes` | `hunt-loop/outcomes.jsonl` (40), `hunt-loop/ships.jsonl` (25), `orch/changes.jsonl` (40), `orch/brain.jsonl` (30), merged newest first |
| command bar | - | `watch()` closures `input_box`, `handle`, `submit_line`, `run_captured`, `run_fullscreen` | none | child `scripts/gnoc <line>` (captured) or the real tty for interactive ones (chair, menu, chat REPL, `--send`, `--attach`) |

**Panel order is an organizing framework, not raw priority (2026-10-21).** Both renderers lay their
cards out in the same three groups, so reading the grid top-left to bottom-right tells the story of
one hunt cycle: **flow** is the pipeline itself (scan for surface -> hunt the focus target -> the
brain decides/pivots -> the report ships), **infra** is what powers that pipeline (model lab, GPU,
desktop link), **audit** is the trail of what the pipeline just did (system/locks, the merged
outcomes feed). `gnoc dash`'s technical-view tab bar shows the three groups explicitly
(`flow[ 1 scan 2 hunt 3 brain 4 inbox ]  infra[ ... ]  audit[ ... ]`); `gnoc watch`'s classic grid
carries the same grouping in `Look.panels()`'s list order (a running Model Lab bench jumps out of
infra into the flow group next to the brain, since that is live pipeline work, not idle capacity).
Change the order in one place (`Technical.PANELS` / `PANEL_GROUP` in `gnoc-dashboard.py`,
`Look.panels()` in `scripts/gnoc`) and it moves consistently.

**All on-screen times are the viewer's local system timezone (2026-10-21), not UTC.** The header
clock, every per-row timestamp in HUNT/ORCH BRAIN/OSS-BOT SCANNER/INBOX/ACTIVITY FEED, all render
through `_local()` (`scripts/gnoc`, renamed from the old `_utc()`), which converts epoch seconds with
`datetime.fromtimestamp(ts).astimezone()`. Table columns use `_when()`: `HH:MM` for today, `MM-DD` for an earlier day (a bare
`01:31` from yesterday used to read as later than now). The RAW LOG TAIL rewrites each line's leading
`[ISO-Z]` stamp to local time (`local_log_line()`), Model Lab shows each run's UTC run-id stamp as a local
`MM-DD HH:MM` column, and `gnoc chair` (header clock, HELM, BRIDGE LOG) follows the same rules. `_ts()` in
`scripts/gnoc` honours an explicit offset (2026-10-22: `ships.jsonl` rows written with `-04:00` were being
read as UTC and drawn 4 h early); a bare or `Z` stamp is UTC as written. Only the DISPLAY changed: `orch.log`, `outcomes.jsonl`,
`ships.jsonl`, `brain.jsonl` and the handoff receipts still store ISO UTC (`...Z`) timestamps on disk
unchanged, so nothing downstream that parses those files needs to change.

Event vocabulary actually seen (seeded the glossary): changes `kind` = pivot, chair, role, stop, resume,
unlock (+ lock, vram, lane, submit written by `_log_change`); brain `action` = pick_target, pivot,
sweep_host, sweep_next, escalate, model-error, follow_up_lane, learn, skip_family, draft, osint, wait,
run_queue; brain `status` = ok, rejected, fallback, wait, error, skip; outcome `verdict` = free text that
STARTS with DEAD, UNFIRED, LEAD, CRITICAL-CANDIDATE, NEEDS, MEDIUM-CANDIDATE, FINDING-CANDIDATE, ...
(matched by prefix); INBOX kinds = AUTO-TARGET, PIVOT, OSS-REVIEW, OSS-SEED, RESCUE-*, OSS-TRIAGE,
AUTO, REVIEW, LANE-DONE, OSS-BACKOFF, EXPLOIT-CANDIDATE, DRAFT, AUTO-LANE, AUTO-HIT, ...; oss-bot jobs =
crawl, enum, nuclei-cve, nuclei-fast, probe, secrets.

## 2. UI stack

Same as `gnoc watch`: Rich renders every panel off-screen into a `Console(file=StringIO)` and the frame is
written as plain ANSI lines inside a synchronized-update block on a raw cbreak tty. Rich's own `Live` and
Textual are not used: the hand-rolled loop already solves flicker, resize and keeping a command box
responsive, and it keeps one look across `gnoc watch`, `gnoc chair` and `gnoc dash`.

## 3. Data/render split

`Feed` (scripts/gnoc) -> `build_snapshot()` (one pass per new Feed version: deep copy, demo scrub, derived
plain-language facts) -> `render_simple(snapshot)` or `render_technical(snapshot)`. Neither renderer reads a
file or calls a collector; both views are built from the identical snapshot object.

## 4. Using it

    gnoc dash                          live (last view + theme; same as python3 scripts/gnoc-dashboard.py)
    gnoc dash --view technical --theme contrast --demo
    gnoc dash --once --size 120x40     one frame to stdout      gnoc dash --snapshot   the snapshot as JSON
    gnoc dash --classic                the old renderer (= gnoc watch, which also still works unchanged)

| key | does (single keys act only while the command box is empty) |
|---|---|
| Tab or v | Simple <-> Technical, remembered in `.claude/state/orch/dashboard-view.txt` |
| 1-9 | Technical: zoom one panel full screen; 0 or Esc back; PgUp/PgDn scroll it |
| , and . | Technical activity feed: cycle the kind filter / the program filter |
| t or Ctrl-T | next theme: neon-noir (default), high-contrast, mono |
| Ctrl-D | demo mode on/off (gnoc watch used Ctrl-D to quit; here q or Ctrl-C quit) |
| q | quit (empty box). Typed words also work: `demo on`, and ` view technical` / ` theme mono` with a leading space, since `v` and `t` on an empty box are the hotkeys |

Every gnoc command works in the box as in gnoc watch (chair, pivot, orch ..., models, dchat, lab ...,
inbox, chat, help, !shell). Colours carry one meaning everywhere: green ok, amber watch, red act, cyan
info, magenta highlight. NO_COLOR or TERM=dumb -> mono; a non-UTF-8 locale or GNOC_ASCII=1 -> ASCII.

Demo mode replaces real program names, SCOPE host labels, report slugs, lane names, hostnames, URLs,
e-mails, IPs and secret-shaped tokens with stable fake ones, in the snapshot (so both views) and in the
captured command-output pane. It cannot cover fullscreen child programs (chair, chat, menu), which draw
their own screens. Screenshots: `scripts/gnoc-dashboard-shots/` (all demo mode, made with
`scripts/gnoc-dashboard-shot.py` in a real pty). Tests: `python3 scripts/test_gnoc_dashboard.py`.
Glossary (edit freely): `scripts/gnoc-dashboard-glossary.json`.

See also scripts/GNOC-LEADS.md (gnoc leads, LEAD LAB).
