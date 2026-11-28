# GNOC COMPANY - the bots run the business, orch-bot is the manager

Spec: `scripts/learn/SPEC-xbow-intel-economy-20261022.md` section 5. Code: `scripts/gnoc_company.py`.
Tests: `python3 -W error::ResourceWarning scripts/test_gnoc_company.py` (temp state, no network, no model).

## How it runs

There is no second daemon. orch-bot (pm2 `orch-bot`) calls `gnoc_company.manage(st)` once per tick as ONE wrapped
step (`company_step` in `scripts/orch-bot.py`, marked `# COMPANY`). A failing duty is journaled and the others still
run; a failing `manage` is logged and the tick still saves `state.json` (tested).

| duty | cadence | what it does (all numbers by code) |
|---|---|---|
| payroll | every tick | roster from `gnoc_economy`: role, wallet, brier, status (working, idle, probation, paused), assignment, morale; a bot under 100 RC is on probation (keeps worker duty, loses lead and brain duty) |
| learn | 1 h | per bot and per (program, class) records in `manager-journal.jsonl`; beliefs ("worker on business-logic lanes: 3/3 reached LEAD or better ...") go through `gnoc_learn.worth_keeping`, `grounded`, then `add` |
| sales | 30 min | crowns from `leads-queue.jsonl`, `RESCUE-BOARD.md` and the AUTO-HUNT pick; only programs `gnoc_pay.filing_gate` lets us file on; ranked by the class steer (business logic, improper auth first) and freshness; the treasury funds bounties for the top 3 (300 medium, 600 high, 1000 critical, times a class factor); one WORK ORDER per bounty through `gnoc_line.open` (station 0) |
| hunt | every tick | STOP absent and AUTO-HUNT set: one company lane for the highest open bounty that has a work order goes into `.claude/state/orch/queue.txt` (`program|lane|brief|probes|A|wo=<id>`); the brief carries the 1:1 paragraph, a code-built facts block, the oracle class, the budget and `gnoc_line.brief`; the chosen bot claims the bounty (bond) |
| intel | 24 h | background: `intake.py fetch --cap 30`, `extract --extractor local` (the spec's `--backend` is spelled `--extractor` in intake.py), `index --no-hq` |
| qa | 30 min | background: `pipeline-sweep.py sweep` (only when `RESCUE-DISPATCH.enabled`), `reports.sh status`; every READY draft in `reports/STATUS.md` section 2 gets one line in `reports/INBOX.md` (never submitted) |
| books | 24 h | background: `h1-feedback/sync.sh` when the H1 token is configured (else `consolidate.py`); `sweep_expired` |
| bonus | daily | 2% of the previous UTC day's mint, from the treasury, paid by code in thirds: best brier, best RC per probe, and every bot whose floor-met honest DEADs beat its floorless DEADs |
| retro | weekly | `research/retro/RETRO-<date>.md`: what paid, what burned RC for nothing, exactly THREE proposals with supporting rows and a kill byte each, filed as PROPOSAL lines in `reports/INBOX.md`; also re-derives the bounty class factors and the advisory routing weights |
| train | daily | the worst-brier bot re-runs `scripts/gnoc-curriculum/core.txt` through `gnoc_train.py` (background, STOP absent); the previous run's grade is journaled |
| bubble | 1 h | the manager's one line for the office |

Background jobs run detached (`start_new_session`), one per duty at a time, output in `.claude/state/economy/logs/`.

## The floor is the line (builder G, 2026-10-23)

Every tick, after payroll, `floor()` computes by code: `kanban` (per station of scripts/HUNT-PROCESS-V2.md, its
INBOX = items waiting for that station's work; SALES = funded rewards with no work order yet; caps `WIP_CAP` SALES 3,
INTEL 3, MODEL 2, MARKET 4, PROBE 6, ESCALATE 2, QA 2, BOOKS 4, overridable per key in company.json `wip_cap`), the
`bottleneck` (fullest inbox against its cap, ties downstream) and the `pull` station (the station just upstream of
the bottleneck if it has work and feeding it would not overfill the bottleneck, else the bottleneck). A full inbox
refuses new work in code: `fund_bounties` stops at the SALES cap, `open_work_orders` waits (not dead) while INTEL is
full, `hunt` skips a work order whose next station is full and queues the pull station's work first, with the bot the
floor staffed there. `desks` = the PROBE floor by evidence (precision ledger JSON through prt.LEDGER: classes with
n >= 5 and >= 30% accepted first, then Other, then ONE trap desk, open only for a work order whose seed names a new
root cause). `staffing` = real work first, then free lane bots best evidence first (RC per probe, brier, class yield),
one per desk. `standup` = open by station, yesterday's P&L, bottleneck, three oldest, HIRING (`plain` text), the
manager's daily line. Then `story()` writes plain sentences to `.claude/state/economy/story.jsonl` (last 20, code
only) and `screen()` builds the office's plain-words view (`NAMES`, `PLAIN`, `stars`, boards, TODAY, JAM, legend).
`gnoc company status` prints a FLOOR block. The bots are the local ones only (`gnoc_economy.participants()` at
runtime): Rex (lead, the desktop RTX), Q (worker, the local 9B), Pip and Pico (the phone 4B and 1.7B), Echo
(reflector), Scanner Sam (oss-bot), The Manager (orch-bot). brain, chat and hunter are role aliases folded into the
bot that owns their model (`aliases()`); they get no desk and no separate story line.

## NUMBERS by code, VOICE by model

No allocation, bonus, demotion, bounty size, work order or queue line reads model output. The model writes only the
1:1 paragraph, the manager bubble and the retro prose, through `orch_brain.voice`. A reply that adds or changes a
number, or is empty, is thrown away for the code template (`_clean_voice`). Morale is a number and changes only the
tone the manager is asked for.

## The manager thinks on the phone

`.claude/state/orch/models.json` (set with `gnoc-models.py save_roles`): `brain` =
`hf.co/mradermacher/Qwen3-4B-abliterated-GGUF:Q4_K_M@phone` (host `phone` = 127.0.0.1:11441 in `llm_endpoints.HOSTS`),
`brain_fallback` = the local Huihui Qwen3.5 9B. `orch_brain._call` sends `"think": false` to the phone, waits at
most `ORCH_BRAIN_PHONE_TIMEOUT` (60 s), and on a refused connection, a timeout or an empty reply journals
`brain-fallback` ("brain fallback: phone <reason>") in `brain.jsonl` and asks the next model. Every decision row
records `model`, `host` and `fallback`. `gnoc orch brain why` shows the fallback lines.

## STOP and PAUSE

- `.claude/state/hunt-loop/STOP`: stops lanes (the hunt duty and training). Payroll, sales, books, intel, QA, learn,
  bonus and retro keep running.
- `.claude/state/economy/PAUSE`: pauses the whole company. orch-bot's tick does nothing but record
  `company_paused` and save its state; `manage` only writes `paused: true` to company.json.
- Both are drawn in the office (COMPANY PAUSED, LANES STOPPED signs).

## Safety

- Nothing is ever submitted to a platform. READY drafts and proposals go to `reports/INBOX.md`.
- The settler token (`.claude/state/economy/.settler`) is read only inside `fund_bounties` (a treasury-funded post
  needs it) and `bonus`; it is never printed or written anywhere else.
- Lanes still pass orch-bot's `start_lane` gates: `lib_policy.network_ok`, every probe host in SCOPE.txt. The company
  adds `lib_scope.program_allows` per host and skips verify-only and no-bounty rows.
- The manager never edits SPINE, CLAUDE.md or the Manual; retro proposals are for GreyNOC.

## State

`.claude/state/economy/company.json` (schema 1): `schema, updated, started, paused, stop, auto_hunt, last{duty},
roster[{bot, role, wallet, brier, status, probation, assignment, run, rc_per_probe, morale}], kanban, desks, desks_source, staffing, standup, screen, story_cursor, reserve (treasury
balance), escrow, bot_of_day, bets[] (open hypothesis markets), bounties[], pnl{minted_24h, burnt_24h, net_24h,
drafts_24h, ready_24h, rc_per_draft, rc_per_ready, dupe_odds}, picks[], refused_programs{}, work_orders{bounty:
{wo_id, check}}, queued, bonus, cells, beliefs, class_factor, routing, jobs, manager{bubble, voice}, errors, results`.
The office spells three keys differently on purpose (`bets`, `reserve`, `run`): see office-docs/CHANGES.md.

`.claude/state/economy/manager-journal.jsonl`: append-only (flock + fsync) rows of kind bot, cell, belief,
belief-refused, bounty-post, bounty-skip, work-order, lane-queued, job, books, bonus, retro, train, train-grade,
voice-rejected, voice-error, duty-error.

## CLI

    gnoc company status | journal [n] | retro | manage
    gnoc econ status | audit | bet | bounty | settle
    gnoc line open | advance | market | status | brief ...

## Office

`gnoc-office` (default `GNOC_OFFICE_BOTS_ONLY=1`) draws the company: see `scripts/office-docs/OFFICE_HANDBOOK.md`
and `ELEMENT-SOURCE-MAP.md` (COMPANY floor section). Fixture: `python3 scripts/office-docs/render_scenes.py`.
