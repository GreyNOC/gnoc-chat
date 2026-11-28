# gnoc leads - LEAD LAB (the rescue-pipeline board)

`gnoc leads` -> `scripts/gnoc-leads.py`. A live board of every item in
`.claude/state/hunt-loop/rescue-ledger.json`: which leads a worker is testing right now and what that
worker is doing this minute, a per-lead drill-down, and a backlog-health verdict. It is NOT Model Lab:
`gnoc lab` is still Model Lab (`scripts/model-lab`). Spec: `scripts/learn/SPEC-gnoc-leads-20261021.md`.

    gnoc leads                 live (Simple view by default; prefs in .claude/state/orch/leads-view.txt)
    gnoc leads --once [--size WxH] [--view simple|technical] [--demo]    one frame
    gnoc leads --snapshot      the JSON both views are drawn from
    gnoc leads --once --drill <id>   one drill-down (the printed frame grows to fit it)

## Panel -> source

| panel | Feed job (cadence) | reads |
|---|---|---|
| header, WORKING NOW, LEADS, OPEN LEADS, WAITING ON YOU, LIVE WORKERS | `leadlab` (3 s) | the ledger (lock-free, it is written by atomic replace), `/proc/*/environ`, `/proc/<pid>/stat` + `cmdline`, the worker's session transcript (RUNNING rows only), `ps -s <pid>` for its current child |
| PIPELINE HEALTH, BACKLOG HEALTH | `leadlab` + `sweepproc` (30 s) | ledger `_meta` (dispatch_log, last_sweep), `RESCUE-DISPATCH.enabled`, `STOP`, `pm2 jlist` (pipeline-sweep, orch-bot, oss-bot) |
| chain map line (PIPELINE HEALTH, simple view) | `leadlab` | ledger `_meta.chain_map` (pid, ts, reaped), newest `reports/leads/<p>/chains/CHAINMAP.md` mtime, `CHAIN-DISPATCH.enabled`; a `RESCUE_ITEM=chainmap:<p>` process whose pid matches `_meta.chain_map[<p>].pid` is listed as `chainmap_live`, not as an orphan |
| RESCUE ACTIVITY | `leadlab` | `outcomes.jsonl` rows whose lane starts `rescue-` (re-parsed only when the file changes) |
| uptime ribbon | `services` (5 s, gnoc's `d_services`) | `/proc/uptime`, pm2 |
| drill-down (on demand, at most every 2 s) | none | the item's ladder (from the ledger), HELD-REASON / LEAD file / WHY-ARCHIVED / DEAD-CONFIRMED / KILLPASS, the newest hunt STATUS.md, the `.out`, outcomes, brain.jsonl + changes.jsonl |

State classification and score come from `pipeline-sweep.py` itself (`state_label`, `score`,
`program_busy`), imported read-only, so the board and the sweep can never disagree.

## How a live worker is detected

- `dispatch` stays on a ledger row after the worker ends (reap only adds `reaped`), so "has a dispatch"
  is not "live". RUNNING = dispatch pid set, no `reaped`, the process alive, AND its environment carries
  the matching RESCUE_ITEM tag (that is the pid-reuse check). Alive without the tag = GONE-PID-REUSED;
  dead and not reaped = EXITED-UNREAPED (the next sweep logs it); reaped = DONE.
- The tag lives only in the child's ENVIRONMENT, so `pgrep -f` (argv) can never see it. The board scans
  `/proc/<pid>/environ` in Python and never puts that literal in any argv.
- A text-mode worker writes its `.out` only at exit: 0 bytes while running is normal. The live signal is
  the transcript `~/.claude/projects/-home-you-gnoc-workspace/<uuid>.jsonl` whose first 8 KB carries
  `"agentSetting"` and `RESCUE of <id> (`. A `.out` that starts `API Error` is shown as `api-error`.
- ORPHAN = a tagged process that is neither a ledger row's live worker nor one of its children.

## Health

CLOGGED when over half the open leads are untouched > 7 days or the backlog needs > 14 days at the daily
cap (`RESCUE_DAILY_CAP`, default 2); BEHIND when anything is stale or it needs > 3 days; else KEEPING UP.
pm2 `pipeline-sweep` shown as `stopped` is NORMAL: it is a cron job (`23 */4 * * *`, autorestart off),
shown as "between runs (cron)". Only errored or missing is red. Ledger older than 5 h = sweep overdue.

## Keys

Box empty: Up/Down select (scroll in a drill-down), Enter open/close, Esc back, `,` filter (open, live,
waiting, all), `.` program, Tab/v view, 1-4 zoom (Technical), PgUp/PgDn scroll, Ctrl-P/Ctrl-N command
history, t theme, Ctrl-D demo, q quit. Letters are never bound by this board (each starts a gnoc command).

Read-only: it never writes the ledger, INBOX, outcomes or reports/, never opens the ledger lock, never
signals a process. The only file it writes is its prefs file. Tests: `python3 scripts/test_gnoc_leads.py`.
