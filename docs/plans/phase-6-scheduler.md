# Phase 6: general scheduled tasks (`/schedule`)

- New `scripts/gnoc_schedule.py`: schedule records in `~/.gnoc/schedules/<id>.json` (0600 files, 0700 dir) that
  carry the prompt, the cron line, the delivery target and a snapshot of what was in force at creation (scope,
  folder, permission rules plus their hash, effort, lead/worker model), installed as a systemd user timer, else a
  marked crontab line, or a crontab line for Termux crond. 5-field cron is converted to `OnCalendar` faithfully or
  refused with the reason.
- `/schedule add "<cron>" <prompt> [--deliver telegram|desktop|file]`, `/schedule rm <id>` and `/schedule run <id>`
  run only from a line typed at the prompt (the `/file` identity check); `/schedule list` may be untyped and shows the
  snapshot. `gnoc schedule run <id>` is what the timer calls.
- A run is a non-interactive Agent on an isolated agent dir, with the snapshot applied (rules, effort, model,
  scope, folder), skip-perms off, a wall-clock cap and an estimated token cap. Every call that needs approval is
  recorded as held and listed in the delivery; nothing held runs.
- Delivery: a 0600 Markdown file always, plus a desktop notification (gnoc_notify) or a Telegram message to the
  owner chat id read from `~/.config/gnoc/secrets.env` when the schedule is created (never from the model or the
  prompt), through `gnoc_secrets.redact`, with timeouts and a configurable API base.
- Model refusal extended in `dispatch.py` to `/schedule`, `gnoc schedule`, crontab edits, systemd user units and
  timers, `systemd-run --on-*`, `at`, Termux boot/crond files and the schedules dir, for bash/bg/gnoc/defend and the
  file tools; the vulnwatch systemd timer comes under the same user-only rule.

## What was built

- `scripts/gnoc_schedule.py`: records, cron parsing and `OnCalendar` conversion (ranges and steps expanded into
  lists, checked with `systemd-analyze calendar` where it exists; `@reboot`, backwards ranges and a line restricting
  both day of month and weekday are refused with the reason), backend detection (Termux, then a systemd user
  session, then crontab), install and uninstall (systemd units 0600; one crontab line marked
  `# gnoc-schedule:<id>`, every other line kept), `add` / `remove` / `listing` / `run_now`, the run itself, delivery
  and `model_refusal`.
- `/schedule add|list|rm|run` in `gnoc_core/commands.py`. add, rm and run need the `/file` typed-line identity AND a
  terminal on stdin (a tool's subprocess has `/dev/null`, and the one-shot launcher marks its own argv as typed, so
  identity alone would not stop `bash: gnoc chat "/schedule add ..."`). `/defender vulnwatch on|off` and
  `/defender schedule <when>|off` take the same check. `/help` lists it under long tasks.
- `gnoc schedule list|run <id>` (public CLI); `schedule` added to the gnoc tool's deny list.
- A run: non-interactive Agent in a temporary agent dir under `~/.gnoc/schedules/runs/`, with the snapshot applied
  (allow rules exactly as saved, deny rules saved plus today's, effort with a bounded step budget, lead and worker
  via `GNOC_ROLE_*`, folder, scope), skip-perms and auto off, lessons off, a wall-clock cap (900 s) and an estimated
  token cap (200,000, chars / 4 at `llm_chat`), a per-task lock. `_approve` is swapped for a recorder that always
  answers no, so every held call is listed as `held for approval: <tool> <summary>`; refusals by a rule are listed
  too. Every facade change is undone afterwards.
- Delivery: a 0600 report file always; desktop through `gnoc_notify.notify(force=True)`; Telegram `sendMessage` to
  the owner chat id saved at creation, token read at send time, text through `gnoc_secrets.redact` with the token
  removed, 15 s timeout, https only (plain http to loopback for tests).
- Model refusal in `dispatch.py` for bash/bg/gnoc/defend/write_file/edit_file/apply_patch/claude_worker, after the
  existing `/defender schedule` refusal (unchanged, still answers first for its shape).
- Vulnwatch: the audit's named path (`defend(action=vulnwatch, op=on)`) did NOT install the timer; it fell through
  to a status read. The real model paths were bash `gnoc_vulnwatch.py timer on` and bash `gnoc chat "/defender
  vulnwatch on"` (the one-shot launcher marks argv as typed), behind an ordinary approval, so none under -s-p. Both
  are refused now, and `defend(vulnwatch, op=on|off)` refuses explicitly with the line to type. No existing test
  asserted the model could do it, so no test was changed.

## Security impact

New surface: a way to run the agent unattended. It goes through the existing gates rather than around them: the
approval gate (non-interactive, recorder answers no, skip-perms forced off), the permission rules (snapshot; deny
rules can only grow), the dispatcher refusals and scope pin (`HUNT_TARGET` from the snapshot), and secret redaction
on everything delivered. "Only the user sets a schedule" is extended from defender sweeps to every scheduler shape a
tool call can reach, and to the vulnwatch timer. The Telegram recipient comes only from the user's config at
creation time. Records and reports are owner-only.

Limits, stated: the refusals are pattern checks (a seat belt, not a sandbox), and `claude_worker` is checked only
by its brief, since it runs another agent with its own permissions (gap 4). The token cap is an estimate.

## Rollback

Revert the three phase commits. Schedules already installed keep firing `gnoc schedule run <id>`, which then fails
with "unknown command"; remove them with `systemctl --user disable --now gnoc-schedule-<id>.timer` and the unit
files in `~/.config/systemd/user/`, or the crontab lines ending `# gnoc-schedule:<id>`, and delete
`~/.gnoc/schedules/`.

## What is left

- Delivery through the Phase 5 gateway, once it lands, instead of the small built-in Telegram sender.
- A `/schedule edit`; today a change is `rm` then `add`.
- `claude_worker` still runs with bypassPermissions behind one approval (gap 4); its brief check here is partial.

## Release note

Scheduled tasks: `/schedule add "<cron>" <prompt> [--deliver telegram|desktop|file]` runs a prompt unattended on a
cron schedule, as a systemd user timer, a crontab line, or a Termux crond line. Only you can set, run or remove a
schedule, from a line you type in a terminal; the model cannot, and neither can it turn the hourly vulnerability
watch on or off any more. A scheduled run never executes anything that needs approval: it lists each held action in
its report. It runs with the folder, permission rules, effort and models in force when you created it (a deny rule
you add later still applies), and `/schedule list` shows them. Reports are saved to a private file and can also go
to a desktop notification or your own Telegram chat. Development: GreyNOC (Brad), with Claude (Anthropic) as a
development contributor.
