# Scheduled tasks (`/schedule`)

A scheduled task is a prompt gnoc runs on a cron schedule, with no chat open, and a report of what it did. The
README has the short version; this page is how it works and what it will and will not do.

## Commands

| Typed in the chat | What it does |
|---|---|
| `/schedule add "<cron>" <prompt> [--deliver telegram\|desktop\|file]` | save the task and install its timer |
| `/schedule list` | every task, with everything it was saved with and its last run |
| `/schedule run <id>` | start it now, in the background (the same run the timer does) |
| `/schedule rm <id>` | remove its timer or cron line, then its record (past reports stay) |

`add`, `run` and `rm` need a line typed at the prompt, in a terminal: the same identity check as `/file`
(the exact string object the REPL or the one-shot launcher read), plus a terminal on stdin. The second check is
what stops a model's `bash` call from running `gnoc chat "/schedule add ..."`: that launcher treats its own argument
as typed, but a tool's subprocess has stdin on `/dev/null`. `list` only reads, so it needs neither.

From a shell: `gnoc schedule list`, and `gnoc schedule run <id>` (what the timer calls). There is no
`gnoc schedule add`.

## What a run acts under

Saved in the record when the task is added, used for every run, shown by `/schedule list`:

- the scope (the active programme or `HUNT_TARGET`, when one is set) and the working folder;
- the permission rules from `~/.gnoc/permissions.json`, copied in full, with a SHA-256 of them;
- the effort level and its step budget (never unlimited in a run), and the lead and worker models;
- the delivery target, including the Telegram chat id and API base.

A run is a non-interactive agent in its own temporary agent folder, so its settings, conversation and activity
never mix with a chat that is open. Skip-perms and auto mode are off whatever the chat had. Each call that would
ask for approval is recorded and refused: the report lists it as `held for approval: <tool> <summary>`, and nothing
held is executed. Calls refused by a rule (a deny rule, the schedule rule below) are listed too.

Allow rules are exactly the saved ones, so an allow rule added later does not widen an old task. Deny rules are the
saved ones plus today's: a "never do this" rule added after a task was created still applies to it.

Each run stops at a wall-clock cap (900 s by default) and an estimated token cap (about 200,000 tokens, counted
as characters / 4 over every model call). A start while the previous run of the same task is still going is
skipped. Unattended runs do not write lessons.

## Backends

| Machine | What `add` installs |
|---|---|
| systemd user session (`systemctl --user show-environment` answers) | `~/.config/systemd/user/gnoc-schedule-<id>.service` and `.timer`, enabled with `--now` |
| no systemd, `crontab` present | one crontab line ending `# gnoc-schedule:<id>`; every other line is kept as it was |
| Termux (`TERMUX_VERSION`, or `$PREFIX/bin/crond`) | the same crontab line; crond must run (`pkg install cronie termux-services`, `sv-enable crond`) |

The cron line is converted to `OnCalendar` by expanding every range and step into an explicit list, which systemd
reads the way cron does (`0 9 * * 1-5` becomes `Mon,Tue,Wed,Thu,Fri *-*-* 9:0:00`). Where systemd is present, the
string is also checked with `systemd-analyze calendar` before anything is written. What cannot be said exactly is
refused instead of guessed: `@reboot`, a backwards range, and a line restricting both the day of the month and the
weekday (cron runs it when either matches; a systemd timer only when both do). Missed runs are not caught up, as
with cron (`Persistent=false`).

## Delivery

Every run writes `~/.gnoc/schedules/out/<id>/<YYYYmmdd-HHMMSS>.md`, mode 0600 in a 0700 folder. Records live in
`~/.gnoc/schedules/<id>.json`, also 0600 (`GNOC_HOME` moves both).

- `desktop`: a notification through the same notifier as the chat (`notify-send`, a WSL toast, or macOS).
- `telegram`: `sendMessage` to `TELEGRAM_OWNER_CHAT_ID`, with `TELEGRAM_BOT_TOKEN`, both from
  `~/.config/gnoc/secrets.env`. The chat id is read once, when the task is added, and stored; the model and the
  prompt never choose it. The token is read at send time and never stored. The text goes through the secret
  redactor and has the token removed; it is cut at 3,900 characters with the report's path. `TELEGRAM_API_BASE`
  changes the server (it must be https, or plain http to this machine only, because the token is in the URL).
  Calls time out after 15 s, and a failure is written into the run's record without the token.

## The rule the model cannot get around

Only the user sets a schedule. Before any approval question, the dispatcher refuses a model's tool call that would
create, change or run one, with skip-perms and auto mode included, and tells the model the line to give the user:

- `bash` / `bg`: `/schedule`, `gnoc schedule`, running or importing `gnoc_schedule`, any `crontab` other than a
  plain `crontab -l`, `systemctl ... enable|start|...` of a timer, `systemctl edit`, `systemd-run --on-*`, `at` and
  `batch`, a write to a systemd unit folder, `/etc/cron*`, a cron spool, `~/.termux/boot` or the schedules folder,
  and the vulnerability-watch timer (`gnoc_vulnwatch.py timer`, `/defender vulnwatch on|off`);
- `gnoc` tool: `schedule ...` (also in its deny list);
- `defend`: `vulnwatch` with `op=on|off` (the tool itself refuses too), and `/schedule` text in its arguments;
- `write_file`, `edit_file`, `apply_patch`: any path in those folders (patch headers included);
- `claude_worker`: a brief that asks for a crontab, a timer or `/schedule`.

The older `/defender schedule` refusal is unchanged and answers first for its own shape. `/defender vulnwatch on|off`
and `/defender schedule <when>|off` now take the same typed-line check as `/schedule`.

These are pattern checks, a seat belt and not a sandbox: they cover the shapes a model reaches for, and the typed
line and terminal checks above are what keep the commands themselves human-only.
