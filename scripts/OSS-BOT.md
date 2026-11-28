# oss-bot - background OSS scanner (one screen)

pm2-managed, scope-proxied, policy-gated. Every output is a forced `LEAD`, never a finding.
Design and build receipts: `scripts/learn/OSS-BOT-SPEC-20261021.md`, `CLAUDE-HANDOFF-CRITICAL-10-05.md`
("OSS-BOT PHASE 0/1/2" entries).

## What it runs

Six jobs, in order of first use: `enum` (subfinder passive, third-party sources only) -> `probe`
(httpx on exact SCOPE rows + the newest enum hosts) -> `nuclei-fast` (exposure/misconfig/takeover
templates on live URLs from a fresh probe) -> `nuclei-cve` (high/critical CVE templates, lower
rate) -> `crawl` (katana, stores responses for the secrets job) -> `secrets` (gitleaks + trufflehog
+ semgrep, LOCAL ONLY, never opens a network connection, `--no-verification` so a found credential
is never used).

## The three scope nets (independent of each other - any one failing fails closed)

1. **Input filter**: every host/URL handed to a tool is pre-checked by
   `bbtools.lib_scope.program_allows` (NOSCOPE first, third-party, internal IP, SCOPE allowlist).
2. **The proxy**: every network job runs behind a per-job `scope_proxy.py` that re-resolves and
   re-checks every connection itself (no DNS-rebind TOCTOU) and denies by default.
3. **Post-run audit**: every host that appears in a tool's own output must have an `allowed:true`
   row in that run's `egress.jsonl`, or the run's leads are dropped, `.claude/state/oss-bot/PAUSE`
   is set, and `.claude/state/hunt-loop/SCOPE-INCIDENTS.md` gets an entry.

## Policy gate

`bbtools.lib_policy.policy(program)` reads `targets/<p>/PROGRAM.md` for an automation ban, a
stated rate limit, and the program's identification header; no PROGRAM.md = excluded (fail
closed). `bot.py plan` prints the status/evidence/rps/header for every program. An override lives
in `.claude/state/oss-bot/policy-overrides.txt` (ban always wins over allow; allow-lines are
GreyNOC's call only).

## Cadence and tiers (`config.json`)

Tier P0 = a live fleet claim / LOCK / the current `AUTO-HUNT` program (swept most often). P1 =
`priority.txt` / `priority-vdp.txt`. P2 = everything else eligible (no-yield.txt programs are
P2-skipped). A NEW-HOST event on a P0/P1 program's probe run triggers `nuclei-fast` on just those
hosts immediately.

## Output layout

```
targets/<p>/recon/oss-bot/{leads.jsonl, hosts.jsonl, urls.jsonl, SEEDS.md, STATUS.md, runs/...}
.claude/state/oss-bot/{bot.db, STATUS.md, state.json, PAUSE, bot.log, hq-rebuild.json}
```
`SEEDS.md` (top 15 open leads) is what a hunter or hypothesis-generator actually reads - every row
is LEAD-only, scanner silence is not a negative, verify each by hand before using it.

## CLI

```
bot.py status                  one-screen digest (read THIS, not raw tool output)
bot.py plan [p]                 policy/tier/evidence table
bot.py run <p> <job> [--dry]    one manual job
bot.py proxytest <p>            offline proof every tool routes through the proxy
bot.py leads [p] [--top N]
bot.py mark <fp> fp|dupe|verified-elsewhere "<why>" [--rule]
bot.py pause | resume
bot.py selfcheck                offline: lib_scope, lib_policy, proxy, ingest, db CHECK
bot.py daemon                   the pm2 loop (OSS_BOT_DRY=1 -> logs would-run argv, fires nothing)
```

## Pause / STOP / rollback

- Pause just this bot: `bot.py pause` (writes `.claude/state/oss-bot/PAUSE`) or `pm2 stop oss-bot`.
- `.claude/state/hunt-loop/STOP` pauses oss-bot too, along with orch-bot and every other hunt-loop
  consumer system-wide - it is a shared flag, never create or remove one you did not set yourself
  without a real reason.
- Back to dry mode: set `OSS_BOT_DRY=1` in `scripts/oss-bot/ecosystem.config.cjs`, then
  `pm2 restart oss-bot --update-env && pm2 save`.
- Full rollback: `pm2 delete oss-bot && pm2 save` (outputs are inert data; optional purge:
  `rm -rf targets/*/recon/oss-bot .claude/state/oss-bot`), or `git revert <phase-sha>` per phase.

## Known limits (as of 2026-10-21)

- No LLM anywhere in the scanning engine (`llm_triage` is off by default and unimplemented).
- No VDP-program ranker yet - `priority-vdp.txt` only self-heals on the HackerOne-paid side
  (`scripts/auto-target.py`'s rank+force-intake fallback); VDP intake is still manual.
- `generic-api-key`-class gitleaks hits on vendored/test/doc paths are suppressed at ingest
  (`ingest.path_context`); other noisy rule classes may still need a `bot.py mark <fp> fp --rule`.
