# GNOC-ECONOMY - the proof market

Module: `scripts/gnoc_economy.py`. Tests: `python3 -W error::ResourceWarning scripts/test_gnoc_economy.py`.
Spec: `scripts/learn/SPEC-xbow-intel-economy-20261022.md` section 3.

A code-adjudicated prediction market over the harness's bots. Unit RC (receipt credit), 1 RC ~ one live probe.
A model may bet, post or claim. It can never mint or resolve: only code that already adjudicates can, and the
economy RE-READS the non-AI evidence itself instead of trusting the row a caller hands it.

## State (`.claude/state/economy/`)
- `ledger.jsonl` append-only, hash-chained AND keyed. Row: `{ts, seq, prev, kind, from, to, amount, ref, memo, sig}`.
  `prev` = sha256 of the previous row's bytes; `sig` = HMAC-SHA256(`.chainkey`, the row without sig, sorted keys).
  Kinds: mint, burn, stake, resolve, royalty, slash, bond, refund.
- `.chainkey` 0600, created once with the first ledger row (or by `migrate`), never printed or returned, registered
  as a secret path in gnoc_secrets. A missing key under a non-empty ledger is a BROKEN economy, never a fresh key.
- The settler token is HMAC(chain key, constant). `mint()`, `resolve()`, `slash()`, bond refund/forfeit, bounty
  settle, the `ready` and `triage` events demand it. The legacy `.settler` file is ignored (a planted one does nothing).
- `lineage.jsonl` rows `{program, hyp_id, slug, report_id, author, prober, verifier, writer, wo, station, bot}`, each
  HMAC-signed; an unsigned or edited row is ignored on read.
- `econ.log` one line per skipped hook (lock timeout, disabled economy, refused event).
- `ledger.jsonl.pre-hmac` the unsigned genesis ledger before the one-time `migrate` (2026-10-22).

Wallets are never stored: `balances()` replays the VERIFIED ledger. Any row with a bad or missing sig, a bad prev or
seq raises `EconomyBroken` from `rows()` / `balances()` / every decision read. Hooks catch it: the event is skipped,
`econ.log` says `economy DISABLED`, `status` and `audit` say BROKEN. A hand-appended row is therefore rejected, never
credited, and the economy stays off until a human repairs the ledger (truncate to the last good row; `audit` names it).

Genesis: 1,000 RC to every roster role (lead, worker, reflector, brain, phone-1.7b, phone-4b, oss-bot, orch-bot,
plus every role in `.claude/state/orch/models.json`), treasury 100,000. Standalone GreyNOC build (2026-10-23): no cloud bots; the three claude-* genesis names are RETIRED (hidden, balances returned to treasury).

## Locks
Every write takes a thread lock and an exclusive flock, each waited on for at most `LOCK_TIMEOUT` (2 s). On timeout
`EconomyBusy` is raised; `on_event` turns it into one `econ.log` line and returns `economy: skipped ...`. A hook can
never hang a hunt.

## Events (`on_event(kind, **kw)`, never raises)
| kind | from | effect |
|---|---|---|
| hyp-add | gnoc_hunt.hypothesis add | lineage author; author posts the market, 10 RC LONG |
| probe | gnoc_hunt.log_probe | lineage prober; the prober posts a 30 RC lane bond once |
| burst | gnoc_hunt.mark_burst (race tool) | debits n RC under ref `burst:<p>:<H>` (the signed burst receipt); refunds the bond once the floor is met per gnoc_hunt state |
| edge-proven | gnoc_hunt.edge | lineage only, never a mint |
| oracle-pass | gnoc_oracle adjudicate | mints only if gnoc_oracle holds a SIGNED passed verdict for `ref` (passed_verified if present, else the seal-key sig); once per oracle id; +50 prover, +25 author; the COMMIT row's hyp resolves proven; bond refunded; claimed bounties settle if the rules below hold |
| ready | `gnoc_economy.py ready-hook <p> <slug>` from `scripts/reports.sh ready` only (settler) | +100 split by lineage, once per draft; refused on a HELD draft or a missing report.md |
| outcome | hunt-state append-outcome | see below |
| ship | hunt-state append-ship | lineage only (draft writer, submission report id). A typed READY status mints nothing |
| triage | settle_triage (h1-feedback sync, settler) | resolved/triaged +1,000 split 30/40/20/10; duplicate -200, not-applicable -500 to the writer |
| line-advance | gnoc_line open/advance | lineage `station -> bot`, never a charge; station 4 PROBE pays +5 once per work order and once per hypothesis only when the floor recomputes as met; station 6 is paid by `ready`; everything else logs |

Outcome rules (the typed row is never trusted for counts):
- Floor met = gnoc_hunt state shows probes >= 8 AND bursts >= 1 for the row's hypothesis AND the signed burst debit
  exists. Then a DEAD mints +5 once per (program, hypothesis) and the market resolves dead. A DEAD without that
  resolves unfired (refunds).
- LEAD or any CANDIDATE resolves **lead** (never proven) when gnoc_hunt logged >= 1 probe, else unfired. Proven comes
  only from an oracle PASS.
- A refused floorless DEAD (hunt-state rc != 0) slashes 20 once per row.

Every gated probe through `gnoc_agent._send` debits 1 RC from the acting bot. `_run_worker` sets `acting_as(bot)` from
the slot's model (`bot_for_model`: phone-1.7b/phone-4b, desktop = lead, else worker);
`_parallel` copies the context into tool threads so the debit lands on that bot; the chat's own turns default to lead.
`llm_chat` debits `debit_llm(bot, model, tokens)` per turn: ceil(tokens/10000) x rate (small 1, 9B 2, haiku 3, sonnet 10, opus 30 RC), tokens from the response usage, else characters / 4.

Only real programs are booked: `targets/<p>/SCOPE.txt` must exist, and names starting `_` or `zz-` are fixtures.
`GNOC_ECON_OFF=1` turns every hook off.

## Market
- `post` author LONG >= 10; `bet(program, hyp, bot, long|short, stake)`. Unknown bots are refused.
- Probe budget = 2 x LONG pool, clamped to 20..200 (`budget()`). ENFORCED in `gnoc_agent._send` (and before a race
  burst): once gnoc_hunt's probe count for the hypothesis reaches the budget the request is refused with
  `budget exhausted for <H>: bet more or pivot`, nothing is fired and no probe is counted. touch checks it on its
  BEFORE read only, so a refusal never strands an unreverted write.
- Proven or lead: longs split the short pool pro rata. Dead: shorts split the long pool. Unfired: refunds.
  House takes 2% (ceil, at least 1 RC of a non-empty losing pool) plus integer dust to treasury.
- `brier(bot)` over resolved markets; `routing_weights()` ~ wealth x (1 - brier), unscored 0.25, excludes broke bots
  (< 100 RC). `gnoc_agent.resolve(role)` consults `route_role()` only with `GNOC_ECONOMY_ROUTING=1` (default off).

## Bounties
- `post`: funded from the POSTER's own wallet (the chat tool posts as the acting bot). Treasury funding needs the
  settler (the `gnoc_economy.py bounty post` command line, GreyNOC's). Max 1,000 RC, 72 h.
- `claim`: bonds 30 RC; the poster or funder cannot claim its own bounty.
- `settle` (settler only, run on an oracle PASS): needs that oracle's signed PASS, its commit kind in the bounty crown's
  classes (gnoc_oracle.CROWN_CLASSES), the commit made after the bounty was posted, and the commit hypothesis's
  lineage prober equal to the claimer. One settle per bounty. READY no longer settles bounties.
- Sweep (inside every `on_event` and `status`): past 72 h the escrow goes back to the funder (a claimer's bond to
  treasury); a claimer with no probe on the program for 2 h forfeits the bond and the bounty reopens.

## Filing futures
`filing_market(open|bet|resolve)` on resolved|duplicate|n-a, resolved by the triage event. `dupe_odds(cls, program)`
is Laplace-smoothed over resolved filing markets.

## Commands
- `python3 scripts/gnoc_economy.py status|audit|migrate|bet|bounty|settle|ready-hook`; chat `/econ [audit]`.
  `migrate` is one-time: it re-signs an unsigned pre-HMAC genesis ledger and refuses anything else.
- Chat tools: `econ_status`, `econ_bet`, `econ_bounty` (list/post/claim; settle is refused).

## Known limits
- The h1-feedback pull is read from `scripts/h1-feedback/out/` (a pull outside it is refused), but a file written
  there by hand is not authenticated; the H1 API pull itself is the trust root.
- A process with shell access can import the module and derive the settler; the defence is that every mint re-reads
  signed non-AI evidence (oracle sig, gnoc_hunt counts plus the signed burst row, the draft on disk).
- gnoc_hunt's ledger.json is plain JSON. The floor also needs the economy's own signed burst row, so editing it alone
  mints nothing.
