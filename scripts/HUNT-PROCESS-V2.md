# HUNT PROCESS V2 - THE LINE (GreyNOC office, 2026-10-23)

GreyNOC, verbatim: "improve our hunting capability and restructure the hunting process for the greynoc
office". Spec: `scripts/learn/SPEC-xbow-intel-economy-20261022.md` section 6. Code: `scripts/gnoc_line.py`.
Tests: `scripts/test_gnoc_line.py`. SPINE wins over this file on any conflict (SPINE section 8b).
Location: the spec named the workspace root; the write-location guard forbids new root files, so this doc
lives in `scripts/` until GreyNOC adds it to the guard's root allowlist.

## 1. Why the old loop is replaced (measured, consolidate.py 2026-10-23)

| measurement | number | what the line does about it |
|---|---|---|
| closures negative | 79% | no station passes on a model's say-so; every handoff is a file a code gate reads |
| dominant kills | mechanism without capability; known public duplicates | station 5 capability gate; stations 1 and 6 dedup |
| dead claims carrying a floor receipt | 4% (426 of 580 deads had probes but no burst) | station 4 refuses without 8 logged probes AND a logged burst with its serial control |
| drafts never filed | 53% | station 0 refuses a program whose pay gate or scope row cannot pay, before any work starts |
| programs refusing our reports on signal | 87 of 106 | station 0 runs `gnoc_pay.filing_gate`; station 6 re-runs it |
| wins that were unauth from a SEED | 88% | station 1 demands at least one seed with a kill byte before modelling |
| class precision | business-logic 83%, IDOR 6% (n=145, 23% overall) | station 0 refuses a TRAP class unless a seed names a NEW root cause |

The old loop (HUNT-LOOP.md and `.claude/workflows/hunt-cycle.js` before 2026-10-23) was eight LLM phases
handing each other prose, and the probe agent's own `outcome` field decided DEAD versus CANDIDATE. That
self-certified field is where the 4% floor-receipt rate came from.

## 2. The stations

A WORK ORDER (WO) is the unit of work. Stations 0 to 3 move the WO; stations 4 to 7 move each hypothesis
on it; station 8 closes the week. A station cannot be skipped: `advance` refuses any station more than one
past where the WO (or the hypothesis) stands and names the station it is at. Re-gating a passed WO station
is allowed and never moves the WO backwards.

| # | station | owner (bot role) | input -> output artifact | code gate (`gnoc_line.py`) |
|---|---|---|---|---|
| 0 | SALES | manager (orch-bot) | queue -> WORK ORDER `targets/<p>/line/WO-<id>.json` {program, crown, class, asset, seed_hint, budget_rc, oracle_class, release_phase, bounty_id} | `gate_sales`: `gnoc_pay.filing_gate` passes; `gnoc_pay.payability(asset)` = pays (no-bounty only with `vdp: true`); class not in the TRAP list unless `new_root_cause` names one; release phase recomputed from the precision ledger and must match |
| 1 | INTEL | intel dept | WO -> SEED PACK `targets/<p>/line/SP-<id>.md` (a ```json block {seeds, dedup, promises}) | `gate_intel`: >= 1 seed with a kill byte; `dedup.stamp` present; a seed matching do-not-rehunt (same host AND class or endpoint) is dropped; every vendor promise has a URL |
| 2 | MODEL | target-modeler | SP -> TARGET-MODEL.md plus `TM-<id>.json` | `gate_model`: every boundary names an asset AND an excluded actor; catastrophe list non-empty |
| 3 | MARKET | hypothesis-generator + skeptics | TM -> hypotheses in the gnoc_hunt ledger, each posted on the economy market | `gate_market`: each hypothesis carries ASSUMPTION, VIOLATION, PREDICTION and a kill byte in the ledger, and an oracle is COMMITTED for it (`gnoc_oracle.commit`) before station 4 opens |
| 4 | PROBE | class hunter (alloy on hard) | market budget -> captures + outcome row, `PR-<id>-<H>.json` | `gate_probe`: oracle PASS = CANDIDATE; else >= 8 probes AND >= 1 burst in the ledger (`gnoc_hunt.floor_status`) = LEAD or DEAD; else refused = UNFIRED. An outcome row claiming DEAD below the floor is refused. A finder CANDIDATE without an oracle PASS becomes LEAD |
| 5 | ESCALATE | escalation agent (different model) | oracle PASS -> chain `ES-<id>-<H>.json`, dial 0-2 | `gate_escalate`: station 4 verdict is CANDIDATE; capability is a crown token (`gnoc_hunt.CROWNS`) that the premise does not already grant; its capture is on disk (`gnoc_hunt.check_evidence`) |
| 6 | QA | dedup-scout, triage-validator, reviewer, report-killer, cvss, repro-checker | chain -> draft READY, `QA-<id>-<H>.json` | `gate_qa`: `Dedup:` and `Gate:` stamps; Summary and Impact each <= 35 words; dedup-scout matchRisk < 70 and no MATCH row in `public-dedup.jsonl`; filing-futures `dupe_odds` < 0.7 (n >= 3); `evidence/liveness-*.json` under 24 h (T-241); >= 2 PNG panels; repro verdict REPRODUCES; release phase allows filing (preview needs `RELEASE-ACK.md`, private needs an oracle PASS); pay gate again. Opens the filing market on PASS |
| 7 | BOOKS | manager | READY -> one line in `reports/INBOX.md` | `gate_books`: the draft is the one QA passed and is not under `reports/submitted/`. Filing needs GreyNOC's explicit approval in chat (CLAUDE.md hard rules, 2026-10-21); h1-feedback sync settles |
| 8 | RETRO | manager | week -> `RT-<id>.json` | `gate_retro`: exactly three proposals, each with rows (a workspace file or an outcomes.jsonl value) and a kill byte |

A model verdict may BLOCK a station (repro-checker NOT-REPRODUCES, dedup-scout matchRisk 70) and never PASS
one. Receipt: the old pipeline let the probe agent self-certify, which is the 4% figure above.

TRAP list: read from the live consolidate output (`.claude/state/learning/LESSONS.md`, the line "TRAP, these
are our WORST converters"); fallback IDOR, Information Disclosure, Improper Restriction of Authentication
Attempts. `gnoc_line.py trap` prints the list in force.

## 3. How a work item moves

```
gnoc_line.py open <p> --json wo.json            station 0; a refused WO writes nothing
gnoc_line.py advance <p> <wo> INTEL SP.md       station 1 (the workflow also re-gates it)
hunt-cycle.js args {target, wo} runs 1 to 7 for that WO:
  gate:sales -> gate:intel -> target-modeler -> gate:model
  hypothesis-generator + attacktree-agent (write HY/AT-<wo>.json) -> dedup-scout -> gate:market (oracles committed)
  per hypothesis: class hunter (logs captures) -> gate:probe -> escalation -> gate:escalate
    -> dedup-scout -> triage -> reviewer -> report-killer -> cvss -> writer -> repro-checker -> gate:qa -> gate:books
gnoc_line.py advance <p> <wo> RETRO RT.json     station 8
```

The workflow runtime has no shell. Each gate is one Haiku call labelled `gate:<station>` that runs the exact
command and returns its JSON. The relay cannot pass a station: `WO-<id>.json` is written only by
`gnoc_line`, and each later station re-reads it, so a relayed `ok` the code never wrote is refused at the
next gate. Every agent call the old workflow made is still made (22 before, 22 after); only the gates changed.

Claude-lane captures reach the floor ledger only as files. `gnoc_line.py log <p> <H#> <capture>...` counts
one probe per distinct non-empty file under `targets/<p>/` (sha256-deduplicated). `gnoc_line.py burst <p>
<H#> --serial <control> <arm> <arm>...` counts a burst only with its serial-control capture and >= 2
distinct arms. A typed count is never accepted, and an empty file is refused (T-41: an empty capture reads as
a tested negative).

A station-4 refusal is UNFIRED, never DEAD (T-40). The workflow re-hunts it once with the untried variants;
still unfired, it is queued, and the asset cannot be marked dead that cycle.

## 4. How a bot is paid at each station (`gnoc_economy`, unit RC, 1 RC ~ one live probe)

| station | economy event | who gains or loses |
|---|---|---|
| 0 SALES | `line-advance` | manager; the WO names budget_rc and an optional bounty id |
| 3 MARKET | `hyp-add` (from gnoc_hunt) | author stakes 10 RC LONG; skeptics may short; budget = 2 x LONG pool, 20..200 probes |
| 4 PROBE | `probe`, `burst` (from gnoc_hunt) | prober posts a 30 RC bond, refunded at the floor; a floorless DEAD outcome is slashed 20 |
| 4 PROBE | `oracle-pass` (from gnoc_oracle) | prover +50, author +25, market resolves proven, claimed bounties settle |
| 4 PROBE | `outcome` (from hunt-state) | floor-met honest DEAD +5 |
| 6 QA | filing market opened by the line | bots bet resolved / duplicate / n-a; `dupe_odds` feeds the next QA gate |
| 6/7 | `ready` | 100 RC split author 30%, prober 40%, verifier 20%, writer 10% |
| 7 BOOKS | `triage` (settle_triage after h1-feedback sync) | acceptance +1000; duplicate -200; not-applicable -500 (T-254 signal weights) |

Every `open` and `advance` also emits `line-advance` (station, ok, verdict, check). The economy does not book
that kind yet (owed, section 7); `on_event` returns a note and never raises into the line.

## 5. The dispatch brief

`gnoc_line.py brief <p> <wo> --bot <bot>` renders, for the NEXT station: the manager's 1:1 slot (a
placeholder line the manager writes; gnoc_line never generates it), the work order, the seed pack with each
seed's kill byte, every hypothesis's oracle id, kill byte and market budget, the floor numbers, the release
phase, the RC budget and spend, and the top six Manual T-ids whose index line mentions the class. A TRAP class
prints its new root cause. Receipt for briefing traps: T-149.

## 6. The office view

`.claude/state/economy/line.json` is rewritten on every open and advance: per program, each open WO with
station, age, RC spent (sum of ledger probes on its hypotheses) against budget_rc, and each hypothesis's
station and verdict. `gnoc_line.py status [<p>]` prints the same plus the last refusal.

## 7. Owed

- `gnoc line open|advance|status|brief` passthrough in `scripts/gnoc` (orchestrator, after builder E).
- A `line-advance` handler in `gnoc_economy._on_event` (builder C); today it returns "unknown event".
- A sealing capture path for Claude lanes: `gnoc_oracle.verify` refuses unsealed captures and only the gnoc
  chat sender seals, so a Claude-lane oracle PASS (the only road to CANDIDATE) needs a sealed sender.
- A liveness producer for Claude lanes: station 6 needs `evidence/liveness-*.json` (today written by the gnoc
  chat `liveness` tool). Until then a workflow draft parks HELD at QA with the failing check named.
- DONE 2026-10-24: office renders line.json (five-room floor); orch-bot opens work orders from its queue (station 0 owner).
- This doc at the workspace root needs a guard allowlist entry (GreyNOC's call).

## 8. Supersession

This file SUPERSEDES the "three layers" section of `HUNT-LOOP.md` for the process: the inner pipeline is the
line above. The outer driver modes (single named target LOCK, platform rotation), the files table, the
guardrails and the support-child front-load in HUNT-LOOP.md still apply unchanged.
