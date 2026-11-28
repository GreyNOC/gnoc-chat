# GNOC ORACLE - hunt like XBOW

Module: `scripts/gnoc_oracle.py`. Tests: `python3 -W error::ResourceWarning scripts/test_gnoc_oracle.py`.
Spec: `scripts/learn/SPEC-xbow-intel-economy-20261022.md` section 1. Source of the idea:
`research/xbow/XBOW-TECHNIQUE.md` section 6 and "THE ONE MECHANISM TO COPY" (Manual T-208).

The one structural difference XBOW has over us: the proof is a PREIMAGE CHECK, not an agent's say-so. A model may
PROPOSE a finding; only code SETTLES it.

## 1. The hash-committed terminal

    oracle_commit hyp_id=H3 kind=cross-user-read planted_as=B must_read_as=A

Commit refuses (bad arguments) anything the verify could never honestly pass:
- `hyp_id` must be an existing hypothesis row of the program in the gnoc_hunt ledger (no free text).
- `must_read_as` is REQUIRED for every canary class; it is a saved identity (gnoc_ident) or `none`.
- identity classes (cross-user-read/write, idor-write, auth-bypass, cache-poisoning) also need `planted_as`, a
  saved identity with credential headers, different from `must_read_as`, and with DIFFERENT credentials (one
  account under two names is refused).
- `open-redirect` needs `attacker_host`; `auth-bypass` needs `planted_url` (the PRIVATE url the planter wrote to);
  `rce` mints a second ECHO token next to the preimage (both shown once, with printf octal forms to send).

The preimage is shown ONCE; only its sha256 (and the echo token's) goes to
`.claude/state/hunt-loop/oracles/<program>.jsonl`. `oracle_verify` is pure code and PASSES only when
1. every capture is SEALED (section 2) and carries a `ts` LATER than the commit,
2. a response carries a token hashing to the commitment, read as `must_read_as` and never by the planter,
3. the request does not carry the preimage in ANY normalised form: JSON-unescaped, URL-decoded up to 3 rounds,
   HTML-unescaped, case-folded, and with every param / header / body value JOINED; any 12-char piece counts,
4. the plant scan over every sealed capture of the program since the commit agrees: for identity classes only
   `planted_as` ever sent the canary (auth-bypass: only to `planted_url`); for ssrf-internal, file-read and rce
   no request ever carried it,
5. the class check passes (section 3).
ONE verdict per commit: a passed, failed or agent commit is never verified again (commit a fresh canary). A
deterministic PASS emits the economy `oracle-pass` event once, inside try/except.

### refire (for unsealed captures from Claude / bbtools / curl lanes)

    gnoc oracle verify --refire <program> <oracle_id> <capture> [...] [--draft reports/drafts/<p>/<slug>]
    oracle_verify oracle_id=o-xxxx captures=[...] refire=true draft=...      (chat: GET/HEAD/OPTIONS only)

The stored REQUEST of each capture is re-sent by code through the gated sealed sender (`_program_gate` + `_send`:
scope, policy, rate, leak check, raw capture, seal) and ONLY the fresh sealed captures are judged. The original file
is a request template, never evidence; there is no seal CLI (it would seal forgeries). A refire PASS with `--draft`
writes `evidence/liveness-<ts>.json` there (the T-241 file `reports.sh ready` wants).

## 2. Authentic captures and signed state

The gated sender's `_capture` calls `gnoc_oracle.seal(path)`: `<capture>.sig` = HMAC-SHA256(secret, bytes), and
`_send` records `elapsed` (seconds) in each capture. The secret is `.claude/state/hunt-loop/oracles/.seal` (0600).
- no `.sig`: "unsealed capture"; `.sig` mismatch: "hand-written capture"; `seal()` never raises.
- EVERY oracle state row (commit and verdict) carries `sig` = HMAC(seal key, row). `oracles()`, `status()`,
  `passed()` ignore a row with a bad or missing sig, and a commit row is always folded as `open`.
- `write_file` / `edit_file` / patch refuse `.claude/state/hunt-loop/oracles/` and `.claude/state/economy/`
  (gnoc_agent `WRITE_DENY`).
- `.seal` and `.claude/state/economy/.settler` are permanent rows in `gnoc_secrets` (SECRET_DIRS: read_file and
  grep refuse; SHELL_SECRET: `cat .seal`, `.s*` globs and whole-dir reads of either state dir are refused); their
  VALUES are redacted from every tool result and refused on writes and on the wire.

## 3. Validator catalogue (`VALIDATORS`)

| class | tier | pass condition |
|---|---|---|
| cross-user-read | deterministic | canary planted by B in a private field, read back as A |
| cross-user-write, idor-write | deterministic | A writes the canary into B's object; B's own read returns it |
| auth-bypass | deterministic | sealed plant by planted_as to planted_url (2xx), a control as must_read_as REFUSED 401/403 there, then a read as must_read_as that returns it |
| ssrf-internal | deterministic | canary served by a host only the target can reach, never sent to the target |
| file-read | deterministic | canary in a file outside the docroot of an owned host, never sent to the target |
| rce | deterministic | command OUTPUT carries the preimage AND the echo token; no request ever carries either |
| open-redirect | deterministic | 3xx Location host == committed attacker_host, which is in the request params, outside the target's registrable domain; Location to the request host or its www/apex twin refused |
| cache-poisoning | deterministic | planted_as sends the canary; must_read_as gets it on the SAME method + path with a clean request |
| race-single-use | deterministic | burst successes > 1 while serial == 1, every arm the same method + path |
| sqli-boolean | deterministic | >= 3 true and >= 3 false predicates (classified by code), one method + path, arms differ |
| sqli-time | deterministic | median(n>=5 timed) - median(n>=5 control) > 3.0 s; from captures' `elapsed`, one method + path |
| xss-dom | agent | a browser on the target origin executes the payload from a URL alone |
| info-disclosure | agent | a human confirms the bytes are private and usable |

`gnoc_report.build` keys the hold on the ONE oracle the draft names: `build(oracle_id=)` or the first `o-xxxxxxxx`
in the chain edges' via / evidence / must_contain that passed for this crown; it writes `Oracle: <id>` into
GATES.md. `draft_hold(program, crown, oracle_id)`: no id, an unknown id, an open / failed id, or a kind that does not
match the crown = HELD with `Unlock: oracle PASS`. A PASS on another draft's oracle lifts nothing.

## 4. Release phases (XBOW's GA / preview / private)

`release_phase(cls, program=None)` reads `research/technique/PRECISION-LEDGER.json` (path from `bbtools/prt.py`),
sums the ledger rows mapped to the class (`CLASS_LEDGER`), and returns
- `GA`: precision >= 0.50 and n >= 3
- `preview`: 0.30 to 0.50; file only with GreyNOC's explicit per-draft ack (written into HELD-REASON)
- `private`: < 0.30 or n < 3; ships only with a deterministic oracle PASS attached
Chat tool `release_phase cls=<class>`; the `/hunt` start banner prints every class by phase next to the pay gate.

## 5. The alloy and the respawn

- In `_run_worker`, when the task contains `[hard]`, or `GNOC_ALLOY=1`, or the lane is past HALF its turn budget
  (`effort()["worker_steps"] // 2`) with no anomaly, turns rotate over the worker endpoint, the lead (or worker)
  endpoint, and the phone 4B (`hf.co/mradermacher/Qwen3-4B-abliterated-GGUF:Q4_K_M@phone`, 127.0.0.1:11441) when a
  1 s TCP check reaches it (phone turns are sent `"think": false`). Each alloyed turn logs `turn N by <model>@<host>`.
  `GNOC_ALLOY=0` turns it off; `GNOC_PHONE_ALLOY_MODEL` overrides the phone model.
- At the cap, a lane with no anomaly gets a `RESPAWN BRIEF` built from disk only (hypothesis row, its oracles, the
  last digest). `fan_out` re-dispatches that brief ONCE automatically as a fresh worker, its task marked
  `[respawn 1]`; a respawned lane is never respawned again.

## 6. Sweep by code (`gnoc_probe.sweep`, chat tool `sweep`)

Put `{{X}}` markers in the url, body or headers; name a set (`encodings`, `path-shapes`, `id-forms`,
`header-hosts`, `bool-sqli`, `ssti-markers`, `redirect-hosts`) or pass `slots={"X": "<set>" | [values]}`. A neutral
baseline, a nonsense control and up to 40 variants go through the SAME gated sender (scope, policy, rate, raw
capture, sealed) and come back as the probe-matrix diff table. Non-GET methods need approval.

## 7. Escalation stage (chat tool `escalate`, lead only)

`escalate_brief(program, finding, dial)` runs only on an oracle PASS, for a DIFFERENT model than the finder
(lead if the finder was a worker). Dial 0 = read-only proof of reach, 1 = reversible self-owned write, 2 =
self-owned delete (the gold BOLA receipt). Never above 2, never a real user's object. `run=true` dispatches it
(asks first).

## 8. CLI

    gnoc oracle status <program>
    gnoc oracle verify <program> <oracle_id> <capture> [...]     exit 0 on passed
    gnoc oracle verify --refire <program> <oracle_id> <capture> [...] [--draft <dir>]
    gnoc oracle phase <class> [program]
    gnoc oracle banner <program>
    gnoc oracle classes

## 9. Known limits

- The preimage reaches the chat history (it must, to be planted). It never reaches oracle state.
- A request sent outside the gated sender (a bash curl) is invisible to the plant scan; refire is the only way such a
  capture counts, and it re-sends through the sender.
- "Private surface" for auth-bypass is proved by a 401/403 control on planted_url, not by reading the server's ACL.
- The registrable-domain check is an approximation (last two labels, three under a short list of 2-level suffixes).
- Oracle rows written before 2026-10-23 carry no sig and are ignored.
