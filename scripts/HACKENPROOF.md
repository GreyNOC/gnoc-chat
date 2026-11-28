# HACKENPROOF - program intake, scope mechanism, and the traps

Everything below was verified LIVE on 2026-10-21 with plain `curl` / `WebFetch` from this
workspace. Nothing here is recalled from documentation. Where a claim is unverified it
says so explicitly - see section 7.

Intake scripts:
- `~/.gnoc/scripts/hackenproof-scope.sh` - one program -> `targets/<slug>/SCOPE.txt` + `PROGRAM.md`
- `~/.gnoc/scripts/hackenproof-rank-programs.sh` - rank every public program by EV
- Front door: `~/.gnoc/scripts/intake.sh hackenproof <slug>`

## 0. WHAT IS DIFFERENT FROM HACKERONE / BUGCROWD / INTIGRITI (read first)

| | HackerOne | Bugcrowd | Intigriti | HackenProof |
|---|---|---|---|---|
| public JSON API | yes (token) | yes (none) | yes (none) | **NONE EXISTS** - see section 1 |
| auth to read public scope | API token | none | none (lvl 4) | **none** |
| handle shape | `<handle>` | `<code>` | `<company>/<program>` | **`<slug>`, one segment** |
| in-scope flag | `eligible_for_submission` | `inScope` per GROUP | `bountyTierId==5` + name (version history) | **`scopes[].out_of_scope` bool, per ASSET, no history** |
| bounty flag | `eligible_for_bounty` | group `rewardRangeData` | tier absent from bounty table | **program-level `rewards`/`maxBounty`, NOT per-asset** |
| severity model | CVSS 3.0 | VRT + CVSS 3.1 | CVSS 3.1 (usually) | **Critical/High/Medium/Low bands; CVSS for web/mobile, impact-based for on-chain** |
| required header | `X-HackerOne:` | none | none (`@intigriti.me` convention) | **none found** (checked program text + docs) |
| unique eligibility gates | reputation (signal) | none platform-wide | ToS acceptance, 2FA | **KYC-to-be-paid, PoC-mandatory, min reputation, PAY-TO-SUBMIT fee** |
| platform focus | general web/mobile | general web/mobile | general web/mobile | **majority Web3/crypto**: smart contracts, protocols, bridges |

The two biggest differences: (1) **there is no API at all** - the data comes from
decoding a Nuxt SSR page's embedded JSON blob, a genuinely different mechanism from
every other platform this workspace onboards; (2) **HackenProof can charge the
researcher a submission fee** (refundable on a valid report, per their own docs) - no
other platform here does this, and it belongs in `PROGRAM.md` as a loud warning, not a
footnote.

## 1. THE MECHANISM (Nuxt SSR page decode, zero auth, NO public API)

Searched for first: a public REST/GraphQL API (`hackenproof api` web search: nothing),
an `api.hackenproof.com` host (grepped every JS bundle the homepage loads: not present),
and `docs.hackenproof.com`'s full page index (`llms.txt`, 90+ pages) - it documents
Slack/Discord/Jira/GitHub/Zapier integrations and an authenticated dashboard "MCP
Server" (for logged-in companies to triage reports with an LLM), but **no public
read-only programs API**. HackenProof publishes none. This script does not call one
because none exists to call.

What hackenproof.com actually is: a **Nuxt 3 SSR application**. Every page response
embeds the exact data the Vue app needs as a single script tag:

    <script type="application/json" data-nuxt-data="nuxt-app" id="__NUXT_DATA__">
      [ ... a flat JSON array, the "devalue" reference format ... ]
    </script>

This is Nuxt's own `devalue`-style state serialization, not HackenProof-specific. The
array is a flat list of values; `array[0]` is the root. Any value that is itself an
object or a list stores its children as **integer indices back into the same array**
(structural sharing - a value referenced from two places is stored once and pointed at
twice), while raw primitives (strings, numbers, booleans, null) are stored directly. A
few entries are wrapped as `["ShallowReactive", <idx>]` / `["Reactive", <idx>]` and must
be unwrapped by following `<idx>`. A small recursive resolver (`decode_nuxt_data()`,
duplicated verbatim in both scripts so each stays self-contained) walks this:

```python
def decode_nuxt_data(script_body):
    arr = json.loads(script_body)
    memo = {}
    def resolve(idx):
        if idx in memo: return memo[idx]
        raw = arr[idx]; memo[idx] = None  # cycle guard
        if isinstance(raw, list):
            if len(raw) == 2 and raw[0] in {"ShallowReactive","Reactive", ...}:
                result = resolve(raw[1])
            else:
                result = [resolve_value(x) for x in raw]
        elif isinstance(raw, dict):
            result = {k: resolve_value(v) for k, v in raw.items()}
        else:
            result = raw
        memo[idx] = result; return result
    def resolve_value(v):
        return resolve(v) if isinstance(v, int) and 0 <= v < len(arr) else v
    return resolve(0)
```

This is a generic technique, not a HackenProof quirk - it will decode the embedded
payload of any Nuxt 3 SSR page in this or any future target.

### Step 1 - the program directory (also the ranking data source)

    GET https://hackenproof.com/programs?page=N
    -> 200 text/html; decoded .data["programs-api-bounty"] =
       { "programs": [ {id, slug, isAudit, image, name, description, state, status,
                         startDate, lastUpdated, isUnending, endDate, submittedReports,
                         reward, rewardPaid, tags{platforms,project_types,types,
                         languages}, triagedByHackenproof, programOfTheWeek,
                         dualDefence, repoUrl, poolUrl, reportUrl, scopeReview,
                         activityStatus{name, downtime}}, ... (10 per page) ],
         "total_items": 325, "next_page": 2, "prev_page": null,
         "filter_attributes": {order_by:[...], with_project_types:[...], by_status:[...],
                               by_kyc:["true","false"], by_poc:[...], ...} }

Verified 2026-10-21: 325 public programs, 10 per page, 33 pages. `id` is always `-1` on
every listing row (redacted); `status` is frequently the sentinel `-1` too (meaning "no
special badge", distinct from `activityStatus.name` which is the real
Active/Completed liveness signal - **do not confuse the two**).

`filter_attributes` documents real UI filter names, but **they do not work as a plain
query string**: `?with_project_types=DEX` returned the byte-identical unfiltered first
page (still led with a CEX program), and `?order_by=max_bounty_float` returned the
identical default order. Only `?page=N` was confirmed to change the result. The
filtering UI likely posts a differently-encoded request (array/bracket syntax, or a
dedicated endpoint) that was not identified. **Both scripts here page through
everything and filter/sort client-side** rather than trust an unverified server filter.

### Step 2 - one program's detail page (the scope)

    GET https://hackenproof.com/programs/<slug>
    -> 200 text/html; decoded .data.program =
       { title, companyName, companySlug, state, status, startDate, endDate,
         isUnending, submitUrl, kycRequired, pocRequired, reputationRequired,
         minReputation, submissionFee, maxReward, maxBounty, minBounty,
         rewards: {critical_min, critical_max, high_min, high_max,
                   medium_min, medium_max, low_min, low_max},
         sla: {first_response, time_to_triage, resolution_time, time_to_reward},
         scopes: [ {id, title, target, target_description, criticality,
                    out_of_scope, position}, ... ],
         programRules, focusArea, disclosureGuidelines,
         eligibilityAndCoordinateDisclosure, labels{types,platforms,languages,
         project_types}, hackerRanks[...], activityStatus, scopeReview }

A **nonexistent slug answers HTTP 302 to `/error`** with a 92-byte meta-refresh body and
no `__NUXT_DATA__` script at all (verified: `programs/totally-bogus-nonexistent-slug-zzz999`).
That is the "not found" signal both scripts check for.

### `scopes[]` - the in-scope mechanism, and why it is SIMPLER than Bugcrowd/Intigriti

Every scope entry carries a plain **`out_of_scope` boolean directly on the asset** - no
group-level flag to inherit (Bugcrowd), no bounty-tier-id-equals-5 indirection, and
**no append-only version history to pick the wrong revision of** (Intigriti's worst
trap). `scopes[]` is simply the current list.

### `scopes[].title` IS FREE TEXT - a real trap, document before writing a parser

Observed titles across 21 sampled programs (196 scope entries): `Web`, `API`,
`Smart Contract`, `Protocol`, `Bridge`, `Infrastructure`, `Android`, `iOS`, `Other`.
Unlike Bugcrowd's `category` enum or Intigriti's `typeId` enum, **the same kind of
asset is filed under different titles by different companies**:

    coingecko      : "Web" | Chrome Extension           (a store link, filed as Web)
    idos-apps-and-sc-1 : "Other" | https://enclave.idos.network/   (a REAL web host, filed as Other)

Because of this, `hackenproof-scope.sh` **never gates on `title`**. It shape-checks
every `scopes[].target` string with `to_host()` regardless of the declared title, and
relies on the `THIRD_PARTY` + `PUBLIC_SUFFIX` guards to keep non-program infrastructure
out of the allowlist even when a company mis-titles it. `title` is kept only as an
inline comment for the human reader.

### The platform is WEB3/CRYPTO-HEAVY - expect many zero-host programs

Of 196 sampled scope entries, 97 (49%) were `Smart Contract` / `Protocol` / `Bridge` /
`Infrastructure` entries pointing at a `github.com` repo path (e.g.
`https://github.com/1inch/limit-order-protocol/tree/4.3.4`) or a block-explorer
contract-address URL (e.g. `https://monadscan.com/address/0x...#code`) - **neither of
which is the program's own host**. `github.com` is already in this workspace's shared
`THIRD_PARTY` set. Block explorers were NOT, so `hackenproof-scope.sh` adds a
best-effort `EXPLORER_HOSTS` set (etherscan.io/bscscan.com/polygonscan.com/arbiscan.io/
solscan.io/suiscan.xyz/starkscan.co/mintscan.io/... and their common testnet
subdomains). **Only `monadscan.com` was empirically observed** in the sample; the rest
are added proactively from general Web3 knowledge and are UNVERIFIED against
HackenProof data specifically - treat any newly-encountered explorer host the same way
(add it to `EXPLORER_HOSTS` in `hackenproof-scope.sh`).

A program whose scope is entirely such references (verified: `1inch-smart-contract`, 8
scope entries, 0 host-shaped) therefore yields **zero** web-host entries by design -
`hackenproof-scope.sh` exits 3 and writes nothing, exactly like a source-code-only
Bugcrowd/Intigriti program. This is **expected**, not a bug: such a program belongs to
this workspace's existing Immunefi-style on-chain hunting lane (fork PoC, impact-based
severity, contract-address targets), not a web host allowlist.

### Reward model: PROGRAM-LEVEL, not per-asset (a real difference)

Bugcrowd and Intigriti both let one asset/group be reward-eligible while a sibling in
the same program is not. HackenProof's `rewards` object (`critical_min/max`,
`high_min/max`, `medium_min/max`, `low_min/max`) and `maxBounty`/`minBounty` are
**program-wide**. There is no per-scope-entry reward field beyond `criticality`, which
sets the ceiling BAND for that asset (e.g. `"Critical"`), not a dollar amount, and is
`null` on every out-of-scope entry observed (0 counter-examples across 21 programs).
So `hackenproof-scope.sh`'s "pays cash" check is one boolean for the whole program;
when false, every in-scope host line still gets an inline `NO-BOUNTY` tag (for
cross-platform `grep NO-BOUNTY` consistency), even though the underlying reason is
program-wide rather than per-asset - `PROGRAM.md` says so explicitly.

## 2. SCOPE.txt MAPPING (grammar authority: targets/README.md)

| condition | placement |
|---|---|
| `scopes[].out_of_scope == true` | BELOW divider, `OOS` note |
| `to_host(target)` fails (not host-shaped) | BELOW divider, `NOT-A-HOST` note |
| host reduces to a third-party/store/repo/explorer host | BELOW divider, `THIRD-PARTY-HOST` note |
| host reduces to a public suffix / bare TLD | BELOW divider, `REFUSED-PUBLIC-SUFFIX` note |
| otherwise | ABOVE divider, tagged with `title` + `criticality` (+ `NO-BOUNTY` if the whole program pays nothing) |

Wildcard forms (`*.foo.com`, `*foo.com`) are preserved VERBATIM, same convention as
every sibling script - `*.foo.com` is dot-bounded, `*foo.com` is a loose suffix glob.

### Zero-host programs exit non-zero

Verified: `1inch-smart-contract` (8 Smart Contract scope entries, all github.com repo
paths) -> `hackenproof-scope.sh` prints the reason, exits 3, writes **no** `SCOPE.txt`,
and removes the target directory if it created it. Same safety contract as
Bugcrowd/Intigriti - an empty-but-present `SCOPE.txt` makes the live scope gate FAIL
CLOSED and block every probe for that target (`targets/README.md`).

## 3. THE WILDCARD-SHADOW HAZARD

Both scope parsers (`scope-gate.sh`, `bbtools.lib_scope`) stop reading at the
out-of-scope divider and never consult an exclusion, so an explicitly out-of-scope host
that is a SUBDOMAIN of an in-scope wildcard above the divider **is allowed by the
gate**. Documented, intentional behavior (`targets/README.md`), not a bug here - but a
real operational hazard. Confirmed instance from this intake:

    backpack-web-and-api : *.backpack.exchange IN SCOPE (Web, Critical)
                           support.backpack.exchange / status.backpack.exchange /
                           guide.backpack.exchange  OUT OF SCOPE  -> ALL THREE ALLOWED

`hackenproof-scope.sh` detects these the same way every sibling script does: by
importing the CANONICAL parser (`bbtools.lib_scope.host_in_scope`) against the file it
just wrote, appending a `GATE-WILL-NOT-BLOCK` block after the divider, and repeating the
list in `PROGRAM.md`.

## 4. `PROGRAM.md` CONTENT

Pays-cash yes/no + the per-criticality reward table, the HackenProof-specific
eligibility gates (KYC-to-be-paid, PoC-mandatory, minimum reputation, submission fee +
its refund-on-valid-report claim), SLA days (first response / triage / resolution /
reward), the in-scope-vs-reward-eligible breakdown, the wildcard-shadow warning, tags/
classification (project types, languages, platforms), and `programRules` /
`focusArea` / `disclosureGuidelines` / `eligibilityAndCoordinateDisclosure` reproduced
**verbatim** (these are the actual rules of engagement; there is no separate
discrete "safe harbor" field the way Bugcrowd has one).

**Required researcher identification**: none found. Checked both a sampled program's
own rules text and `docs.hackenproof.com`'s
`bug-bounty/reports-basics/report-submission-requirements` page directly (fetched
live) - neither mentions a required header, User-Agent, or test-account email
convention, unlike HackerOne's `X-HackerOne:` header or Intigriti's `@intigriti.me`
convention. `PROGRAM.md` still tells the operator to re-verify on the live page.

**Report submission itself requires a HackenProof dashboard account**
(`submitUrl` is always `https://dashboard.hackenproof.com/user/programs/<slug>/reports/new`).
This script never visits `dashboard.hackenproof.com` - it is the authenticated side of
the platform and out of scope for a zero-auth intake pull.

## 5. DEAD ENDS / THINGS TESTED AND UNVERIFIED - do not re-walk these

| attempt | result |
|---|---|
| web search "hackenproof api" / "hackenproof public api docs" | no results about HackenProof at all |
| grepping every JS bundle the homepage loads for `api.hackenproof` or any `/api/` path | zero hits (only two unrelated client-side endpoints found: `/activities-api/hackers/weekly`, `/blog-api/featured` - homepage widgets, irrelevant to program scope) |
| `docs.hackenproof.com/llms.txt` (full 90+ page doc index) | no public programs-read API documented; the one "MCP Server" is an AUTHENTICATED dashboard feature for companies triaging reports, not a public reader |
| `?with_project_types=DEX` / `?order_by=max_bounty_float` as plain query string on `/programs` | **no effect** - byte-identical `total_items` and first-page order to the unfiltered default. Real filtering mechanism not identified; do not assume `filter_attributes` names work as GET params |
| `/programs/<slug>.json` or any `.json` suffix on program pages | not tested (no evidence any such route exists; the HTML page IS the only observed data source) |
| homepage root (`/`) | its `__NUXT_DATA__` script is LAZY - a `data-src="/_payload.json?<hash>"` attribute points at a separate payload fetch instead of embedding the body inline. `/programs` and `/programs/<slug>` do NOT do this (body is always inline) - this script does not need the lazy case, but a future page added to this intake might, so check for `data-src` before assuming the inline body is non-empty |

## 6. VERIFICATION RECEIPTS (2026-10-21)

- Scope-gate hook fix verified: `hackenproof.com` was **not** in `.claude/hooks/scope-gate.sh`'s
  `PLATFORM_RE` before this work (confirmed: a plain `curl https://hackenproof.com/`
  was hard-BLOCKED with `OOS host hackenproof.com not in targets/<locked-target>/SCOPE.txt`).
  Added `hackenproof\.com` next to `bugcrowd\.com|intigriti\.com|yeswehack\.com` -
  same category (workspace tooling / program-directory infra, never a bounty asset).
  Re-verified after the fix: `curl` to `hackenproof.com` succeeds (HTTP 200).
- Full-scale pagination: 33 pages, 325 unique programs decoded, 0 decode errors, matches
  the directory's own reported `total_items`.
- `hackenproof-scope.sh zmo-exchange`: 2 scope entries, both in-scope hosts
  (`www.zmo.com`, `*.zmo.com`), pays cash ($50-$2,000 by band), parser-agreement
  confirmed (`bbtools.lib_scope.host_in_scope` IN for `www.zmo.com` and the wildcard
  match `foo.zmo.com`, OUT for `evilzmo.com`).
- `hackenproof-scope.sh backpack-web-and-api`: 7 scope entries, 2 in-scope hosts
  (`*.backpack.exchange`, `ws.backpack.exchange`), 5 explicitly out of scope, 3 of
  those wildcard-shadowed (section 3) - all correctly detected and written.
- `hackenproof-scope.sh 1inch-smart-contract`: 8 scope entries, all Smart Contract
  github.com references, 0 in-scope hosts -> exit 3, confirmed no file left behind.
- `hackenproof-scope.sh totally-bogus-nonexistent-slug-zzz999`: HTTP 302 -> `/error`,
  exit 2, confirmed no directory created.
- No-clobber re-run writes `SCOPE.txt.new`/`PROGRAM.md.new`; `--refresh` overwrites in
  place; `scripts/intake.sh hackenproof <slug>` runs the full pipeline including the
  canonical `verify_scope()` safety check - all confirmed.
- `hackenproof-rank-programs.sh`: paginates all 33 pages, decodes 325/325 programs with
  0 errors, default filters (pays cash + not audit + Active) reduce 325 -> 151,
  `--all` returns all 325, `--max-pages` bounds the sweep, output is a sorted TSV
  through `column -t`.
- Test target directories `targets/zmo-exchange/` and `targets/backpack-web-and-api/`
  created solely to prove this pipeline were deleted after verification; they carry no
  hunting work product.

## 7. SEVERITY / SUBMISSION NOTES

- Web/mobile programs explicitly say they use **CVSS** to place a finding into a
  Critical/High/Medium/Low band (confirmed live from
  `docs.hackenproof.com/bug-bounty/vulnerability-classification/web-and-mobile`:
  *"We use the Common Vulnerability Scoring System to assess the severity of reported
  vulnerabilities"*). Smart-contract and blockchain-protocol programs use a separate,
  impact-based classification table (`.../vulnerability-classification/smart-contracts`
  and `.../blockchain-protocols`) - route those to this workspace's existing on-chain/
  Immunefi-style severity model, not CVSS, same as `CLAUDE.md`'s Immunefi section
  already directs.
- **Submission fee** (`submissionFee`, seen as low as 1 and as high as 7 on sampled
  programs): HackenProof can charge the researcher a fee to submit a report, which
  their own docs describe as refunded on a valid/accepted report. No other platform in
  this workspace does this - flag it loudly before telling GreyNOC a program is
  "zero-cost to test"; submitting is not necessarily zero-cost even though reading
  scope is.
- **KYC-to-be-paid** (`kycRequired`, true on roughly half of sampled programs) and a
  **minimum reputation to submit** (`minReputation`) are both real eligibility gates
  that exist before the first report, independent of the bounty amount.
- Disclosure is platform-gated per program text (`disclosureGuidelines`): typically "no
  disclosure without explicit mutual agreement", reproduced verbatim in `PROGRAM.md`.
- Report drafts go to `reports/drafts/<slug>/`. GreyNOC submits manually through
  `dashboard.hackenproof.com` - there is no automated submission path here, and the
  workspace `submit-guard` hook should be extended to cover that host before any
  automated-submit attempt is made (not done as part of this work; intake only).

## Sources

All verified live 2026-10-21 from this workspace:
- `https://hackenproof.com/programs?page=N` (directory, devalue-decoded, 325 programs / 33 pages)
- `https://hackenproof.com/programs/<slug>` (program detail, devalue-decoded)
- `https://hackenproof.com/programs/<bogus-slug>` (302 -> /error, the not-found signal)
- `https://docs.hackenproof.com/llms.txt` (full doc index - no public API documented)
- `https://docs.hackenproof.com/bug-bounty/vulnerability-classification/web-and-mobile` (CVSS confirmation)
- `https://docs.hackenproof.com/bug-bounty/reports-basics/report-submission-requirements` (no identification-header requirement)
- Web search "hackenproof api" / "hackenproof public api docs" (no results)
