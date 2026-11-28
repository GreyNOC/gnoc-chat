# IMMUNEFI - platform guidelines, smart-contract policy, and report submission

The operating doc for hunting Immunefi programs in this workspace. Immunefi is a smart-contract
(on-chain) bounty platform: severity is judged by IMPACT, not CVSS, and a runnable fork PoC is
mandatory. This doc is the authority the report flow and the EVM layer hunters consult for any
Immunefi target. Distilled from the live policy (sources at the bottom).

## 0. WHAT IS DIFFERENT FROM HACKERONE / YESWEHACK (read first)

- SEVERITY IS IMPACT-BASED, NOT CVSS. Pick the impact category from the program's dropdown; it must
  appear verbatim in the program's impacts list (section 2). A CVSS vector is not used for the
  severity decision. This OVERRIDES the workspace default (SPINE: H1 = CVSS 3.0, others 3.1).
- A RUNNABLE FORK POC IS MANDATORY (section 4). No PoC = no payout, regardless of how clear the
  description. A unit test against mocks is rejected; the PoC must fork the live deployed state.
- TESTING ON MAINNET OR ANY PUBLIC TESTNET = PERMANENT BAN. All testing is on a LOCAL FORK. Only a
  read-only confirm (cast call / eth_call) may touch the live chain, never a value-moving tx.
- THE REPORT IS THE IMMUNEFI 7-SECTION DASHBOARD FORM (section 5), not the workspace 3-section shape.
  Map Summary -> Bug Description, the captured fork run -> PoC, the impact category -> Impact.
- DISCLOSURE IS PROJECT-GATED (Category 3 for Polygon): zero public disclosure until the project
  approves in writing, with no guaranteed timeline (section 6).

## 1. TARGET SETUP (intake)

Run `scripts/immunefi-scope.sh <program-slug> [--refresh]` to AUTO-FETCH the program and fill
`targets/<slug>/SCOPE.txt` + `PROGRAM.md` with the live asset list, payout table, KYC/primacy/launch
and the Immunefi SC severity model. There IS no official scope API, but the data is not hidden:
Immunefi is a Next.js App-Router SPA and embeds the whole program (assets, rewards, rules) inline in
the page as RSC flight chunks. `scripts/immunefi-fetch.py <slug>` joins+unescapes those chunks and
extracts, with ZERO auth (no token, no key, no login): every in-scope contract address, its chain, a
suggested public fork RPC per chain, the per-severity payout min/max (+ "% of funds at risk"), the
KYC flag, primacy-of-impact and launch date. Address extraction covers EVM `0x`, Solana and Stacks
(explorer path-tail); github/gitlab entries are treated as SOURCE, not on-chain assets.

The single input you provide is the correct URL SLUG - the path segment in
`immunefi.com/bug-bounty/<slug>/information/` (e.g. `lombard-finance`, not `lombard`; an HTTP 404
means the slug is wrong). No egress unlock is normally needed (plain urllib with a browser UA gets
200); if a CF/bot wall ever 403s, feed a pre-fetched page in:
`curl -sL -A '<browser-UA>' 'https://immunefi.com/bug-bounty/<slug>/information/' | scripts/immunefi-fetch.py <slug> --stdin`.
Run `scripts/immunefi-fetch.py --self-check` for an offline parse test. `--refresh` overwrites
existing SCOPE.txt/PROGRAM.md (default: existing files are left untouched, so re-running is safe).

SCOPE.txt holds one identifier per line (each contract address, each chain, each fork RPC host) so
the scope-gate hook passes both the addresses and the fork RPC. Spot-check a few addresses against
the Scope tab, then model the target (target-modeler) and hunt with the EVM layer specialists.

Scaffold the runnable fork PoC harness in one command: `scripts/scaffold-fork-poc.sh <slug> <chain>
[fork_block]` writes `targets/<slug>/poc/` with `foundry.toml` + a `ForkPoC` base (forks from a
keyless drpc.org archive RPC, funded actors, `assertGained` terminal-receipt helper) + a
`test_harness_selfcheck` that proves the fork before any result is trusted. See
`targets/_templates/fork-poc/README.md`.

## 2. SMART CONTRACT SEVERITY -> IMPACT TABLE (Immunefi v2.3)

The CANDIDATE's captured impact must map to one of these EXACT categories (the hunter drives the
chain to one of these terminals; anything below is Informative, not a finding):

CRITICAL (direct theft / permanent loss / insolvency):
- Direct theft of user funds, at-rest or in-motion, other than unclaimed yield
- Direct theft of user NFTs, at-rest or in-motion, other than unclaimed royalties
- Permanent freezing of funds; permanent freezing of NFTs
- Unauthorized minting of NFTs
- Predictable or manipulable RNG that abuses the principal or NFT
- Unintended alteration of what the NFT represents (token URI, payload, content)
- Protocol insolvency
- Governance vote manipulation that deviates from the voted outcome and changes the intended effect

HIGH (unclaimed yield theft/freeze; temporary freeze of principal):
- Theft of unclaimed yield; theft of unclaimed royalties
- Permanent freezing of unclaimed yield; permanent freezing of unclaimed royalties
- Temporary freezing of funds; temporary freezing of NFTs

MEDIUM (operational disruption; griefing; gas theft):
- Smart contract unable to operate due to lack of token funds
- Block stuffing; griefing (no attacker profit, damage to users/protocol); theft of gas;
  unbounded gas consumption

LOW: contract fails to deliver promised returns but does not lose value.

GATE: the impact selected at submission MUST appear verbatim in the program's impacts list. A
mismatched or invented impact = immediate downgrade or Informative close.

## 2b. BLOCKCHAIN / DLT SEVERITY (v2.3) - node / consensus / network assets (onchain-hunter: Cosmos, Substrate, alt-L1)

- CRITICAL: total network shutdown (nodes cannot confirm new tx); unintended PERMANENT chain split
  requiring a hard fork; direct loss of funds; permanent freezing of funds (fix needs a hardfork).
- HIGH: unintended chain split (network partition); temporary freeze of network tx by delaying one
  block 500%+; forcing nodes to process mempool tx beyond set parameters; RPC API crash affecting
  projects with >=25% market cap on that layer.
- MEDIUM: node resource consumption up >=30%; shutdown of >=30% of nodes without shutting the
  network; a layer 0/1/2 code bug causing unintended smart-contract behavior.
- LOW: shutdown of >10% to <=30% of nodes; tx-fee modification outside design parameters.

## 2c. WEBSITES / APPS SEVERITY (v2.3) - a program's web/app asset class

Most Immunefi web scope is the SPA-trap (in-scope = marketing URLs, real backend OOS - see the
goodscope memory), but some programs list real web assets; map our normal web bugs to these:

- CRITICAL: arbitrary system command execution; read sensitive server files (/etc/shadow, DB creds,
  blockchain keys); take down the app/website or the NFT URI; state-modifying AUTHENTICATED actions
  on behalf of other users without consent (register, comment, vote, trade, withdraw); change NFT
  metadata; subdomain takeover WITH an already-connected wallet interaction; direct theft of user
  funds or NFTs; malicious interaction with an already-connected wallet (modify tx args, substitute
  a contract address, submit a malicious tx); malicious HTML/XSS injected via NFT metadata.
- HIGH: inject/modify PERSISTENT static content without JS; change another user's sensitive details
  without wallet interaction, up to one click; improperly disclose highly-sensitive PII
  (email/phone/address) without consent; subdomain takeover WITHOUT a connected wallet.
- MEDIUM: change another user's non-sensitive details (incl. local storage) without consent, one
  click; REFLECTED static-content injection without JS; open redirect.
- LOW: change user details WITH significant interaction; take over broken/expired outgoing links;
  temporarily disable a user's access.

## 2d. AUTO-EXCLUDED (Common Vulnerability Exclusion List - closed OOS regardless of PoC; check BEFORE drafting)

immunefi.com/common-vulnerabilities-to-exclude/ - a submission that matches an item here is closed
out-of-scope no matter how good the PoC. Run this gate before any Immunefi draft.

- GENERAL: self-inflicted-then-reported damage; any impact that needs a leaked key / credential; any
  impact that needs a privileged address (UNLESS the contract has no privileged role at all);
  externally-caused stablecoin depeg; unverified GitHub secrets; best-practice / feature-request
  asks; test / config files.
- SMART CONTRACT / DLT: PASSIVE bad-oracle-data (but oracle MANIPULATION, e.g. a flash-loan-moved
  price, STAYS in scope); 51%-class economic / governance attacks; illiquidity; Sybil;
  centralization risk.
- WEB / APP: theoretical-only; needs physical / local-network access; REFLECTED PLAIN-TEXT injection
  (but REFLECTED HTML / JS STAYS in scope - a byte-level line); self-XSS; impact-less CSRF;
  header / cookie-flag findings with no demonstrated impact; non-confidential server info
  disclosure; enumeration-only; DDoS-only; cosmetic UX; browser/plugin-caused; non-sensitive
  API-key leak; SPF/DMARC; scanner-only.

## 2e. SEVERITY NUANCES a CVSS-trained reflex gets WRONG here

- Immunefi is IMPACT-first, not likelihood/complexity-first. A trivial-to-reach bug with no real
  fund/data impact is LOW (or excluded) even where CVSS inflates it on low attack complexity; a
  hard-to-reach direct-fund-theft is CRITICAL regardless of complexity.
- PRIVILEGE-required or uncommon-user-interaction DOWNGRADES or rejects the bug (opposite of CVSS
  PR/UI, which only shaves decimals).
- SC "Low" is nearly a null tier (one line item). A CVSS Low/Medium informational is more likely
  AUTO-EXCLUDED (2d) here than paid as a Low.
- The Risk Breakdown cites the Immunefi table directly, never a CVSS vector.
- A genuine BYPASS of a fix from a prior audit / known issue is VALID, not a dupe (our highest-EV
  Immunefi class; see the incomplete-fix skill). A "private known issue" is program-dependent -
  confirm per program.

## 3. PRIMACY OF IMPACT vs PRIMACY OF RULES (check the program header before submit)

- PRIMACY OF IMPACT (most programs, researcher-favorable): a bug is judged by impact, so an
  unlisted-but-related contract is eligible if the impact category is in scope. It is a per-program
  OPT-IN stated in the Program Overview, and covers only an IN-scope impact landing on an OOS asset;
  it does NOT cover an out-of-scope impact, a theoretical / non-current-risk impact, or a severity
  beyond what the program names.
- PRIMACY OF RULES (strict): the contract address must appear verbatim in the scope list, or the
  report is out-of-scope regardless of severity.
Verify the designation on the program page each time; record it in PROGRAM.md.

## 4. POC REQUIREMENTS (mandatory, hard-enforced)

- WHEN: Polygon requires a PoC for ALL severities including Low. General Immunefi: required for
  Critical/High, expected for Medium/Low.
- FORK-ONLY: test on a LOCAL fork of mainnet/testnet via Foundry (`vm.createSelectFork`,
  `anvil --fork-url`) or Hardhat (`hardhat_reset` + `forking.url`). Testing on mainnet or any public
  testnet is grounds for an immediate permanent ban, enforced even with zero financial damage. A
  unit test that does not fork live state is rejected. ONE exception: when forking is genuinely
  infeasible, the project's OWN test suite is accepted as the substitute, but only if the test
  conditions accurately reflect the state of the DEPLOYED code. HOSTED / managed forks (Tenderly,
  an Infura fork endpoint) are UNSAFE for a real PoC: a third party can observe the exploit before
  disclosure. Use a LOCAL fork only (anvil, hardhat local node, Remix-VM).
- WHAT IT MUST SHOW: actual fund movement / state change / the exact claimed impact, on the REAL
  deployed addresses, at a pinned fork block. Self-verify success by asserting the terminal state
  (balance delta, storage corrupted, supply minted) - a `print` / `console.log` that fires even on a
  reverted tx is not proof. This is the same proof-integrity gate as
  `patterns/_meta/EVM-ONCHAIN-DOCTRINE.md`.
- FORMAT: a Foundry `.t.sol` forge test (preferred) or a Hardhat test, runnable by an independent
  reviewer with one command, including the fork block + RPC, the `vm.deal`/`vm.prank` setup, the
  exploit call, and the terminal assertion. Simple bug = paste inline; multi-file = Google Drive
  link. Scaffold locally with `scripts/scaffold-fork-poc.sh <slug> <chain> [block]` (shared `ForkPoC`
  base, keyless archive RPC, self-check). Our `ForkPoC.assertGained` is the home-grown equivalent of
  Immunefi's own `snapshot(account, tokens[])` modifier (auto-prints pre/post balance + profit,
  `address(0)` = native) - a reviewer who knows the template will recognize either. To start from
  Immunefi's template instead: `forge init --template immunefi-team/forge-poc-templates --branch
  [default|reentrancy|flash_loan|price_manipulation|oracles|sandwich|mocks]`. FASTEST PATH: clone the
  project's OWN repo at the vulnerable commit and reuse ITS unit tests (swap the contract-factory
  ref) rather than hand-transcribing; `cast interface` / `cast etherscan-source` pull the real
  deployed contract. Upstream reference: https://github.com/immunefi-team/forge-poc-templates
- MAXIMIZE THE DAMAGE: before writing the report, optimize the attack parameters to show the MAXIMUM
  realistic economic damage - Immunefi bounties scale off "% of funds at risk", so quantify the loss
  in the Impact section, do not just prove the mechanism fires.

## 5. REPORT FORMAT (the Immunefi dashboard 7-section form; fill EVERY section)

1. TITLE - vulnerability class AND the impact, one line ("Reentrancy in withdraw() drains all
   funds"), never "Critical bug in protocol".
2. ASSET - select from the program's asset dropdown; never a custom string (wrong asset = scope
   reject).
3. IMPACT AND SEVERITY - select the impact from the program's dropdown (section 2 category), not a
   CVSS score; it must match what the PoC proves.
4. BUG DESCRIPTION - root cause, the vulnerable function/contract/line, why it is exploitable.
   Impact does not go here.
5. PROOF OF CONCEPT - the runnable fork test (section 4), with the fork block number + RPC; it must
   demonstrate the exact claimed impact, not a weaker primitive.
6. RECOMMENDATION - the specific code change / invariant that closes it, not "add access control".
7. REFERENCES - Etherscan/Polygonscan links, audit reports, related CVEs, docs.

Map from the workspace internal shape: Summary -> (4) Bug Description; PoC capture -> (5) PoC;
captured terminal + impact category -> (3) Impact + (1) Title. Drafts still land in
`reports/drafts/<program>/` for the operator's manual submit via the Immunefi dashboard; NEVER auto-submit.
First person, English, no theoretical content, evidence only - the workspace report discipline still
applies inside the Immunefi sections.

LENGTH: Immunefi reports are 2500-3000 words (the operator 2026-06-28). This OVERRIDES the workspace
<1000-word default - an Immunefi dashboard report needs room for the 7 sections, the root cause, the
fork PoC, and the reachability/eligibility argument. The C1 reference report ran 3359 words; aim for
the 2500-3000 band and compress only prose, never evidence. The draft-write lint and
`scripts/immunefi-presubmit.sh` both enforce this band for Immunefi drafts.

ACCEPT signals (what triagers reward): impact matches a listed category exactly; PoC runs clean on a
fork and produces the claimed terminal state; title names class + impact; description names the
function + root cause; recommendation is specific. CLOSE signals: "could lead to" with no
terminal-state PoC; unit-test-only or mock PoC; OOS asset under Primacy of Rules; impact mismatch;
duplicate root cause; capability-empty (a protocol quirk granting no new capability - the
mechanism-without-capability disease).

## 6. KYC, DISCLOSURE, PROHIBITED ACTIONS

- KYC before any payout: government ID (passport), proof of residence, wallet address; US persons
  need a W-9; no payouts to OFAC/UNSC-sanctioned persons.
- DISCLOSURE (Polygon = Category 3, Approval Required): zero public disclosure or third-party share
  until the project approves in writing; no guaranteed timeline; no Twitter/blog/Discord before fix
  + approval. Violation = report closed, no payout, possible ban.
- PROHIBITED (any = ban or closure): testing on mainnet or public testnet; exploiting beyond what
  proves impact (no real fund theft); social engineering or phishing the team/users; DoS or
  automated traffic against live infra; oracle manipulation that affects real users; harming
  third-party protocols; public disclosure of unpatched bugs; any destructive/irreversible action on
  production; bulk enumeration or exfiltration of real user data. Submit via the Immunefi dashboard
  only.

## 7. THE SIX SHIP GATES (a CANDIDATE passes ALL before a draft ships)

- GATE-1 IMPACT MATCH: the claimed impact maps to an exact category in section 2; else Informative
  or escalate to a category that matches.
- GATE-2 TERMINAL RECEIPT: the PoC ran on a FORK (not mainnet, not unit-test) and produced a
  captured terminal state (funds moved, state corrupted, yield stolen, supply minted); the assert on
  the event/balance passed, not a print.
- GATE-3 ASSET IN SCOPE: the contract is in the asset list (Primacy of Rules) or the impact category
  is in scope (Primacy of Impact).
- GATE-4 POC FORMAT: runnable Foundry/Hardhat fork test at a pinned block, with setup + exploit +
  terminal assertion, runnable in one command.
- GATE-5 REPORT SECTIONS COMPLETE: all seven of section 5.
- GATE-6 DISCLOSURE CLEAN: no public post, no third-party share, no prior submission of the same bug
  elsewhere.

## 8. THE BULLET GATE (pre-submit, one-shot - run before any Immunefi draft is READY)

Immunefi rate-limits submissions (since 2025-10-01): 1 report / 24h until your first PAID report,
then 5 / 48h; pay-to-submit is exempt. AI-generated / automated / spray-and-pray reports and
repeated OOS or severity-misclassified submissions are documented reject-or-ban triggers, so the
draft must be a bullet that cannot miss and must not read machine-generated. Before telling the operator a
draft is READY, run the mechanical gate and clear the judgment confirms:

```
scripts/immunefi-presubmit.sh reports/drafts/<program>/<draft> [gist_dir]
```

It hard-FAILs on the three things that have cost us reports, and prints CONFIRM lines for the two
judgment calls a script cannot decide:

- RULE 1 - NEVER OUT OF SCOPE (the berachain #83336 miss). The mechanical check verifies the `## ASSET`
  token is on a non-OOS SCOPE line and that no cited `0x...`/github component is on an OOS line. The
  DECISIVE check is judgment and is owned by report-killer: name the file/contract whose code MUST
  change to fix the bug; that exact component must itself be a LISTED in-scope asset. #83336 declared
  `ASSET = bera-reth` (in scope) but the fix lands in `bera-geth` (UNLISTED, and "Upstream reth bugs"
  are OOS) - a laundered OOS root cause that closed OOS in 29 minutes. A declared asset that is merely
  a spec-correct SIBLING of the faulty component is OUT OF SCOPE under Primacy of Rules.
- RULE 2 - THE GIST MUST REPRODUCE FROM ANY ENVIRONMENT. The check fails the gist on any host-path /
  username / VPS-IP leak and on the absence of a Docker-first repro (native repro is environment-
  fragile: C1's native path failed because a local `cc` shadowed the real compiler). Then MANUAL-VERIFY:
  clone the gist to an EMPTY dir on a clean box and run the Docker repro end to end; it is only verified
  when the terminal receipt prints from the clean container. A triage-validator clean-env run owns this.
- RULE 3 - 2500-3000 WORDS (section 5 LENGTH).

A PASS here is necessary, not sufficient: clear every CONFIRM/MANUAL-VERIFY line, then run
report-killer (Primacy-of-Rules round) and a triage-validator clean-container repro before READY.

## Sources
- https://immunefi.com/bug-bounty/polygon/information/#top
- https://immunefi.com/immunefi-vulnerability-severity-classification-system-v2-3/
- https://immunefi.com/common-vulnerabilities-to-exclude/ (the auto-OOS exclusion list, section 2d)
- https://immunefi.com/immunefi-top-10/ and https://immunefi.com/common-vulnerabilities/ (root-cause taxonomy)
- https://immunefi.com/blog/expert-insights/primacy-of-impact/
- https://github.com/immunefi-team/Web3-Security-Library (curated tools + vuln-class + bugfix-review index)
- Immunefi Medium public fallbacks when the Zendesk help-center 403s to a login wall: "Why You Should Never Test Exploits on Mainnet or Public Testnets", "A Hacker's Guide to Submitting Bugs", "How To Use Foundry To PoC Bug Leads" parts 1-2
- https://immunefisupport.zendesk.com/hc/ (PoC Guidelines, Bug-Report Template, Primacy-of-Impact, KYC, Duplicates: all LOGIN-WALLED as of 2026-07, use the Medium fallbacks above)
- https://github.com/immunefi-team/forge-poc-templates
- Full distillation: .claude/research/sc-fleet/5-immunefi-policy.md
