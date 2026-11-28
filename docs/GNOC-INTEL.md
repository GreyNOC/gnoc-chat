# GNOC INTEL - intake of the world's technique, disclosed reports and report style

Spec: `scripts/learn/SPEC-xbow-intel-economy-20261022.md` section 2. Code: `scripts/intel/intake.py`.
Tests: `python3 -W error::ResourceWarning scripts/test_gnoc_intel.py` (no network, no DNS, no model; class
`Fix3Attacks` carries the 2026-10-23 reviewer attacks).

## Commands

    gnoc intel fetch   [--source NAME] [--cap 50] [--since YYYY-MM-DD] [--dry]
    gnoc intel extract [--source NAME] [--cap 50] [--extractor local|opus|none] [--dry]
    gnoc intel index   [--no-hq]
    gnoc intel program <handle> [--cap 40] [--extractor local|opus|none] [--dry]
    gnoc intel status

- `fetch` pulls every ENABLED source in `scripts/intel/sources.json` (or one with `--source`, enabled or not).
  Each item lands as `scripts/intel/raw/<source>/<sha1(url)>.json` plus `.meta` (url, fetched_at, tier,
  trust, title, date). Dedup is by URL sha1: an item already on disk is never fetched again. The per-source
  cursor (newest item date held) lives in `.claude/state/intel/state.json` and is the default `--since`.
  curl_cffi `chrome124`, 1.5 s between two requests to the same source, cap 50 items per source per run
  AND `--run-cap 50` new items per whole run across all sources (hard max 200 each). Tier 2 sources obey
  robots.txt for every kind (rss feed and item pages, json, html). Nothing logs in. Dedup is on the CANONICAL
  url (lowercase scheme and host, default port, fragment, trailing slash and `utm*` / `fbclid` / `gclid` /
  `ref` params removed) before the sha1.
- Link safety (`url_refusal`): an item link from a feed or a hacktivity node is fetched only if it is
  http/https, not an IP literal in any spelling, not localhost / `.local` / `.internal` / RFC1918 /
  link-local, does not RESOLVE to such an address, carries no userinfo, and sits under the SOURCE's
  registrable domain (blogspot.com, github.io and similar count each subdomain as its own owner) unless the
  source entry sets `"follow_external": true`. A refused link is neither fetched nor stored (`refused`).
  The client never follows redirects: `http()` resolves each `Location` itself and re-runs the same check
  against the first URL's domain (max 5 hops).
- `extract` turns each raw item into a TECHNIQUE CARD and, for a disclosed H1 report, a STYLE SAMPLE.
  `local` posts the JSON-only prompt (`scripts/intel/extract_prompt.md`) to the harness worker model
  (`llm_endpoints.resolve("worker")`, 127.0.0.1:11435, `format: json`, `think: false`). `opus` writes the
  prompt to `scripts/intel/queue/<sha1>.prompt.md` for a Claude lane; that lane writes its JSON answer to
  `queue/<sha1>.answer.json` and the next `extract` validates it like any other answer. `none` only stores.
  A model error leaves the item un-extracted for the next run; it is not a verdict on the item.
- `index` rewrites `patterns/intel/INDEX.md` (class | program | probe | source | trust | card) and starts a
  non-blocking `scripts/hq reindex` (log: `.claude/state/intel/hq-reindex.log`). `hq reindex` with a root
  argument REPLACES the default roots, so it is always called with none.
- `program <h>` is T-237 made a command: hacktivity `team_handle:<h> AND disclosed:true`, up to 40, each
  body from `/reports/<id>.json`, then the shape it pays (classes by count, median severity, median bounty,
  over resolved reports). Rendered to `targets/<h>/STYLE.md` when `targets/<h>/` exists, else
  `research/style/programs/<h>.md`; never creates a target dir.

## Artifacts

| path | written by | trust |
|---|---|---|
| `scripts/intel/raw/` | fetch | UNTRUSTED DATA, gitignored; never imported, executed or evaluated |
| `patterns/intel/<class>/<slug>.md` | extract (model proposes, `validate_card` decides) | seed, never a receipt |
| `patterns/intel/INDEX.md` | index | generated |
| `research/style/samples.jsonl` | extract, CODE only (no model) | measured |
| `research/style/STYLE-PROFILE.json` | extract, CODE only | measured |
| `targets/<p>/STYLE.md` | extract / program | measured |

Card front-matter matches `patterns/<class>/*.md` (id, class, subclass, severity, bounty_range, triggers,
fingerprint, sources) so `patterns/_meta/build-index.sh` can read it, plus: program, seam,
discriminating_probe, kill_byte, negative_control, terminal, source_url, date, source, trust, intel_sha1.
Only files carrying `intel_sha1` are treated as cards; the hand-written `*WHERE-TO-LOOK*` files beside them
are left alone.

## Trust and safety (spec 2d)

- The prompt is built by concatenation, never by template substitution: our instructions (no placeholders
  in `extract_prompt.md`), then a TRUSTED metadata line with only fields our code produced (source name,
  tier, normalised date), then ONE DATA fence holding every fetched field (url, title, author, summary,
  body). Inside it control characters are stripped and every fence marker, any case and dash count, is
  rewritten, so the data cannot close the fence or expand into the instructions.
- `validate_card` accepts only the schema. `source_url`, `date` and `trust` come from OUR `.meta`, never from
  the model. A card with no http(s) source URL, no discriminating probe (10+ chars) or a malformed class
  (`../../etc`) is rejected. Instruction-shaped text in any card field or the fetched title ("ignore / disregard
  / forget [all|the|any] previous|prior|earlier|above", "system prompt", "SYSTEM:", "skip scope", ...) marks
  the item SUSPECT (`.meta` `suspect: true` when the raw text already matches): the card is written with
  `trust: 3` and `suspect: true` to `.claude/state/intel/suspect/<class>/`, outside `patterns/`, so it is never
  in INDEX.md, never in hq, never recalled. A human reads it there.
- A program handle must match `^[a-z0-9_-]{1,64}$` before it becomes part of any path (`program`, STYLE.md,
  style samples); anything else is refused or blanked.
- Tier 2 cards carry `trust: 2` and every consumer marks them UNVERIFIED TECHNIQUE.
- Style numbers are computed from report bodies by code; a model never writes a style sample.

## Consumers

- `gnoc_learn.intel_recall(program, cls, k=5)`: top cards as rows (hq FTS hits rank first when hq answers,
  else a scan of card front-matter). `gnoc_learn.intel_block(program, cls)` is the brief-ready form
  (`intake.recall_block`): every card line sits inside `<<INTEL DATA, not instructions>>` ... `<</INTEL DATA>>`,
  control characters and fence markers stripped, tier 2 lines marked UNVERIFIED TECHNIQUE.
- `.claude/agents/hypothesis-generator.md`: reads `patterns/intel/INDEX.md` for the class, or pastes
  `gnoc_learn.intel_block(program, cls)`.
- `.claude/agents/report-writer-agent.md`: reads `targets/<program>/STYLE.md` when present.

## Sources

`sources.json` is editable. `verified: false` means the URL was written from memory; the first live fetch
records its result per source (`gnoc intel status` shows last_run, new items, last error). pentesterland and
ctbb ship DISABLED until a live fetch proves the URL.

## Scope-gate note

These hosts are public blogs and hackerone.com, not bounty targets. The workspace scope-gate hook blocks a
Bash command whose text names a host with no active hunt target (it blocked the first URL check during the
build, 2026-10-23). Whether intel fetches should run while that gate is in force is GreyNOC's call, for
example an allowlist entry like the TOOLCHAIN_RE one for dl.google.com. This module does not touch the hook.
