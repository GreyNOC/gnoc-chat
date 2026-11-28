# HUNT-INDEX - one queryable SQLite brain over all hunt data

Maps hosts, endpoints, requests/responses, notes, verdicts and reports across
the live workspace into one SQLite file with full-text search. Built for cheap,
token-thin querying by the orchestrator and workers: one `hq` call returns a
distilled table, never a raw file dump.

## WHAT THIS INDEX DOES NOT CONTAIN (measured 2026-10-10 - read before trusting a zero)

The line above used to read "every host ... AND every HDD backup snapshot". That overclaimed, and the
`--backups` note further down already contradicted it. Three gaps, all measured:

1. **NO HDD BACKUP ROWS.** `SELECT COUNT(*) FROM sources WHERE path LIKE '/mnt/hdd%'` returns **0**,
   and `/mnt/backup` is unmounted. The index is LIVE-TREE ONLY unless someone runs `--backups`.
2. **THE REQUEST TABLE IS FORMAT-LIMITED.** `parse_requests()` understands HAR and per-line JSON only.
   Most captures in this workspace are curl text, `.hdr` or `.resp.txt`, and they are INVISIBLE to it.
   Measured: a host hammered with thousands of requests in one session returns EMPTY from
   `hq reqhost`, while appearing in 476 files on a filesystem content sweep. **`hq` alone handed a
   retrospective audit a false all-clear.**
3. **TRANSCRIPTS BEGIN 2026-09-30T18:15:59Z.** Nothing earlier has a transcript instrument at all.

So an empty `hq` result means "not in the parsed subset of the live tree since 2026-09-30", NEVER
"this never happened". For any question that must be answered definitively - did we ever send this,
is this surface really uncovered - triangulate and SAY WHICH INSTRUMENTS YOU RAN: the request table,
the hosts table joined to docs, a filesystem CONTENT sweep over capture extensions plus extensionless
files under capture-looking directories, a filename sweep, the session transcript jsonl (which is what
actually found all three hits in that audit), and a direct grep of `reports/` and the staging tree.

- Indexer: `scripts/hunt-index.py`  (Python stdlib only, no deps)
- Query wrapper: `scripts/hq`  (thin sugar over `sqlite3`; raw SQL always available)
- Database: `.hunt-index/hunts.db`  (regenerable; not committed)

## Build / refresh

```bash
scripts/hq reindex                     # live workspace only (~2.5 min, ~1.6G) - the daily driver
python3 scripts/hunt-index.py --backups  # ALSO index HDD backup snapshots (heavy, slow, 18G+)
python3 scripts/hunt-index.py --selfcheck  # runnable check, no side effects
```

Full rebuild each run (drops tables). Content-hash dedup collapses duplicate
files (and, with `--backups`, the overlapping snapshots), storing one unique
note ONCE while the `sources` table keeps every physical copy for provenance.

Default is live-only because the HDD backups are mostly the same notes at
different points in time - high cost, low marginal value. HDD roots are globbed
from `/mnt/backup` (see `HDD_GLOBS`). Add any root: `--root /path/to/extra`.

## Query

```bash
hq                         # schema + counts (unique docs, total copies, hosts, urls)
hq stats                   # dashboard: docs per role, top programs, request status spread
hq search graphql introspection    # FTS across every note/verdict/report/capture
hq host portal.2k.com      # which docs mention a host, and for which program
hq hosts thredup           # distinct hosts seen, by frequency
hq target program-19  # every doc for a program, newest first
hq req /login              # captured request/response records (method,status,url)
hq reqhost api.acme.com    # hosts we hit + status codes + how many programs
hq urls /graphql           # distinct URLs matching
hq sources STATUS-2026     # every copy (live + which backup) of a doc
hq sql "SELECT target,count(*) FROM docs GROUP BY target ORDER BY 2 DESC"
```

`search` is full-text over the two high-signal tiers (intel + http); it does
NOT return cloned/decompiled source, which is stored discoverable-only.

## Browser UI (interactive)

```bash
scripts/hq-web            # http://127.0.0.1:8001  (Ctrl-C to stop)
scripts/hq-web 8080       # custom port
```

Runs [datasette](https://datasette.io) over the db (read-only/immutable). Gives:
browse+filter every table, click-facets on role/kind/target/status, live SQL, a
JSON API (append `.json` to any URL), and canned queries in the left nav -
full-text `search`, `host`, `requests_by_host`, `program_docs`, `top_programs`.
Install once: `pipx install datasette`. Config: `scripts/hq-web.json`.

## What is indexed (whitelist - hunt intelligence only)

Two full-text tiers, by extension whitelist (`INTEL_EXT` in the script):
- `intel` - md/txt/verdicts/reports/scope/status/notes. Full-text.
- `http`  - captures (.jsonl/.ndjson/.har/.log/.csv) + small `.json` under
            hunt/evidence/recon/poc/reports/state paths. Full-text AND parsed
            into the `requests` table (method/host/url/status).

Host/URL extraction is capped at 500 per doc so a mega recon-dump cannot blow
the tables. A live-only build is ~55k docs / ~1.6G in ~2.5 min.

Skipped and COUNTED (printed at end of build, never silent):
- cloned/decompiled source (.java/.smali/.sol/.js/.ts/.go/.rs/...) - ~1.2M files,
  not hunt data. Add with `--full-code` if you must grep them.
- large `.json` recon dumps (over 512KB) and non-intel extensions (.html/.xtb/...)
- true binaries (images, objects, archives, apks, fonts, media)
- decompiled-app trees (smali/res/META-INF) - add with `--include-decompiled`

## Schema

`docs`(id, sha, path, target, kind, role, ext, mtime, size, ncopies, body) |
`sources`(sha, path, root, mtime) | `hosts`(doc_id, host) | `urls`(doc_id, url) |
`requests`(doc_id, target, method, host, url, status) | `fts`(FTS5 over docs.body)
