# Compaction and lineage

How gnoc chat keeps a long conversation inside the model's window without losing it (Phase 2, 2026-11-26).
Code: `scripts/gnoc_core/compact.py` (the stages), `scripts/gnoc_core/lineage.py` (the archive),
`scripts/gnoc_core/summary.py` (the model stage and its validator), `scripts/gnoc_recall.py` (search).
Tests: `scripts/test_gnoc_phase2_compaction.py`.

## When it runs

- Before a turn, when the window is over 88% full (preflight).
- During a turn, before each model step, when the history no longer fits (deterministic only, see below).
- After a turn, before the chat is saved.
- On `/compact`.
- Inside a delegated worker (deterministic only, no archive: a worker's transcript is not a saved chat).

## Stage 1: deterministic (always)

Unchanged from before Phase 2, except that hunt vocabulary is now confined to hunt mode:

1. Old tool output shrinks to 300 characters, then the five newest-but-one to 1500. The newest tool result is
   never cut (the model has not read it yet).
2. Old turns fold into one `[SESSION NOTES ...]` user message at the top: `Q:`/`A:` lines and one line per tool
   call. The current turn (`keep_from`) is never folded; an assistant message leaves together with all of its
   tool results; without a protected tail at least three messages stay.
3. Hunt mode (`hunt_stance`) picks verdict words and `targets/` / `reports/` evidence paths out of tool output,
   exactly as before. A general chat picks general file paths instead and no verdicts.

## The archive (always, for a saved chat)

Before the notes are rewritten, the original form of every message the pass dropped or shortened is written to
`sessions/segments/<sid>/sNNNN.json`:

```json
{"id": "<sid>~s0003", "parent": "<sid>~s0002", "turn_base": 7, "turns_after": 9,
 "notes_before": "...", "messages": [{"role": "user", "content": "...", "turn": 8, "state": "dropped"}]}
```

- Segments are written once (atomic write, never overwritten, mode 600, directory 700) and form a chain through
  `parent`. The live `sessions/<sid>.json` records `parent` (the newest segment), `segments` and
  `turns_archived`.
- A message trimmed by an earlier pass and dropped by a later one is marked `trimmed_earlier`; its full text is
  in the earlier segment.
- If the archive cannot be written (full disk, permissions), the fold still happens (an overflowing window is
  cut silently by the server, which is worse), the turn says so, and the notes record that some folded text has
  no archive. That chat's notes then never go to the model stage.

The first line of the notes body names what they stand for:

```
[archived originals: chat <sid>, segments 1-7; model summary through segment 5; the recall tool returns their exact words]
```

## Stage 2: the model summary (general chats only, optional)

Runs after a turn (and on preflight and `/compact`), never mid-turn, so a turn does not pay one extra model call
per step. It runs only when all of these hold:

- the chat is not in hunt mode (hunt notes are receipts; a paraphrase of a verdict is not one);
- `GNOC_COMPACT_SUMMARY` is not `0`;
- the notes carry an archive header for this chat, with no unarchived folds;
- every segment the notes cover is readable on disk (`Lineage.reachable`): a summary is never made of a summary
  whose originals are gone;
- there are segments the model summary does not cover yet;
- the deterministic notes are not enough: they miss a path or a user constraint of the new originals, keep under a
  quarter of the conversation's own text, or are within 10% of the 8000-character cap.

The input is the current notes plus the originals of the new segments, read back from disk, redacted with
`gnoc_secrets.redact` and fenced as data. The call is the existing worker role (`resolve("worker")`, `llm_chat`
with thinking off, no retry, a 90 s timeout, `GNOC_COMPACT_SUMMARY_TIMEOUT` to change it), so routing, the privacy
gate and cloud redaction are the same as every other worker call.

The answer is scanned with `gnoc_comms.injection_signs`: invisible characters are removed, and an answer with
attack signs (override, role, exfiltrate, hidden-html, tool-call) is discarded. An error, a timeout or an empty
answer is discarded too. In every one of those cases the deterministic notes stay as they are.

## The validator

Whatever the model wrote, these are added back verbatim when it left them out:

- **File paths**: tokens starting with `/`, `~/`, `./` or `../`, or ending in a file extension, or with two or
  more slashes (never inside a URL, never an all-digit date), plus bare names with a source extension
  (`calc.py`). Taken in full from the user's and gnoc's messages and tool-call arguments, and the first 8 of each
  tool result. At most 60 are re-added; the rest are counted and stay in the archive.
- **User constraints**: sentences of the user's own words containing don't / do not / never / must / mustn't /
  only / always / avoid / stop / no longer / should / shouldn't / need to / has to / have to / make sure / keep /
  without / instead of. One counts as kept when three quarters of its content words appear on one line of the
  summary.

Restored items outrank the model's prose at the cap: the prose is cut first.

## Recall

`gnoc_recall` indexes the archived segments next to the live chats (index schema 2; an older index is dropped and
rebuilt, it is a cache). A hit from a segment says `chat <sid> (archived segment N, turn T)`. The current chat's
live messages are left out of a search (the model already has them), its archived turns are not. Once a chat has
an archive, its live notes are not indexed: search returns originals, never a summary. Archived tool results are
indexed as well and are scanned for injection signs when shown.

## Rollback

`GNOC_COMPACT_SUMMARY=0` turns the model stage off. Reverting the Phase 2 commits restores in-place compaction;
segment files left on disk are ignored by the old code, which reads the newer recall index through the columns
both schemas share (delete `recall.sqlite` to force a clean rebuild).
