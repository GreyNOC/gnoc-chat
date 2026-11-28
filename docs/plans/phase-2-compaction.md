# Phase 2: summarizing compaction with lineage

- Archive first: every compaction writes the ORIGINAL form of each message it drops or trims to
  `sessions/segments/<sid>/sNNNN.json` (parent-linked) before the live history is rewritten; the session file
  records `parent`, `segments` and `turns_archived`.
- Keep the deterministic notes as stage one; hunt vocabulary (`_VERDICT`, the hunt-only path regex) runs only in
  hunt mode, general mode uses a general path regex. Hunt-mode notes stay byte-identical.
- Stage two (general mode only, worker role, optional): when the deterministic notes lose too much, the worker
  model rewrites the notes from the archived originals read back from disk. Redact before sending, scan the answer
  for injection/invisible characters, fall back to the deterministic notes on any error, timeout or refusal.
- A mechanical validator re-adds every file path and user constraint the summary dropped. The model stage refuses
  to run unless every segment the notes cover is readable on disk and the notes hold no pre-lineage lines.
- Recall indexes archived segments (schema v2, auto-rebuilt) and names the segment and turn of each hit.

## What was built

- `gnoc_core/lineage.py`: per-chat segment archive (`sessions/segments/<sid>/sNNNN.json`), written once, atomic,
  mode 600, parent-linked; `head`, `chain`, `reachable`, `turns_archived`. Session ids with path separators refused.
- `gnoc_core/compact.py`: `_compact(..., hunt, lineage, summarize)`. Originals are deep-copied before any trim and
  archived before the notes change; the notes get an archive header (segment range, how far the model summary
  reaches, a gap flag). `_VERDICT` and the hunt path regex run only with `hunt=True`; general chats use a general
  path regex. `upgrade_notes` is stage 2; `chat_kwargs` builds the keywords for a saved chat.
- `gnoc_core/summary.py`: the worker request (redacted, fenced), the injection scan of the answer, the validator
  that restores dropped paths and user constraints (heuristic documented in the module and in
  `docs/GNOC-COMPACTION.md`), the "not enough" test, and `worker_summarizer` on the existing worker role.
- Wiring: the turn's preflight and after-turn compaction get the lineage and the summary stage, mid-turn folds get
  the lineage only (no extra model call per step); `/compact` the same as after a turn; workers pass `hunt` and no
  lineage. `Agent.save` writes `parent`, `segments`, `turns_archived`.
- `gnoc_recall.py`: index schema 2 (turn, chat, segment), archived segments indexed (tool results too), live notes
  skipped once originals are archived, hits name segment and turn, every shown row scanned for injection signs.
  The recall tool description and the past-chat trigger now cover "earlier in this chat".

## Security impact

- More chat text on disk: segments keep what compaction used to discard. They sit beside the session files, mode
  600 in a 700 directory, never leave the machine, and are not listed as chats.
- One new model call per qualifying compaction, on the worker role through `llm_chat`: same routing and privacy gate
  as other worker calls, input redacted with `gnoc_secrets.redact`, output scanned with
  `gnoc_comms.injection_signs` (invisible characters stripped, attack signs refuse the summary), bounded by a 90 s
  timeout with no retry. Hunt chats never make it.
- Recall can now return archived tool results (web pages, files); they are scanned and flagged when shown, and as a
  tool result they pass through the existing tool-result redaction.
- No gate was loosened.

## Rollback

`GNOC_COMPACT_SUMMARY=0` turns the model stage off at runtime. Reverting the branch restores in-place compaction;
segment files are ignored by the old code, which also reads the new recall index (shared columns; verified).

## What is left

- Segments are never pruned; a very long chat roughly doubles its on-disk size. A retention setting is future work.
- The recall index never forgets a deleted chat or segment (true before this phase too).
- `NOTES_TAG` still says "probes, verdicts"; it is an identifier matched in saved chats, so renaming it needs a
  migration that recognises both strings.
- Chats compacted before this phase keep their old notes and never get a model summary (their originals are gone).

## Release note

Long chats no longer forget. When gnoc chat folds old turns to make room, it first saves the original messages next
to the chat, and `/recall` finds them again, naming the segment and turn. In an ordinary chat your worker model then
rewrites the folded notes, and gnoc adds back any file path or instruction of yours that the summary left out. If
the worker is unavailable the plain notes are kept; `GNOC_COMPACT_SUMMARY=0` turns the step off.
Development: GreyNOC (Brad), with Claude (Anthropic) as a development contributor.
