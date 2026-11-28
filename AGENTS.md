# Engineering contract for gnoc chat

This file binds every contributor, human or AI. It was written for the Hermes-parity work (2026-11-26) from
GreyNOC's brief, because the repo had no contract of its own.

## Code

- No elided patches. Every change is written out in full; nothing is left as "..." or "rest unchanged".
- Comments explain WHY: the incident, the constraint, the receipt. The code already says what.
- Standard library first. A new third-party dependency needs a stated reason in the commit body and in
  `requirements.txt`, and gnoc must still start without it (degrade with a message naming the package).
- Every network call has a timeout.
- New code is `ruff check` and `mypy --ignore-missing-imports` clean. Inside large existing files, only the new
  lines must be clean; do not reformat code you did not change.
- New modules take their dependencies explicitly. Do not add new `gnoc_core.runtime.bind(...)` facade lookups;
  convert an existing `bind` only in a function you are already editing.
- Hunt-specific vocabulary (verdicts, programmes, targets) stays behind hunt mode, not in general paths.

## Safety invariants (never weaken)

Approval gating, scope enforcement, secret redaction, injection and invisible-character scanning of loaded text,
"only the user sets a schedule", "the model never chooses a message recipient", "a repo cannot grant itself
permissions", typed-only `/file`, and signed updates. Every new surface (gateway, plugin, scheduler, sandbox,
subagent) goes THROUGH these gates, never around them. A change that loosens one is rejected.

## Tests

- `cd scripts && python3 -m pytest -q` after every change set. No change may add a failure.
- New behaviour gets tests with negative cases (the refusal, the timeout, the malformed input), not only the
  happy path.
- Tests build their own workspace in a temp dir. A test that passes only on the operator's machine is a bug.

## Process

- One branch and one PR-sized set of commits per phase. Conventional commits.
- A phase that touches 3 or more files or a public interface writes a plan of 5 bullets or fewer to
  `docs/plans/<phase>.md` first.
- Each phase's summary states the security impact and the rollback.
- Never push, tag, publish a release, or post anywhere. The human reviews and ships.
- AI-assisted commits end with `Co-Authored-By: Claude <noreply@anthropic.com>`, and `CREDITS.md` lists the
  phases Claude worked on.
- `VERSION` never goes backwards.
