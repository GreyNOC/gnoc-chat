# Test baseline on the synced 2026.11.26 tree

Recorded 2026-11-26 on branch `sync/2026.11.26` (sync commit f5a86d3 plus the VERSION fix 03b32e5), with
`cd scripts && python3 -m pytest -q`, Python 3.13.5, pytest 9.1.1, Linux, run as an ordinary user (not root).

| | passed | skipped | failed |
|---|---|---|---|
| GitHub d2c33ff (2026.11.25.1), container run as root, from the task brief | 849 | 11 | 2 |
| 2026.11.26 sync, this host | 901 | 10 | 3 |

The two failures from the brief (`RealTurnsRunEndToEnd::test_a_command_that_was_held_is_not_reported_as_run`
and `..._is_marked_unchecked`) PASS here as an ordinary user. Phase 0 settles their cause.

The three failures on this host are all 2026.11.26 tests in
`test_gnoc_drive_20261120.py::AnotherProgrammesPathIsNotARoute20261125`:
`test_foreign_file_is_fenced_and_its_path_refused`, `test_grep_lines_are_attributed_per_file`,
`test_hunt_search_is_limited_to_the_active_programme`. They pass only in a workspace that has `targets/stayco/`
on disk. Phase 0 diagnoses and fixes them.

Phase −1 adds `scripts/test_gnoc_release_20261126.py` (4 tests, all passing): the /file typed-only gate, which
had no test. After it, the baseline is 905 passed, 10 skipped, 3 failed. No later phase may add a failure.
