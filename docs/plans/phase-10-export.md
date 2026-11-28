# Phase 10: trajectory export and a headless batch runner

- New module `scripts/gnoc_trajectories.py`, stdlib only, dependencies passed in (no new `bind()` lookups):
  `gnoc export trajectories --format sharegpt|openai [--since YYYY-MM-DD] [--out PATH] [--good-only]
  [--no-redact] [--allow host,...] [--from PATH]` reads `gnoc_learn.TRAJ` (or `--from`), redacts, converts,
  validates every emitted line against an in-code schema check, prints counts on stderr.
- Redaction is ON by default (`--redact` is accepted as a no-op alias; `--no-redact` turns it off and warns).
  Layers: `gnoc_secrets.redact` (known values), `gnoc_distill` patterns plus a few extra token shapes and secret-named
  dict keys, `$HOME` -> `~` and the user name in paths, IPv4/IPv6 and hostnames outside an allowlist
  (`~/.gnoc/export-allowlist.txt` and `--allow`) replaced by one stable placeholder each per export
  (`host-1.invalid`, `198.51.100.1`, `2001:db8::1`). Applied to content, tool-call arguments and tool names.
- `gnoc_learn.log_trajectory` gets its record shape factored into `trajectory_record()` so the batch runner writes the
  exact same schema; nothing about what log_trajectory writes changes.
- `gnoc export batch <prompts.jsonl> --out DIR [--workers N] [--timeout S] [--steps N]`: one child process per prompt
  (a real wall-clock kill, and one Agent per process so no global state is shared), bounded pool (default 2, cap 8),
  each child a fresh `Agent(interactive=False)` with skip-perms forced off, so every gated call is HELD: recorded in
  a `held` list (tool + args summary) by wrapping `_approve`, never executed. Ctrl-C kills every child.
- `scripts/gnoc` gets `export` in the public command table and help; README section; tests in
  `scripts/test_gnoc_phase10_export.py` (schema, redaction, held write never touches disk, pool bounds/timeouts,
  malformed input refusals).

## Result

**Built.** `scripts/gnoc_trajectories.py` (export, redaction, schema checks, batch pool and child entry);
`gnoc_learn.trajectory_record()` (log_trajectory writes byte-for-byte what it wrote before); `gnoc export` in
`scripts/gnoc` (public command table and both help texts, run in-process so a relative `--out` and the batch's
agents use the folder it was typed in); README section "Export trajectories"; 35 tests in
`scripts/test_gnoc_phase10_export.py`. Full suite: 979 passed, 10 skipped, 0 failed (baseline 944/10/0).

**Spec notes.** The brief says both "[--redact]" and "redaction on by default": redaction is default-on, `--redact`
is a documented no-op alias, `--no-redact` disables it with a stderr warning, and both together is refused. Extras
beyond the brief: `--from` (to export a batch's output), `--good-only`, `--allow`. Program handles are redacted too.

**Security impact.** Read-only over the trajectory log; writes only to stdout, `--out` (0600, atomic) or a new batch
folder (0700, files 0600). Redaction only adds layers on top of `gnoc_secrets.redact` and `gnoc_distill`'s patterns;
neither is modified. The batch runner goes THROUGH the approval gate: it forces skip-perms off, runs
`Agent(interactive=False)`, and replaces `_approve` with a recorder that always answers no, so every gated call is
held and the dispatcher's own "not run" path answers the model. The user's own `/permissions` allow rules still
answer the ordinary question (as in any headless `gnoc chat` run); deny rules and every ask-every-time rule are
unchanged. Learning is off in a batch (`GNOC_NO_LEARN`), so a batch never writes the lesson book. Children run in
their own process group; a timeout or Ctrl-C kills the group. Nothing is uploaded.

**Rollback.** Revert the feat commit (module + CLI wiring) and the test/docs commits; the `gnoc_learn` refactor is
behaviour-neutral and can stay or go.

**Left.** Hostname detection outside URLs/emails/host:port relies on a curated TLD list, chosen so code
(`gnoc_learn.py`, `logger.info`, `self.app`) is not mangled; a bare `name.app` or `name.dev` host in prose is kept
unless it appears in a URL, an email or host:port. No real-model end-to-end batch run was made (tests use a scripted
model in-process and a stand-in child for the pool).

**Release note.** gnoc can now export what it has learned from: `gnoc export trajectories --format sharegpt|openai`
turns the logged tool turns into fine-tuning data, validated line by line and redacted by default (secrets, your home
folder and user name, IP addresses and hostnames outside your allowlist), and `gnoc export batch` runs a file of
prompts headless with a bounded pool, a time and step limit per prompt, and every action that needs your approval held
instead of run. Development: GreyNOC (Brad), with Claude (Anthropic) as a development contributor.
