# Credits

Development: GreyNOC (Brad), with Claude (Anthropic) as a development contributor.

Claude's contributions are AI-assisted development work reviewed and shipped by GreyNOC. This file records who
worked on what; it is not an endorsement of gnoc chat by Anthropic.

## Phases Claude worked on

- Phase −1: synced the tree to the signed, verified 2026.11.26 release; fixed the package's VERSION file;
  added the /file typed-only regression tests.
- Phase 0: gap audit against Hermes Agent, baseline diagnosis, the provenance workspace-root fix, and the
  public build's references to files it does not ship.
- Phase 1 (`phase-1/providers`): provider adapter seam, native Anthropic Messages and Gemini wires with streaming, thinking and prompt caching, and real token usage billed to the economy (fixing a chars/4 billing bug).
- Phase 2 (`phase-2/compaction`): archive-first compaction lineage, a validated model-written summary stage, and session search that reaches archived originals.
- Phase 3 (`phase-3/skills`): skills (procedural memory) with progressive disclosure, repo trust, and user-approved proposals.
- Phase 4 (`phase-4/subagents`): concurrent delegated children through one bounded pool, with per-child budgets, structured summaries and escalation refusals.
- Phase 5 (`phase-5/gateway`): messaging gateway core with Telegram, Slack, Signal and email adapters, in-chat owner-only approvals, and Discord on the shared core.
- Phase 6 (`phase-6/scheduler`): user-typed scheduled tasks on systemd timers, cron or Termux crond, with held actions reported and never run.
- Phase 7 (`phase-7/sandbox`): local, docker and ssh execution backends behind the same gates.
- Phase 8 (`phase-8/plugins`): in-process Python plugins with lifecycle events that can tighten but never loosen approvals.
- Phase 9 (`phase-9/termux`): native Termux install, doctor, setup and a reduced defender.
- Phase 10 (`phase-10/export`): redacted trajectory export (ShareGPT and OpenAI formats) and a headless batch runner.
- Phase 11 (`repo-quality`): public repo intake for `/repo` and `--repo` (shallow cached clone, credential
  URL refusal, origin-checked reuse), and a repo map that cannot read through a symlink out of the repo,
  cannot be taken down by one generated file, and no longer calls a timed-out search "not found".

Design ideas for the Hermes-parity work were taken from the documentation and source of Nous Research's Hermes
Agent (MIT). No Hermes code was copied.
