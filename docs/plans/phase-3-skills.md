# Phase 3: skills (procedural memory)

## Plan

- New stdlib module `scripts/gnoc_skills.py`: SKILL.md parsing (name, description, triggers), the user store
  `~/.gnoc/skills/` and the repo store `<repo>/.gnoc/skills/`, a whole-tree trust model copied from repo hooks
  (sha256 over every file, symlinks refused, one read hashed and parsed), trigger ranking, the pending queue.
- Progressive disclosure: only names and descriptions (scanned, capped by count and characters, trigger matches
  first) go into the general and code system prompts; `load_skill(name)` returns the body fenced with its scan.
- `propose_skill` writes only to `~/.gnoc/skills/.pending/`; it is refused in a turn that read web, email, chat or
  MCP text, when it copies text read from a response, or when the text trips the lesson poisoning and injection
  checks or carries a secret. `write_file` / `edit_file` / `apply_patch` are refused under `.gnoc/skills/`.
- `/skills`, `/skills show <name>`, `/skills review` (unified diff, typed `yes`), `/skills rm <name>`,
  `/skills trust|untrust`; review, rm and trust run only from a line the user typed (the `/file` identity check).
- A one-line end-of-turn hint after a long clean turn (>= 8 tool calls, not interrupted, no failing test, no
  untested edit, no outside text, not hunting), or when a proposal is waiting. It never blocks.

## What was built

- `scripts/gnoc_skills.py` (stdlib only): parsing, catalog, repo trust over the whole `.gnoc/skills` tree,
  trigger scoring, the prompt block, `load`, `propose`, the pending queue, `approve` (writes only the record the
  user was shown, rescanned), `remove`, the end-of-turn `hint`, and the `/skills` command body.
- `scripts/gnoc_tools/skills.py`: `t_load_skill`, `t_propose_skill` (reads the turn's `_tainted` and
  `_untrusted_text`, which already include what helper bots read).
- Wiring: `load_skill` / `propose_skill` in `TOOLS` and `CODE_TOOLS` (general turns get them, hunt turns do not);
  `load_skill` pinned against the tool budget when a skill is installed; `_skills_block` in the general and code
  system prompts (not hunt, not small talk); `/skills` in `commands.py` with the `/file` identity check;
  `/skills` in the help; `_GNOC_SKILLS` write refusal in `gnoc_core/paths.py`; the hint in `gnoc_core/agent.py`.
- Prompt stability: when every skill fits the cap the list is in name order and identical on every turn (the
  2026-11-25 head-of-request rule); only an over-cap catalog is ranked by trigger matches.
- Tests: `scripts/test_gnoc_phase3_skills.py`, 52 tests.

## Security impact

New text reaches the prompt (names and descriptions) and tool results (bodies). Both pass the existing injection
scanner; listed text with any sign is dropped, a body with attack signs is fenced as untrusted data. Repo skills
need a typed `/skills trust` and stop on any byte change, added file or symlink. Writes happen only from a typed
`/skills review` + `yes`; the model's file tools are refused under `.gnoc/skills/`. Residual: an approved or
auto-run shell command can still write `~/.gnoc/skills/` (the same exposure `~/.gnoc/hooks.json` has today).

## Rollback

Revert the feature commit. Nothing else depends on it; `~/.gnoc/skills/` and `~/.gnoc/trusted-skills.json` are
left on disk and are ignored by the older code.

## What is left

- Proposals carry `SKILL.md` only; scripts and references are added by hand.
- The injection scanner's `tool-call` pattern refuses a body that says "use the bash tool"; a proposal must
  describe commands, not tools. Loosening that would weaken the shared scanner, so it was left as is.
- Hunt turns neither list nor offer skills.

## Release note

gnoc now keeps skills: saved procedures in `~/.gnoc/skills/<name>/SKILL.md`, listed to the model by name and
description and read in full only when a task needs one. After a long task that worked, gnoc can propose a new
skill or an edit; `/skills review` shows the diff and nothing is saved until you type yes. Proposals made after
reading a web page, an email or a chat message are refused, as are ones that read like injected instructions or
contain a secret. A repo's `.gnoc/skills/` loads only after `/skills trust` and stops loading when it changes;
your own skill of the same name always wins. Development: GreyNOC (Brad), with Claude (Anthropic) as a
development contributor.
