# Skills

A skill is a saved procedure. Lessons (`/lessons`) are one sentence each and ride every turn; a skill is a
whole procedure and is read only when a request needs it.

## Where they live

| Place | Loads |
|---|---|
| `~/.gnoc/skills/<name>/` (or `$GNOC_HOME/skills/`) | always |
| `<repo>/.gnoc/skills/<name>/` | only after `/skills trust` in that repo, while every file under `.gnoc/skills/` is unchanged |

A folder holds `SKILL.md` and anything else you want next to it (`scripts/`, `references/`). The folder name and
the `name:` field must match: lowercase letters, digits and dashes, up to 48 characters.

## SKILL.md

```
---
name: release-notes
description: Write the release notes from the pull requests merged since the last tag
triggers: [release notes, changelog]
---
1. ...
```

- `description`: one line, up to 200 characters. This and the name are what the model sees in its instructions.
- `triggers`: phrases (up to 12, 60 characters each). They are matched as whole words against the request.
  When there are more skills than fit (12 names or 1800 characters), skills whose triggers match the request are
  listed first. When they all fit, the list is in name order and the same on every turn, so the start of each
  request does not change and the model server does not re-read the conversation.
- Triggers may also be written as `triggers: a, b` or as indented `- a` lines.

A skill whose name, description or triggers trip the injection scanner (text aimed at an AI, invisible
characters) is not listed, and `/skills` says why.

## How the model uses them

- `load_skill(name)` returns the body inside a `<<SKILL name - scan: ...>>` fence. A body that reads like an
  injected instruction (possible in a hand-edited or repo skill) is shown as untrusted data instead, with the
  signs named, and the model is told not to follow it.
- `load_skill(name, file="references/x.md")` reads one of the skill's own files, fenced as data. Only files that
  are part of that skill's folder can be read this way. Scripts run through `bash` like any other command, with
  the usual approval.
- A skill grants no permission. Every action it describes asks as usual.

## Proposals

`propose_skill(name, description, body, triggers, why)` writes only to `~/.gnoc/skills/.pending/`. It is refused:

- in a turn that read web, email, chat or MCP content, including content a helper bot read for it;
- when it copies a run of 24 or more characters from a response read in that turn;
- when the text trips the lesson book's poisoning check or the injection scanner, or holds invisible characters;
- when it contains the value of a known secret.

A newer proposal for the same name replaces the older one; at most 20 wait at once.

`/skills review` shows each proposal as a unified diff against your current `SKILL.md` and asks you to type `yes`
(anything else keeps it waiting; `discard` drops it). The proposal is checked again before it is written, and
only the exact record you were shown is written. Approving an edit replaces `SKILL.md` and keeps the other files.

The end of a long turn (8 or more tool calls, not interrupted, last test run passing, no untested edit, no
outside text read, not a hunt) prints a one-line suggestion. A waiting proposal is always named there.

## Who can do what

- `/skills review`, `/skills rm` and `/skills trust` run only from a line typed at the prompt (the same check as
  `/file`); text the model, a tool or a goal loop produces is refused.
- `write_file`, `edit_file` and `apply_patch` are refused under any `.gnoc/skills/` and on
  `~/.gnoc/trusted-skills.json`.
- `/skills rm` deletes only your own skills; a repo's skill is the repo's file.
- A symlink anywhere in a skills folder, or a file over 256 KB, stops that folder from loading or being trusted.

## Not covered

A shell command the user approves (or one run under `/auto` or skip-permissions) can still write into
`~/.gnoc/skills/`, just as it can write `~/.gnoc/hooks.json`. Proposals carry only `SKILL.md`; scripts and
references are added by hand.
