# gnoc chat plugins

A plugin is Python code that gnoc runs inside the chat process around its actions and its model calls. Shell
hooks (`~/.gnoc/hooks.json`, `/hooks`) are unchanged and keep working next to plugins. Code:
`scripts/gnoc_plugins.py`. Tests: `scripts/test_gnoc_phase8_plugins.py`.

## Where plugins live and how they are turned on

- `~/.gnoc/plugins/<name>.py`, or `~/.gnoc/plugins/<name>/plugin.py` for a plugin with several files. `GNOC_HOME`
  moves `~/.gnoc`. A name is lower-case letters, digits, `-` and `_`.
- Never from a repo or the current folder. The file is compiled from the bytes that were hashed and runs as the
  module `gnoc_plugin_<name>`. Nothing is added to `sys.path`, so a plugin called `json` does not replace the
  standard `json` module.
- Refused: a file or folder that is group- or world-writable or owned by another user (checked for `~/.gnoc`,
  `~/.gnoc/plugins` and every file of the plugin), and a symlink that leads out of `~/.gnoc/plugins`.
- `/plugins` lists every plugin with its state: `enabled`, `disabled`, `changed`, `refused`, `error` or `missing`.
- `/plugins enable <name>` records the sha256 of every file of the plugin in `~/.gnoc/plugins/enabled.json` and
  loads it. `/plugins disable <name>` removes it. Both run only from a line typed at the prompt (the same check
  as `/file`). If any file of an enabled plugin changes, the plugin stops loading until it is enabled again.
- The agent cannot install or enable a plugin: `write_file`, `edit_file` and `apply_patch` into
  `~/.gnoc/plugins` are refused, and so is a `bash` or `bg` command that names that folder and is not a plain
  read (`ls`, `cat`, `sha256sum` ...). The shell check is pattern based, a seat belt: a shell command you
  approve could still write the folder and `enabled.json` (as it could edit `~/.bashrc`). What the sha256 pin
  guarantees is narrower: a plugin file that appears there is not run unless `enabled.json` names its exact
  hash, and an enabled plugin whose files change stops.

## The API

```python
def register(api):
    api.on("pre_tool", guard)                    # any number of handlers per event
    api.tool("word_count", count, "Count the words in a text",
             {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]})
    api.command("hello", lambda rest: f"hello {rest}", "say hello")
    api.log("loaded")                            # a line in ~/.gnoc/plugins.log

def guard(ev):
    if ev["tool"] == "bash" and "terraform apply" in ev["args"].get("command", ""):
        return {"block": "terraform apply is typed by hand"}
    return None

def count(args):
    return str(len(args.get("text", "").split()))
```

A handler receives a copy of the event (changing it in place changes nothing) and returns:

| return | meaning |
|---|---|
| `None` | pass |
| `{"block": "reason"}` | block (see the table below for what that means per event) |
| `{"rewrite": {...}}` | replace the named fields |

| event | event fields | rewrite fields | block means |
|---|---|---|---|
| `pre_tool` | `tool`, `args` | `tool`, `args` | the call does not run; the model reads the reason |
| `post_tool` | `tool`, `args`, `result` | `result` | the result is withheld |
| `pre_llm` | `model`, `host`, `messages` | `messages` | the model call is not sent |
| `post_llm` | `model`, `host`, `content`, `tool_calls` | `content` | the answer is withheld and its tool calls dropped |
| `approval_request` | `tool`, `args`, `required` | (none) `{"require": true}` adds an approval | the call is refused |
| `approval_response` | `tool`, `args`, `answer` | (none: observe only) | (none) |
| `session_start`, `session_end` | `sid` | (none: observe only) | (none) |

Handlers run in plugin name order. For `pre_tool` the rewrites chain: the next plugin sees the rewritten call.

A plugin tool is called with one dict of arguments and returns text. A plugin command is called with the text
after the command name and returns the text to show; it is shown to you and never sent to the model.

## What the core enforces

- **No loosening.** A `pre_tool` rewrite is planned again from the start: every refusal, your `/permissions deny`
  rules, and the tool's own gates (the shell deny list, the scope gate, the write guards). Approval is asked if
  the original call OR the rewritten call needs it. `rm -rf build` rewritten into `ls` still asks, and you are
  asked about what will run (`ls`). Such a rewrite is logged as rejected.
- **Only you approve.** `approval_request` can add a requirement or refuse the call. An answer such as
  `{"approve": true}`, `{"require": false}` or `{"skip": true}` is ignored and logged. Whatever
  `approval_response` returns is ignored: a no stays a no.
- **Secrets and privacy.** `pre_llm` runs before the secret redaction and the `/privacy` switch, so a message a
  plugin adds or changes is scrubbed and refused like any other. A `pre_llm` block is not treated as a model
  failure, so gnoc does not resend the call to another model.
- **Model output.** `post_llm` changes the text kept in the conversation (words already streamed to the screen
  stay there). The model's tool calls cannot be rewritten; they go through every gate like any other call.
- **No shadowing.** A plugin tool named like an existing tool, or a plugin command named like a built-in slash
  command, is not registered; `/plugins` says so.
- **Plugin tools ask every time**, auto mode and skip-perms included, until you save `/permissions allow <tool>`.
  A plugin that names a tool after a built-in cannot make that built-in allowable this way.

## Failures

Each handler has a time budget: `GNOC_PLUGIN_TIMEOUT` seconds, default 5 (10 for loading a plugin, 30 for a
plugin command).

| event | a handler that raises, times out or returns something malformed |
|---|---|
| `pre_tool`, `pre_llm`, `approval_request` | fails CLOSED: the action is blocked with a message naming the plugin |
| `post_tool`, `post_llm`, `approval_response`, `session_*` | fails OPEN: the event goes on unchanged |

Every failure, every ignored approval attempt and every rejected loosening is written to `~/.gnoc/plugins.log`
(secrets scrubbed). Python cannot stop a thread, so a handler that times out keeps running in the background;
its answer is dropped. An event raised from inside plugin code does not run the handlers again.

## Limits

- Plugins are your own code and run with your rights. The checks above stop a plugin from loosening gnoc's
  gates; they do not sandbox the plugin itself (it can open files or sockets like any Python program).
- Only the entry file's bytes are executed from the hashed read. Other files of a plugin are hashed at load, but
  a plugin that reads them later reads them from disk.
- Plugin tools are registered when the chat starts and after `/plugins enable|disable`. A plugin enabled from
  another open chat starts handling events here at once; its tools appear here at the next start.
