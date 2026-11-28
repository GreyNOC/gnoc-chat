"""Reading the operator's message and the model's answer: questions, small talk, work and plan requests, promises not kept, tool calls written as text."""
import re
from .runtime import bind


# A tool call the model WROTE instead of MAKING arrives in two shapes. The fenced one was already
# handled; the bare <tool_call> tag is the chat template's own wrapper leaking into the answer, and it
# was invisible here. Measured 2026-10-25: GreyNOC said "yes" to applying a fix and the whole reply was
# <tool_call>{"name": "defend", "arguments": {"action":"services"}}</tool_call> printed as text. Nothing
# ran, nothing was said, and the turn ended on raw JSON.
_JSON_FENCE = re.compile(r"```(?:json)?\s*\n(\{.*?\})\s*\n```|<tool_call>\s*(\{.*?\})\s*</tool_call>", re.S)


# Third shape (reels driver 2026-10-26): the 9B fallback wrote its call in the Hermes XML form,
# <tool_call><function=bash><parameter=command>gnoc video clip ...</parameter></function></tool_call>, as plain
# text; nothing ran and the turn ended. Parsed here into the same (tool, args) pairs.
_XML_CALL = re.compile(r"<function=([A-Za-z_][A-Za-z0-9_]*)>(.*?)</function>", re.S)


_XML_PARAM = re.compile(r"<parameter=([A-Za-z_][A-Za-z0-9_]*)>\s*(.*?)\s*</parameter>", re.S)


_FREE_TEXT_ARGS = {"command", "content", "new", "old", "text", "brief", "patch", "code", "body", "data", "query",
                   "message", "prompt", "args", "request"}


_INTENT = re.compile(r"\b(?:call|use|run|invoke|start with|make|using|with)\b", re.I)


def stalled_call(reasoning, tools):
    """The ONE call a model named at the end of its reasoning but never made, as a tool_call dict, or None.

    The Qwen3.5 lead ends its reasoning with "Let me call defend with action=exposure.</think>" and stops: no call,
    no answer, about half the time with thinking on or off (measured 2026-10-24, 5/12 calls). Asking again or
    prefilling the reasoning recovered 0/4 and 2/4. Only its LAST two sentences count, the tool must be one this
    turn offers, named next to an intent verb, every argument must be a key=value / key: value for a property that
    tool declares (enums respected), and the tool's own required-argument check must pass. The call then goes
    through run_tools like any other, so approval and argument hardening still apply."""
    (
        TOOLS, _DEFEND_INFERABLE, _FREE_TEXT_ARGS, _INTENT, _PRECHECK, re,
    ) = bind(
        "TOOLS", "_DEFEND_INFERABLE", "_FREE_TEXT_ARGS", "_INTENT", "_PRECHECK", "re",
    )
    names = [((t.get("function") or {}).get("name")) for t in tools or []]
    names = [n for n in names if n in TOOLS]
    if not reasoning or not names:
        return None
    sents = [x for x in re.split(r"(?<=[.!?])\s+|\n+", reasoning.replace("</think>", "").strip()) if x.strip()]
    tail = " ".join(sents[-2:])
    hits = [(m.start(), m.group(1)) for m in re.finditer(r"\b(" + "|".join(map(re.escape, names)) + r")\b", tail)]
    hits = [(i, n) for i, n in hits if _INTENT.search(tail[max(0, i - 40):i + len(n) + 25])]
    if not hits:
        return None
    at, name = hits[-1]
    props = ((TOOLS[name][1].get("function") or {}).get("parameters") or {}).get("properties") or {}
    args = {}
    for m in re.finditer(r"\b(\w+)\s*[=:]\s*(?:\"([^\"]*)\"|'([^']*)'|`([^`]*)`|([\w./:,@-]+))", tail[at:]):
        k = m.group(1)
        v = next(g for g in m.groups()[1:] if g is not None)
        if k in props and k not in args:
            if m.group(5) is not None:
                v = v.rstrip(".,")
                if k in _FREE_TEXT_ARGS:   # "command: ls -la" unquoted read as "ls": never run a guess
                    return None
            enum = props[k].get("enum")
            if enum and v not in enum:
                return None
            args[k] = v
    if name == "defend" and "action" not in args:
        # "Let me call the defend tool to check if auto defense is currently running." names the tool and no
        # action, and defend needs one: the turn died empty three times in a row on exactly this (2026-11-20
        # defender drive). Take the LAST look-only action word the reasoning used ("the status can be checked").
        # Only look-only actions are inferred; an acting one (answer, respond, undo, enforce) is never guessed.
        wide = " ".join(sents[-4:])
        best = None
        for act in _DEFEND_INFERABLE:
            for mm in re.finditer(r"\b" + act + r"\b", wide, re.I):
                if best is None or mm.start() > best[0]:
                    best = (mm.start(), act)
        if best:
            args["action"] = best[1]
    if name in _PRECHECK and _PRECHECK[name](args):
        return None
    return {"id": f"call_named_{abs(hash(tail)) % 10**8}", "function": {"name": name, "arguments": args}}


# defend actions that only look, and so may be inferred from a stalled lead's own words (see stalled_call)
_DEFEND_INFERABLE = ("status", "sweep", "journal", "alerts", "triage", "exposure", "processes", "connections",
                     "logins", "services", "persistence", "firewall", "settings", "audit", "onion", "vulnwatch")


def named_tool(reasoning, tools):
    """The tool a stalled lead's last sentences say it will call, even when no call can be built from them."""
    names = [((t.get("function") or {}).get("name")) for t in tools or []]
    if not reasoning or not names:
        return None
    tail = " ".join([x for x in re.split(r"(?<=[.!?])\s+|\n+", str(reasoning).replace("</think>", "").strip())
                     if x.strip()][-2:])
    hits = [m.group(1) for m in re.finditer(r"\b(" + "|".join(map(re.escape, [n for n in names if n])) + r")\b", tail)]
    return hits[-1] if hits else None


_PROMISE = re.compile(r"^(?:let me\b|i'?ll\b|i will\b|now (?:i'?ll|let me|running|applying|checking|fixing|"
                      r"creating|writing|updating|testing)\b|(?:applying|running|checking|fixing|starting|"
                      r"creating|writing|updating|testing)\b.*\bnow\b)", re.I)


# A last line that is only an action HEADING with nothing under it: "## Executing Actions", "**Applying the
# fixes**", "Next steps:". The answer stopped where the actions were to begin (GreyNOC 2026-11-19, `please defend
# this machine`: "Based on the tool outputs, here's what I found and what I'll execute: ... ▍Executing Actions"
# and the turn ended, nothing executed).
_ACTION_HEADING = re.compile(r"^(?:(?:now\s+)?(?:executing|applying|running|implementing|carrying\s+out|taking|"
                             r"fixing|hardening|remediating|proceeding|performing|starting|making)\b.{0,60}|"
                             r"(?:next\s+steps?|actions?(?:\s+(?:to\s+take|taken|now))?|execution|remediation|"
                             r"(?:the\s+)?plan(?:\s+of\s+action)?|what\s+i(?:'?ll|\s+will)\s+(?:do|execute|run|change)"
                             r"(?:\s+now)?)\s*:?)$", re.I)
# "here's what I'll execute:" / "I'll now apply ..." in the closing lines, followed only by headings, a table or a
# list restating findings: still an announcement with nothing done after it
_ANNOUNCE = re.compile(r"\b(?:what\s+i(?:'?ll|\s+will)\s+(?:execute|run|do|apply|change|fix)|"
                       r"i(?:'?ll|\s+will)\s+(?:now\s+)?(?:execute|apply|run|carry\s+out|proceed|implement)|"
                       r"(?:executing|applying)\s+(?:these|the|them|now))\b", re.I)


_DEFERRED = re.compile(r"\b(?:when|once|after|if)\s+you\b|\blet me know\b|\bsay the word\b|\bon your (?:go|say)\b|"
                       r"\bwhenever you\b|\bwould you like\b|\bif you'?d like\b", re.I)


def promised_action(text):
    """The action a model ANNOUNCED as the last thing it said and then never took, or None.

    Measured 2026-10-25 on the real lead, three times in two sessions: "Applying the Gatewayco Admin API fix
    now:" and "Now running tests on the changed file:" were each the FINAL line of an answer, with no
    tool call after them. The turn ended there. To the user that reads as a hang - the bot said it was
    doing the thing and then sat silent - and the thing was never done.

    Only the last non-empty line counts, and a question is never a promise: "Want me to apply the fix?"
    is the model correctly asking, and must not be pushed.
    """
    (
        _ACTION_HEADING, _ANNOUNCE, _DEFERRED, _PROMISE, re,
    ) = bind(
        "_ACTION_HEADING", "_ANNOUNCE", "_DEFERRED", "_PROMISE", "re",
    )
    lines = [ln.strip() for ln in str(text or "").splitlines() if ln.strip()]
    if not lines:
        return None
    # A shell command TYPED as the last thing, under "Let me check ...": a ```bash block is not a tool call, and
    # nothing ran (GreyNOC 2026-11-19: "Let me check the RESCUE-BOARD.md file ..." + ```bash cat ...``` and the
    # turn ended). Only a shell-ish fence counts; a Python or JSON example under "I'll show you" does not.
    if lines[-1].startswith("```") and len(lines) >= 3:
        opens = [i for i in range(len(lines) - 1) if lines[i].startswith("```")]
        if opens and re.match(r"^```\s*(?:bash|sh|shell|zsh|console|terminal)?\s*$", lines[opens[-1]], re.I):
            before = [ln.lstrip("*_# -▍>").strip() for ln in lines[:opens[-1]]][-2:]
            for ln in reversed(before):
                if ln and not ln.endswith("?") and not _DEFERRED.search(ln) and re.match(
                        r"^(?:let me|i'?ll|i will|now (?:i'?ll|let me)|running|checking|next,? i'?ll)\b", ln, re.I):
                    return ln
    raw_last = lines[-1]
    last = raw_last.lstrip("*_# -▍>").rstrip("*_ ").strip()
    if not last or last.endswith("?") or _DEFERRED.search(last):
        return None   # "I will do it when you say go" is waiting for GreyNOC, not stalling
    if len(last) <= 80 and _ACTION_HEADING.match(last) and (
            raw_last.startswith(("#", "**", "▍", "__")) or last.endswith(":") or len(last.split()) <= 4):
        # an action heading as the very last thing: the section it opened is empty
        if not any(_DEFERRED.search(ln) or ln.rstrip("*_ ").endswith("?") for ln in lines[-4:-1]):
            return last
    if len(last) <= 200 and _PROMISE.search(last):
        # IMMINENT, not merely intended: it ends on a colon (the thing was about to follow) or says "now".
        if last.endswith(":") or re.search(r"\bnow\b", last, re.I):
            return last
    # The same, as the last SENTENCE of the last line, and "Let me <do it>." with a full stop. Three turns in one
    # day ended there with nothing after it (2026-11-21 drives): "The typecheck tool is available. Let me run it
    # on the inventory files:", "Let me create the new functions and update the existing ones to use them.",
    # "The HTTP server on port 8765 is not running yet. Let me start it properly using the bg tool."
    sent = re.split(r"(?<=[.!?])\s+", last)[-1].strip()
    if sent and len(sent) <= 200 and not sent.endswith("?") and not _DEFERRED.search(sent):
        if sent is not last and _PROMISE.search(sent) and (sent.endswith(":") or re.search(r"\bnow\b", sent, re.I)):
            return sent
        if re.match(r"^(?:now,?\s+|next,?\s+|so\s+)?let me\s+(?:first\s+|now\s+|quickly\s+|just\s+|go\s+ahead\s+and\s+)?"
                    r"(?:run|start|create|check|fix|apply|update|write|test|install|read|look|implement|add|try|"
                    r"verify|execute|make|fetch|open|search|rename|edit|extract|refactor|build|restart|stop|"
                    r"commit|delete|remove|move|set|call|use|do)\b", sent, re.I):
            return sent
    # an announcement a few lines up, with only headings / table rows / bullets restating findings after it
    tail = lines[-12:]
    for i, ln in enumerate(tail):
        if _ANNOUNCE.search(ln) and not _DEFERRED.search(ln) and not ln.rstrip("*_ ").endswith("?"):
            after = tail[i + 1:]
            if after and all(a.startswith(("#", "|", "│", "┼", "-", "*", "•", "▍")) or a[:2].rstrip(".)").isdigit()
                             for a in after) and not any(a.rstrip("*_ ").endswith("?") for a in after):
                return ln.lstrip("*_# -▍>").strip()
    return None


TEXT_CALL_NUDGES = 3  # per turn; see the consumer in _turn


def text_tool_calls(text):
    """Tool calls the model WROTE instead of MAKING: [(tool, args)] for each fenced JSON object whose keys
    match one tool's arguments. An explicit {"name": ..., "arguments": ...} block counts too.

    Matching is by argument names, because that is what the model reliably reproduces: an object with
    new/old/path is edit_file, one with action/text/receipt is goal. At least two keys must match, and
    the best-matching tool wins, so a stray config snippet in an explanation is not mistaken for a call."""
    (
        TOOLS, _JSON_FENCE, _XML_CALL, _XML_PARAM, json,
    ) = bind(
        "TOOLS", "_JSON_FENCE", "_XML_CALL", "_XML_PARAM", "json",
    )
    found = []
    for groups in _JSON_FENCE.findall(text or ""):
        blob = next((g for g in (groups if isinstance(groups, tuple) else (groups,)) if g), "")
        try:
            obj = json.loads(blob)
        except ValueError:
            continue
        if not isinstance(obj, dict):
            continue
        if isinstance(obj.get("name"), str) and obj["name"] in TOOLS and isinstance(obj.get("arguments"), dict):
            found.append((obj["name"], obj["arguments"]))
            continue
        keys = set(obj)
        best, score = None, 0
        for name, spec in TOOLS.items():
            props = set(((spec[1].get("function") or {}).get("parameters") or {}).get("properties") or {})
            hit = len(keys & props)
            if hit >= 2 and hit / len(keys) >= 0.6 and hit > score:
                best, score = name, hit
        if best:
            found.append((best, obj))
    for name, body in _XML_CALL.findall(text or ""):
        if name in TOOLS:
            args = dict(_XML_PARAM.findall(body))
            if args:
                found.append((name, args))
    return found


REFUSAL = re.compile(r"^\W*(I(’|')?m sorry,? but I (can(’|')?t|cannot|won(’|')?t)|I can(’|')?t (help|assist) with|"
                     r"I cannot (help|assist|provide)|I(’|')?m unable to (help|assist)|Sorry, (but )?I can(’|')?t)", re.I)


# NOTE (2026-11-01): a second _QUESTION rebinds this name ~60 lines below, before either is ever used, so
# THIS pattern was dead - every caller got the later one, which does NOT list why / how / explain /
# describe / tell me about / show me how. Removed rather than merged, so behaviour is unchanged: merging
# them would silently reclassify "explain the loop" and "how does X work" as questions instead of work.
_HOWTO = re.compile(r"(\byou(?:'ll| will)? (?:can|could|should|may|might|need to|want to)\b|\brun (?:the following|this|"
                    r"these|it)\b|\bon the host\b|\blet me know if\b|\bif you(?:'d| would)? (?:like|want)\b|"
                    r"^\s*```(?:bash|sh|shell|console|zsh)\s*$|\byour terminal\b)", re.I | re.M)


_WORK_HINT = re.compile(r"(https?://|/|\.\w{2,4}\b|\b(hunt|probe|find|check|review|fix|write|build|run|test|"
                        r"analy[sz]e|explain|compare)\b)", re.I)


# "how does X normalise paths" and "why did the lane die" are analysis requests, and the bare words how/why were
# the only reason they counted as work. Those same two words also made "how are you today?" a work order: it
# failed every classifier, so a greeting ran a full turn - hunt prompt, 87 tool schemas, a worker on the other
# GPU, and the answer held until that worker finished (117 s, 2026-11-17 00:18Z). The analysis shapes are matched
# explicitly now, and a social "how are you" is not one of them.
_ANALYSIS_HINT = re.compile(r"\bwhy\b|\bhow (?:do|does|did|can|could|should|would|to|come)\b", re.I)


def hints_work(text):
    """True when the message points at something to look up, run or analyse, not merely a question shape."""
    (
        _ANALYSIS_HINT, _WORK_HINT,
    ) = bind(
        "_ANALYSIS_HINT", "_WORK_HINT",
    )
    t = text or ""
    return bool(_WORK_HINT.search(t) or _ANALYSIS_HINT.search(t))


# Nouns that name the work itself. "how are you doing on the gatewayco report?" opens like a greeting and is still
# about the report, so the conversation classifier checks the rest of the message against these too.
_WORK_NOUN = re.compile(r"\b(report|reports|target|targets|program|programs|lane|lanes|scope|finding|findings|"
                        r"lead|leads|draft|drafts)\b", re.I)


# A turn that CONCLUDES "still a lead / not proven" without firing a probe to close it. The hunt loop
# counts these across turns: thin-turn (tools<2 or >=15) and NEXT-repeat both miss the 3-5-tool, 0-probe
# turn that just re-analyses one unprovable edge (program-0 2026-10-24: ~10 such turns before the budget
# drained). This is the signal the no-progress breaker keys on.
_NOPROVE = re.compile(r"\b(not (yet )?(a finding|proven)|still (a|just a) lead|capability gate (is )?not"
                      r"(?: yet)? clear|cannot (?:be )?prove|no (?:captured )?terminal|evidence does not"
                      r" contain)\b", re.I)


# Widened 2026-10-26 for web-app work. A .html / .css / .vue / template edit used to be invisible here, so
# the verify nudge never fired on it, find_symbol never searched it, and code_review on a frontend
# directory collected nothing: the harness did not consider a rendered file to be code.
CODE_FILE = re.compile(r"\.(py|js|mjs|cjs|ts|tsx|jsx|go|rs|java|kt|rb|php|sh|c|h|cpp|cs|swift|"
                       r"html?|vue|svelte|astro|css|scss|sass|less|ejs|hbs|jinja2?|j2|twig|erb|sql)$")


# the harness's own source: an edit here is gated by `gnoc qaqc`, not an arbitrary repo's test command
HARNESS_FILE = re.compile(r"(^|/)(gnoc[_-][\w.-]+|test_gnoc_[\w.-]+)\.py$")


TEST_CMD = re.compile(r"\b(pytest|unittest|npm\s+(run\s+)?test|node\s+\S*test|go\s+test|cargo\s+test|make\s+test|"
                      r"python3?\s+\S*test\S*\.py|tsc|eslint|ruff|bash\s+-n|node\s+--check|py_compile)\b")


_SMALL_TALK = re.compile(r"^(hi|hiya|hello|hey|yo|sup|thanks?|thank you|thx|ty|ok|okay|k|cool|nice|great|good|"
                         r"good (morning|afternoon|evening|night)|morning|evening|bye|see you|later|lol|haha|"
                         r"yes|no|yep|nope|sure|fine|alright|roger|got it|understood)\b[\w\s,!.?]{0,12}$", re.I)


# A CONVERSATION is answered from what the chat already knows: no tools, no second model, no bot-event preamble.
# This is the turn GreyNOC talks to the bot with ("how are you today?"), so it cannot hinge on a greeting whitelist
# that never listed how-are-you. The pattern matches a social or self-referential opener; the REST of the message
# is then checked for work, so "how are you fixed for the gatewayco hunt?" stays a work turn.
_CONVERSATIONAL = re.compile(
    r"^(?:"
    r"how(?:'re|'r| are| r) (?:you|u|ya)\b|how(?:'s|s| is| are) (?:it|things|life|your day)\b|"
    r"how have you been\b|how do you feel\b|"
    r"what(?:'s| is) up\b|sup\b|you (?:good|ok|okay|there|awake|around)\b|"
    r"who are you\b|what are you\b|what can you do\b|"
    r"(?:good )?(?:morning|afternoon|evening)\b|hi(?:ya)?\b|hello\b|hey\b|yo\b|"
    r"thanks\b|thank you\b|thx\b|ty\b|nice\b|great\b|cool\b|ok(?:ay)?\b|got it\b|roger\b|understood\b|sure\b|"
    r"i(?:'m| am) (?:good|fine|well|ok|okay|tired|here)\b|same here\b|you too\b|how about you\b"
    r")", re.I)


# An order after a social opener: "ok, implement the plan", "sure, go ahead", "cool, continue", "okay, commit and
# push". None of these words were work hints, so the opener made the whole message small talk and the turn ran
# with NO tools - the harness's own plan panel suggests "go ahead, implement the plan" (QAQC 2026-11-19).
# A REQUEST after a social opener, whatever its nouns: "ok can you buffer the red team and assist and see if you can
# get into our DB's" opened with "ok", matched no work word, and ran as small talk with NO tools; the lead wrote
# site_redteam as text four times and the turn ended with nothing run (2026-11-27). The shape of asking is the
# signal, so the work-word lists do not have to anticipate every noun he will use.
_REQUEST = re.compile(r"\b(?:can|could|would|will) (?:you|u|we|ya)\b(?! (?:believe|imagine|tell)\b)|\bplease\b|"
                      r"\blet'?s\b|\bhelp me\b|\bi (?:want|need) (?:you|to)\b|\bsee if\b|\btry (?:to|and)\b|"
                      r"\bred ?team|\bpen ?test|\bdrill\b|\bdbs?\b|\bdb's\b|\bdatabases?\b|\bget into\b|"
                      r"\bbreak into\b|\bhack\b|\battack\b|\bscan\b", re.I)


_GO_ON = re.compile(r"\b(go\s+ahead|proceed|continue|carry\s+on|keep\s+going|implement|apply|commit|push|merge|"
                    r"deploy|ship|delete|remove|restart|start|stop|resume|retry|try\s+again|rerun|redo|undo|revert|"
                    r"do\s+(?:it|that|this|so)|install|update|upgrade|change|edit|add|create|make|set|switch|send|"
                    r"open|close|finish|next|approve|yes\s+do)\b", re.I)


def is_conversation(text):
    """A social or self-referential message: answer it, with NO tools and no second model.

    "how are you today?" failed every classifier, because the bare word how was a work hint, so a greeting ran a
    full turn: hunt prompt, 87 tool schemas, a worker on the other GPU, and the answer held back until that worker
    finished (117 s, 2026-11-17 00:18Z). The turn is decided by what the message IS, not by its word count.
    """
    (
        _GO_ON, _CONVERSATIONAL, _STATUS_Q, _WORK_NOUN, hints_work,
    ) = bind(
        "_GO_ON", "_CONVERSATIONAL", "_STATUS_Q", "_WORK_NOUN", "hints_work",
    )
    t = (text or "").rsplit("\n\n", 1)[-1].strip()
    if not t or not _CONVERSATIONAL.match(t):
        return False
    rest = _CONVERSATIONAL.sub(" ", t, count=1).strip(" ,.")   # the opener only: the rest must be free of work
    # "hey, what's the status?" is still a question to answer with a look, and "how are you doing on the gatewayco
    # report?" is still about the report: the opener does not swallow what follows it.
    return not hints_work(rest) and not _WORK_NOUN.search(rest) and not _STATUS_Q.match(rest) \
        and not _GO_ON.search(rest) and not _REQUEST.search(rest)


def is_small_talk(text):
    """A greeting or acknowledgement, nothing to act on: the turn runs with NO tools and no bot-event preamble.
    'hello' once came in with 8 bot events prepended and a fallback model answered it with `gnoc stop` and
    `gnoc resume` against the whole hunt fleet."""
    (
        _GO_ON, _SMALL_TALK, hints_work, is_conversation,
    ) = bind(
        "_GO_ON", "_SMALL_TALK", "hints_work", "is_conversation",
    )
    t = (text or "").rsplit("\n\n", 1)[-1].strip()
    if is_conversation(text):
        return True
    return bool(t) and len(t.split()) <= 4 and bool(_SMALL_TALK.match(t)) and not hints_work(t) \
        and not _GO_ON.search(t)


_STATUS_Q = re.compile(r"^(?:is|are|was|were|do|does|did|has|have|what(?:'s| is| are)?|how (?:many|much)|"
                       r"can you tell me|show me)\b", re.I)


def is_status_question(text):
    """A short yes/no or status question about the system's CURRENT state: 'is X on prod?', 'what's the
    STOP flag?', 'are the GPUs busy?'. It gets the small-talk treatment - no bot-event preamble, no deep
    worker, no ultra fan-out: an answer, not an expedition. 'how does X work', 'find ...', 'check ...'
    carry a work hint and stay full turns."""
    (
        _STATUS_Q, hints_work,
    ) = bind(
        "_STATUS_Q", "hints_work",
    )
    t = (text or "").rsplit("\n\n", 1)[-1].strip()
    if not t or not t.endswith("?"):
        return False
    if len(t) > 140 or len(t.split()) > 24:
        return False
    if hints_work(t):
        return False
    return bool(_STATUS_Q.match(t)) and not t.lower().startswith(("how does", "how do", "why ", "what does", "what do"))


_QUESTION = re.compile(r"^\s*(which|what|who|whom|whose|where|when|is|are|am|was|were|do|does|did|can|could|"
                       r"would|will|should|shall|have|has|had|may)\b", re.I)


# Inside a question these are not work orders: "is the hunt still running?", "should we hunt gatewayco?" and
# "how many leads do we have?" ask for an answer. "how does X work" and "why ..." stay work (analysis).
_QUESTION_ONLY = re.compile(r"\bhunt(?:s|ing)?\b|\bhow (?:many|much|long|often|old|far)\b", re.I)


# "did the hunt find anything?" / "have you fixed it?" ask about work already done: only a path or URL in them
# is still a work hint, the verb is not
_PAST_Q = re.compile(r"^\s*(did|was|were|has|have|had)\b", re.I)


_PATH_HINT = re.compile(r"(https?://|/|\.\w{2,4}\b)", re.I)


def _core_q(t):
    """The sentence after a lead-in or a condition said first: "offline. what is a negative control" is the question
    "what is a negative control" (read as no question at all, it grepped the home folder five times, batch 7)."""
    return _LEAD_IN.sub("", t, count=1).strip() or t


def is_direct_question(text):
    """A question with no work verb in it: the user wants an ANSWER, not a hunt.

    "which model am i speaking with?" is 6 words, which used to clear worth_both_gpus() and, at effort=ultra,
    auto-launch a 6-bot plan against the active program (2026-10-22). A question that asks for work
    ("how does X normalise paths", "find ...", "check ...") still carries a work hint and is not caught."""
    (
        _PAST_Q, _PATH_HINT, _QUESTION, _QUESTION_ONLY, hints_work, is_conversation,
    ) = bind(
        "_PAST_Q", "_PATH_HINT", "_QUESTION", "_QUESTION_ONLY", "hints_work", "is_conversation",
    )
    t = _core_q((text or "").rsplit("\n\n", 1)[-1].strip())
    if not t:
        return False
    if is_conversation(text):
        return True   # "how are you today?" asks for an answer, whatever shape the sentence has
    asks = t.endswith("?") or bool(_QUESTION.match(t))
    body = _QUESTION_ONLY.sub(" ", t)
    hinted = bool(_PATH_HINT.search(body)) if _PAST_Q.match(t) else hints_work(body)
    return asks and not hinted


_RETARGET = re.compile(
    r"\b(pick|choose|select|switch|change|move|rotate|try|go|hunt|start|work)\b.{0,40}"
    r"\b(different|another|other|new|next|fresh)\b.{0,24}\b(program|target|programs|targets|one)\b"
    r"|\b(something|anything|somewhere)\s+else\b"
    r"|\bswitch\s+(over\s+)?to\s+\w"
    r"|\b(drop|leave|abandon|park|ditch|stop)\s+(this|the current|\w+)\b.{0,30}\b(pick|choose|hunt|try|move|next|another)\b"
    r"|\b(next|another|different|new)\s+(best\s+)?(program|target)\b"
    r"|\b(switch|change|rotate)\s+(the\s+)?(program|target)s?\b", re.I)


# "find another endpoint on THIS target" / "pick a new hypothesis for this program" are about the current one
_SAME_TARGET = re.compile(
    r"\b(this|the current|the same|same|our current)\s+(program|target|one)\b|\bon this\b"
    r"|\btarget\s+(header|host|url|param|parameter|endpoint|field|cookie|value|string)\b"
    r"|\b(different|another|other|new|next|fresh)\s+(hypothesis|hypotheses|endpoint|endpoints|vector|host|"
    r"subdomain|surface|path|route|approach|angle|idea|probe|lead|header|payload|vantage|url|param|parameter)\b",
    re.I)


def is_retarget_request(text):
    """The user asking to hunt something ELSE: "pick a different program", "switch to vandelay", "hunt something
    else", "drop globex and pick the next best one". The ultra pre-planner must not fan out on the current
    program for these (it did, 2026-10-22: six bots on globex for "pick a different program"); the lead
    handles them with pick_target / set_program. Work on THIS target ("find another endpoint on this
    target", "pick a new hypothesis") is not a retarget."""
    (
        _RETARGET, _SAME_TARGET,
    ) = bind(
        "_RETARGET", "_SAME_TARGET",
    )
    t = (text or "").rsplit("\n\n", 1)[-1].strip()
    if not t or not _RETARGET.search(t):
        return False
    return not _SAME_TARGET.search(t)


def worth_both_gpus(text):
    """/deep and /effort max put the worker GPU on every message; a greeting or a two-word reply is not worth
    waiting on a second model for. Real requests (a task, a path, a URL, 6+ words) still get both GPUs.
    A conversation or a direct question never does: it is answered, not worked."""
    (
        hints_work, is_conversation, is_direct_question,
    ) = bind(
        "hints_work", "is_conversation", "is_direct_question",
    )
    t = (text or "").rsplit("\n\n", 1)[-1].strip()
    if is_conversation(text) or is_direct_question(t):
        return False
    return len(t.split()) >= 6 or hints_work(t)


# GENERAL-KNOWLEDGE QUESTIONS (2026-11-16, GreyNOC: "figure out why gnoc chat cant just answer simple questions").
# "how do you think the pyramids were built?" matched _ANALYSIS_HINT ("how do"), so it read as a work order; at
# effort=ultra _ultra_plan split it into 6 bots that grepped the bug-bounty corpus, read the Manual and SPINE and
# fetched Wikipedia for 5m33s (850k tokens) and never answered. "why is the sky blue?" took the same path. A
# question with nothing in it that points at this machine, the repo, a program or the work is answered from what
# the model knows, with web_search / web_fetch only - no disk tools to wander with, no bots, no side worker.
_QUESTION_OPENER = re.compile(r"^\s*(how|why|what|who|whom|whose|which|where|when|is|are|am|was|were|do|does|did|"
                              r"can|could|would|will|should|shall|has|have|had|may|might)\b", re.I)


# Anything that ties the question to the session or the workspace keeps it a normal turn with its tools: a path,
# URL or file name, a code identifier, a work noun or verb, a system word, a program name, or a pronoun that
# refers back to the conversation ("why did it fail?", "what does that mean?").
_ANCHOR = re.compile(
    r"(https?://|[/\\`]|\.\w{2,4}\b|\w_\w|(?-i:\b[a-z]+[A-Z]\w*)|(?-i:\b[A-Z]{2,}\b)"
    r"|\b(gnoc|gpus?|models?|bots?|workers?|repo|repos|code|files?|scripts?|functions?|tools?|hooks?|harness|"
    r"session|commit|branch|bugs?|vuln\w*|endpoints?|hosts?|api|server|errors?|logs?|chat|prompt|burp|tokens?|"
    r"accounts?|payouts?|bount(?:y|ies)|hackerone|bugcrowd|intigriti|immunefi|yeswehack|h1|manual|spine|handoff|"
    r"memory|disk|machine|desktop|laptop|vps|parsers?|flags?|stop|loop|lanes?|gates?|config\w*|settings?|status|"
    r"state|queue|process(?:es)?|daemon|services?|ports?|proxy|ledgers?|database|db|index|cache|pipeline|station|"
    r"effort|steps?|fan[_ -]?out|delegate|mcp|ollama|vram|terminal|shell|command)\b"
    r"|\b(it|its|that|this|these|those|they|them|their|there|here|same|again|above|earlier|before|we|our|us|"
    r"my|mine|me|i|your|yours)\b"
    r"|\byou (?:did|do|found|find|just|changed|made|wrote|ran|said|mean|see|saw|get|got|use|used|have|are)\b)",
    re.I)


_PROGRAM_NAMES = []


def _program_names():
    """The program directory names under targets/, read once: 'is gatewayco paying?' is about the work."""
    (
        WS, _PROGRAM_NAMES, os,
    ) = bind(
        "WS", "_PROGRAM_NAMES", "os",
    )
    if not _PROGRAM_NAMES:
        try:
            _PROGRAM_NAMES.extend(sorted(
                (n for n in os.listdir(os.path.join(WS, "targets")) if os.path.isdir(os.path.join(WS, "targets", n))),
                key=len, reverse=True) or ["\0"])
        except OSError:
            _PROGRAM_NAMES.append("\0")
    return [n for n in _PROGRAM_NAMES if n != "\0"]


def is_question(text):
    """The user's own text is a question (it ends in ? or opens with a question word), whatever it asks about."""
    (
        _QUESTION_OPENER,
    ) = bind(
        "_QUESTION_OPENER",
    )
    t = _core_q((text or "").rsplit("\n\n", 1)[-1].strip())
    return bool(t) and (t.endswith("?") or bool(_QUESTION_OPENER.match(t)))


_ON_THIS_MACHINE = re.compile(r"\b(?:installed|running|up[- ]to[- ]date|outdated|enabled|disabled|listening|patched|"
                              r"allowed|permitted|turned (?:on|off)|switched (?:on|off)|"
                              r"configured|on (?:this|my) (?:machine|box|computer|pc|laptop|system|server|host)|"
                              r"on here|in here|here)\b", re.I)
# a request that asks for a CHANGE (so failing tests must be fixed before answering), as opposed to "run the tests"
_WANTS_CHANGE = re.compile(r"\b(?:fix|fixes|repair|resolve|implement|add|change|update|refactor|rename|write|create|"
                           r"remove|delete|make (?:it|them|this|that|the \w+|\w+) pass|get (?:it|them|\w+) (?:to )?(?:pass|green)|"
                           r"until (?:it|they|all|the tests?) pass)\b", re.I)
# HIS request is only to run something ("run the tests", "rerun the suite", "run pytest"): once it ran, the turn is
# done. Nothing about a numbered results list may send it back to work (2026-11-20 SWE drive: "run the tests" ended
# in an edit of report.py and a second review).
_JUST_RUN = re.compile(r"^\W*(?:(?:please|ok(?:ay)?|now|can you|could you|just)[\s,]+)*(?:re-?run|run|execute)\s+"
                       r"(?:the\s+|all\s+(?:the\s+)?|my\s+|our\s+)?(?:unit\s+|integration\s+|e2e\s+|whole\s+)?"
                       r"(?:tests?|test suite|suite|specs?|pytest|lint(?:ers?)?|type ?checks?|typecheck(?:er)?)\b"
                       r"(?![^.?!]*\b(?:fix|change|make|update|repair|edit|resolve|implement|add|remove)\b)"
                       r"[^\n]{0,40}$", re.I)
# Which failing tests are THIS task's. Asked to "fix the discount bug", the lead fixed it; the run still failed in
# test_remove_more_than_stock_raises, a bug already there, and the fail push sent it to fix remove() too
# (2026-11-20 SWE drive, w09). A failure is the task's when a name in it is a word of the request or of a function
# the turn edited, or when the request is about the tests at all ("fix the failing tests", even typed "failng tset").
_FAIL_LINE = re.compile(r"^(?:FAILED|ERROR)\s+\S*?::([\w\[\]-]+)|^not ok \d+ - (.+)$|^--- FAIL: (\w+)", re.M)
_ABOUT_TESTS = re.compile(r"\b(?:te?st\w*|tset\w*|fail\w*|suite|green|ci|pass(?:ing|es)?)\b", re.I)
_NAME_STOP = {"test", "tests", "that", "this", "with", "from", "into", "when", "then", "than", "more", "does",
              "should", "would", "could", "make", "have", "what", "were", "will", "your", "also", "only", "just",
              "them", "they", "raises", "returns", "works", "case"}


def _name_words(s):
    out = set()
    for w in re.findall(r"[A-Za-z][A-Za-z0-9]*", s or ""):
        for part in re.findall(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])", w):
            p = part.lower()
            if len(p) >= 4 and p not in _NAME_STOP:
                out.add(p)
    return out


def failing_tests(msgs):
    """The failing test names of the LAST test run in `msgs` (pytest, node --test, go test), at most 12."""
    for m in reversed(msgs or []):
        if m.get("role") != "tool":
            continue
        c = str(m.get("content") or "")
        if re.search(r"^\s*\d+/\d+ (?:test commands? )?passed|\b\d+ failed\b|^exit \d+", c, re.M):
            return [next(g for g in t if g) for t in _FAIL_LINE.findall(c)][:12]
    return []


def last_run_scope(msgs):
    """(files, name) of the LAST run_tests call in msgs: which test files it named (a tuple, as typed) and its
    name= filter (None when it ran every test in them). None when there was no run_tests call.

    A test that is not in the last run's failures has only PASSED if that run included it. After a run filtered
    to name='test_skus', "(gnoc: this turn also made 'test_discount_percent' ... pass)" was said of two tests
    that had not run at all (three-part drive 2026-11-21)."""
    import ast
    for m in reversed(msgs or []):
        if m.get("role") != "assistant":
            continue
        for c in reversed(m.get("tool_calls") or []):
            fn = c.get("function") or {}
            if fn.get("name") != "run_tests":
                continue
            a = fn.get("arguments") if isinstance(fn.get("arguments"), dict) else {}
            files = a.get("files")
            if isinstance(files, str) and files.strip().startswith("["):
                try:
                    files = ast.literal_eval(files)
                except (ValueError, SyntaxError):
                    files = [files]
            files = [files] if isinstance(files, str) else list(files or [])
            name = str(a.get("name") or "").strip()
            if name.lower() in ("all", "*", "any", "every", "everything", "none", "null"):
                name = ""
            return tuple(sorted(str(f).rstrip("/") for f in files)), (name or None)
    return None


def turn_tree(r):
    """A git object naming the TRACKED working tree as it is right now (`git stash create`, which changes nothing),
    or "HEAD" when the tree is clean; None outside a git repo. Taken when a turn starts, it is what "before this
    turn" means: the turn before may have fixed a test and not committed it."""
    import subprocess
    import gnoc_worktree
    try:
        pr = subprocess.run(["git", "-C", r, "stash", "create"], capture_output=True, text=True, timeout=20,
                            stdin=subprocess.DEVNULL, env=gnoc_worktree.git_env())
        if pr.returncode != 0:
            return None
        return pr.stdout.strip() or "HEAD"
    except (OSError, subprocess.SubprocessError):
        return None


def failing_on_head(r, msgs, ref="HEAD"):
    """The names of the tests that fail in the tree `ref` (the turn's starting tree, see turn_tree; HEAD when that
    is unknown), in the test files the turn ran last with run_tests: the same files run again in a throwaway copy
    (git archive), with the environment run_tests itself uses.
    None when that cannot be told (no such tree, no explicit test files, the runner would not start, a time-out).

    It was HEAD at first, and that was wrong: turn 9 fixed slugify and left it uncommitted, turn 10 broke it again,
    and because the test also fails at HEAD the lead was told "the failing tests were failing before this change;
    report them, not fix them" about a failure it had just caused (debug drive 2026-11-21).

    The rename drive of 2026-11-21: "rename apply_discount ..., keep the tests the way they were passing or
    failing". Two tests failed before and after; the lead said so; "its last test run FAILED, fix the code" then
    had it rewrite the discount maths and remove(). Whether a failure is the turn's is a fact git can answer."""
    import ast
    import os
    import shutil
    import subprocess
    import tempfile
    import gnoc_secrets
    import gnoc_worktree
    G = __import__("gnoc_agent")
    a = None
    for m in reversed(msgs or []):
        if m.get("role") != "assistant":
            continue
        for c in reversed(m.get("tool_calls") or []):
            fn = c.get("function") or {}
            if fn.get("name") == "run_tests":
                a = fn.get("arguments") if isinstance(fn.get("arguments"), dict) else {}
                break
        if a is not None:
            break
    if a is None:
        return None
    files = a.get("files")
    if isinstance(files, str) and files.strip().startswith("["):
        try:
            files = ast.literal_eval(files)
        except (ValueError, SyntaxError):
            return None
    if not isinstance(files, list) or not files or len(files) > 6:
        return None
    runs = []
    # a SOURCE file named to run_tests stands for the tests that cover it, here as in run_tests itself: the
    # baseline of `node --test src/slug.js` is "no test, exit 0", which made a failure that was there all along
    # look new, and the lead was pushed to fix a bug it had been told to leave (verification drive 2026-11-21)
    _testing = __import__("gnoc_core.testing", fromlist=["_TEST_NAME"])
    mapped = []
    for f in files:
        f = str(f)
        if os.path.isabs(f) or ".." in f.split("/"):
            return None
        in_test_dir = any(part in ("test", "tests", "__tests__", "spec", "specs") for part in f.split("/")[:-1])
        if not _testing._TEST_NAME.search(os.path.basename(f)) and not in_test_dir:
            cover = _testing.tests_for(r, [f])
            if not cover:
                return None
            mapped += [c for c in cover if c not in mapped]
        elif f not in mapped:
            mapped.append(f)
    for f in mapped:
        full = os.path.join(r, f)
        argv, _ = G.test_argv(r, full)
        if not argv:
            return None
        runs.append([f if x == full else x for x in argv])
    d = tempfile.mkdtemp(prefix="gnoc-head-")
    try:
        arch = subprocess.run(["git", "-C", r, "archive", str(ref or "HEAD")], capture_output=True, timeout=60,
                              env=gnoc_worktree.git_env())
        if arch.returncode != 0 or subprocess.run(["tar", "-x", "-C", d], input=arch.stdout, capture_output=True,
                                                  timeout=60).returncode != 0:
            return None
        names = set()
        for argv in runs:
            if not os.path.exists(os.path.join(d, argv[-1])) and not any(os.path.exists(os.path.join(d, x))
                                                                         for x in argv[1:]):
                continue   # the test file is new in this turn: nothing in it failed before
            pr = subprocess.run(argv, cwd=d, capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL,
                                env=gnoc_secrets.user_env({"PYTHONDONTWRITEBYTECODE": "1"}))
            out = (pr.stdout or "") + (pr.stderr or "")
            got = {next(g for g in t if g) for t in _FAIL_LINE.findall(out)}
            if pr.returncode != 0 and not got:
                return None   # it failed without naming a test (collection error, missing runner): no baseline
            names |= got
        return names
    except (OSError, subprocess.SubprocessError):
        return None
    finally:
        shutil.rmtree(d, ignore_errors=True)


def outside_task(names, own_text, msgs):
    """True when every failing test in `names` is about something the request did not name and the turn did not
    edit (then it was most likely failing before, and it is their to decide, not the lead's to fix)."""
    if not names or _ABOUT_TESTS.search(own_text or ""):
        return False
    asked = _name_words(own_text)
    for m in msgs or []:
        if m.get("role") != "assistant":
            continue
        for c in m.get("tool_calls") or []:
            fn = c.get("function") or {}
            if fn.get("name") not in ("edit_file", "write_file", "apply_patch"):
                continue
            a = fn.get("arguments") if isinstance(fn.get("arguments"), dict) else {}
            blob = " ".join(str(a.get(k) or "") for k in ("old", "new", "content", "patch", "edits"))
            for d in re.findall(r"\b(?:def|function|func|fn|class)\s+(\w+)", blob):
                asked |= _name_words(d)
    return all(not (_name_words(n) & asked) for n in names)


# a request about THIS repo's code, which must be answered from the code ("explain this repo", "what does this
# project do", "how is the code structured")
_ABOUT_THIS_CODE = re.compile(r"\b(?:this|the|my|our)\s+(?:repo|repository|project|codebase|code|app|module|package|"
                              r"library|test suite|tests)\b", re.I)
# a stalled lead's reasoning saying it must look at THIS machine ("I should read the test file first")
_LOCAL_INTENT = re.compile(r"\b(?:read|open|look at|check|inspect|run|list|grep|search|find|examine|view|cat)\s+"
                           r"(?:the|this|that|my|your|its|a|some|which|what|all|each|every)?\s*"
                           r"(?:\w+\s+){0,2}(?:file|files|test|tests|code|repo|directory|folder|config|log|logs|"
                           r"output|command|process|port|ports|service|package|packages|module|script|source)s?\b"
                           r"|\b(?:use|call|run)\s+(?:the\s+)?(?:bash|read_file|grep|list_dir|run_tests|defend|find_file)\b",
                           re.I)
# what a question in a code repo names when it is about THAT repo ("what would change in the tests")
CODE_NOUN = re.compile(r"\b(?:tests?|test suite|function|method|class|module|file|files|repo|codebase|code|bug|"
                       r"error|exception|import|readme|docs|dependency|dependencies|package|script|build|ci)\b", re.I)
_DO_ORDER = re.compile(r"^\s*do (?:the|it|that|this|those|them|all|both|everything|each|what|as)\b", re.I)


# "what is the difference between a process and a thread?": a concept question. "process" is an anchor word (it can
# mean one on this machine), so it was given shell tools and tried to `echo` its answer through bash, which asked for
# approval (tool drive 2026-11-21). Only the indefinite form, with nothing that points at a file or at "this".
_CONCEPT_DIFF = re.compile(r"^\s*(?:(?:what(?:'s| is| are)|explain|describe)\s+)?(?:the\s+)?differences?\s+between\s+"
                           r"an?\s+[a-z][a-z -]{1,30}?\s+and\s+(?:an?\s+)?[a-z][a-z -]{1,30}?\s*\??"
                           r"(?:\s*[,(]?\s*(?:in\s+)?\d+\s+(?:lines?|sentences?|words?|bullets?)\)?)?\s*[?.]?\s*$", re.I)
_POINTS_HERE = re.compile(r"[/\\`_]|\.\w{2,4}\b|\b(?:this|that|these|those|here|my|our|your|its|their)\b", re.I)


def is_general_question(text):
    """A world-knowledge question with no tie to this machine or the work: answer it, do not investigate it.
    One- and two-word questions ("why?", "really?") are follow-ups to whatever was just said, so they never count."""
    (
        _ANCHOR, _WORK_HINT, _WORK_NOUN, _program_names, is_conversation, is_question, re,
    ) = bind(
        "_ANCHOR", "_WORK_HINT", "_WORK_NOUN", "_program_names", "is_conversation", "is_question", "re",
    )
    t = _core_q((text or "").rsplit("\n\n", 1)[-1].strip())
    concept = bool(_CONCEPT_DIFF.match(t)) and not _POINTS_HERE.search(t)
    if not concept and (not is_question(t) or is_conversation(text) or len(t.split()) < 3 or len(t) > 300):
        return False
    if not concept and (_ANCHOR.search(t) or _WORK_NOUN.search(t) or _WORK_HINT.search(t)):
        return False
    if _ON_THIS_MACHINE.search(t) or _DO_ORDER.match(t):
        # "is ufw installed", "is openssh up to date" ask about THIS machine; "do the safe parts" is an order that
        # opens with "do". Read as world questions they got web tools only and died empty (2026-11-20 drive).
        return False
    import gnoc_modes
    if gnoc_modes.detect(t) == "defender":
        # "is auto defense on", "is tor installed": about THIS machine, never world knowledge. Read as world
        # questions they got web_search/web_fetch only, so the lead reasoned "call defend with action=status"
        # three times and could not, and the turn ended empty (2026-11-20 defender drive, traced).
        return False
    low = t.lower()
    return not any(re.search(r"(?<![\w-])" + re.escape(n.lower()) + r"(?![\w-])", low) for n in _program_names())


def is_hunt_directive(text):
    """The text the hunt loop feeds a turn (gnoc_hunt.directive / nudge), not something the user typed."""
    t = (text or "").rsplit("\n\n", 1)[-1].lstrip() if "✻" in (text or "")[:200] else (text or "").lstrip()
    return t.startswith("[HUNT ") or t.startswith("STUCK:")


# Tool results that put a decision to GreyNOC himself. A turn that has one is DONE once it asks him: the
# "planned but did not act" nudge used to fire on exactly that answer (GreyNOC 2026-11-18, `defend`: the sweep
# asked two questions, the nudge said "execute it NOW ... make the edits with edit_file, then run_tests", and the
# lead spent 18 steps trying to answer them itself, then sudo, then a 40-times repeated paragraph).
_AWAITS_GREYNOC = ("QUESTIONS FOR GREYNOC", "needs the user's own yes", "The user's message does not answer it",
                   "These are the user's decisions")


def awaits_greynoc(tool_output):
    """True when a tool's output says the next move is the user's decision, not the model's."""
    (
        _AWAITS_GREYNOC,
    ) = bind(
        "_AWAITS_GREYNOC",
    )
    text = str(tool_output or "")
    return any(k in text for k in _AWAITS_GREYNOC)


# Words people start a sentence with before they get to it. "hey, what can you do for me in one short paragraph"
# is a question, and was a work order: the plan nudge fired on the answer and the lead went looking for a plan.md.
_LEAD_IN = re.compile(r"^(?:(?:hey|hi|hello|yo|ok(?:ay)?|so|and|now|well|right|also|then|please|pls|alright|cool|"
                      r"great|thanks|thank you|fine|good|nice)\b[\s,.!:;-]*|"
                      # a condition said first: "without sending any traffic anywhere: which program would you
                      # hunt next" is a question too, and was pre-planned into 6 bots that ran go test (BB drive)
                      r"(?:no network|offline|read[- ]only|on[- ]disk only|from disk only|"
                      r"(?:without|do not|don't|dont|no)\s[^:.;?!]{3,60})[.:;]\s*)+", re.I)
# A request whose whole product is words in the answer: nothing on this machine is to be run, written or changed.
# "give one command to test whether nginx config is valid" was answered with the command, then pushed with "Do not
# tell me how. Do it yourself now" and tried to run nginx -t (general-chat drive 2026-11-21).
_SAY_IT = re.compile(
    r"^(?:(?:give|tell|name|show|suggest)\s+(?:me\s+)?(?:(?:one|a|an|the|two|three|four|five|some|\d+)\s+)?"
    r"(?:[\w-]+\s+){0,2}?(?:commands?|examples?|reasons?|words?|lines?|sentences?|names?|numbers?|definitions?|"
    r"tips?|summar(?:y|ies)|answers?|formulas?|ways?|options?|ideas?|analog(?:y|ies)|synonyms?|titles?|jokes?|facts?|riddles?|quotes?|stor(?:y|ies)|"
    # "checklist before I press submit, eight items" was an order: a worker grepped the workspace to the 420 s cap
    r"checklists?|lists?|templates?|outlines?|bullets?|points?|steps?|cheat\s*sheets?)\b|"
    r"(?:a\s+|an\s+|the\s+|one\s+)?(?:short\s+|quick\s+|brief\s+)?(?:checklist|template|outline|cheat\s*sheet)\b|"
    # "write a bash one-liner that shows the 5 largest files" is words: it was run, refused, re-tried, and the answer
    # gave invented sizes for real paths (batch 5, 2026-11-23). A script or a function is still work.
    r"(?:write|give|show|make)\s+(?:me\s+)?(?:a|an|one|the)\s+(?:[\w-]+\s+){0,2}?(?:one-?liners?|oneliners?|"
    r"commands?|regex(?:es)?|regular\s+expressions?|aliases|alias|cron\s+lines?|crontab\s+lines?)\b|"
    r"(?:translate|calculate|compute|compound|convert|define|rephrase|reword|paraphrase|spell|pronounce|solve|"
    r"multiply|divide|round)\b|"
    # "explain compound interest with a 1000 dollar example over 3 years" was fanned out into six bots that
    # read leftover files and ran to the 420 s cap (general drive 2026-11-22). An explanation is the answer.
    r"(?:explain|describe|summari[sz]e|compare|outline)\s+(?!(?:and\s+)?(?:fix|change|edit|update|refactor)\b)|"
    r"(?:write|draft|compose)\s+(?:me\s+)?(?:(?:one|a|an|the|two|three|four|five|\d+)\s+)?(?:[\w-]+\s+){0,3}?"
    r"(?:e-?mails?|messages?|repl(?:y|ies)|letters?|poems?|haikus?|jokes?|tweets?|sentences?|paragraphs?|"
    r"apolog(?:y|ies)|notes?|speech(?:es)?|toasts?|captions?|slogans?|limericks?|essays?|stor(?:y|ies)|bios?|"
    r"headlines?|subject lines?|texts?)\b|"
    r"(?:write|draft|compose)\s+(?:me\s+)?(?:(?:one|a|an|the|two|three)\s+)?(?:(?:short|brief|better|new|clear|"
    r"one[- ]line|two[- ]line|impact)\s+){0,2}(?:statements?|descriptions?|summar(?:y|ies)|titles?)\b|"
    # "rewrite this report title so a triager gets it at once: 'xss found'" was fanned out into six bots, one
    # of them sent to edit reports/STATUS.md (BB drive 2026-11-22): the product is the rewritten words
    r"(?:rewrite|re-write|improve|shorten|polish|tighten|reword)\s+(?:this|that|the|my)\s+(?:[\w-]+\s+){0,3}?"
    r"(?:titles?|sentences?|paragraphs?|lines?|summar(?:y|ies)|descriptions?|statements?|headlines?|text|wording|"
    r"messages?|e-?mails?|bio)\b|"
    r"(?:a|an|one)\s+(?:(?:one|two|three|short)[- ]lines?\s+)?(?:[\w-]+\s+){0,2}?(?:statements?|summar(?:y|ies)|"
    r"titles?|descriptions?|sentences?|paragraphs?)\s+(?:for|about|of|on)\b)", re.I)
_NAMES_A_FILE = re.compile(r"(?<![\w.])[\w-]+\.(?:py|js|ts|tsx|jsx|json|md|txt|sh|yml|yaml|toml|html|css|sql|go|rs|c|h|"
                           r"cpp|java|rb|php|csv|ipynb)\b|(?:^|\s)(?:\./|~/|/)[\w.-]+", re.I)


def is_action_request(text):
    """A request to DO something (imperative), not a question. Bot-event preambles are ignored.

    A GREETING IS NOT A WORK ORDER. This used to be "anything that is not a question", so `hello` was an
    action request: the acting-nudge then saw an answer offering options, read it as how-to, and injected
    "Do not tell me how. Do it yourself now with your tools" - a work order with no task in it. Asked to
    act on nothing, the lead picked the biggest thing in sight and reasoned its way to clearing the global
    STOP and resuming the hunt fleet, off the word `hello` (the user, 2026-11-01, deepseek-reasoner lead).
    is_small_talk() was written for the first version of this exact incident - its own docstring records a
    fallback model answering `hello` with `gnoc stop` and `gnoc resume` - but the three nudges below never
    consulted it. Gating it here covers all three at once, because none of them has a task either."""
    (
        _QUESTION, is_small_talk,
    ) = bind(
        "_QUESTION", "is_small_talk",
    )
    t = (text or "").rsplit("\n\n", 1)[-1].strip()
    if is_small_talk(text):
        return False
    core = _LEAD_IN.sub("", t, count=1).strip() or t
    if _QUESTION.match(core):
        return False
    # a bare follow-up asks about the last answer; it names nothing to do. "why not", after "I will not run
    # rm -rf /home", was pushed with "do it yourself now", and the lead tried the rm (defense drive 2026-11-22).
    if re.fullmatch(r"(?i)(?:but\s+|and\s+|so\s+)?(?:why(?:\s+not)?|how\s+so|how\s+come|really|what\s+else|such\s+as|"
                    r"like\s+what|for\s+example|meaning|and|so)\W*", core):
        return False
    # a fragment that only extends the last answer: "and with monthly compounding", "without eggs", "what about
    # sundays". It was pushed with "do it yourself now" and the lead edited a file nobody named (2026-11-22).
    if len(t.split()) <= 7 and re.match(r"(?i)(?:(?:and|but|or|plus|also)\s+)?(?:with|without|for|in|at|on|by|from|"
                                        r"instead\s+of|what\s+about|how\s+about|same\s+(?:for|with|but))\b", t) \
            and not _NAMES_A_FILE.search(t) \
            and not re.search(r"(?i)\b(?:add|fix|run|write|make|change|create|remove|delete|update|rename|edit|"
                              r"commit|push|install|build|deploy|refactor|implement)\b", t):
        return False
    # "how do I undo one thing" asks to be told how. ("how does X work" and "why ..." stay analysis work.) It
    # got "Do not tell me how. Do it yourself now", and the lead tried sudo sysctl -w (defense drive 2026-11-22).
    if re.match(r"(?i)how\s+(?:do|can|could|would|should|might)\s+(?:i|we|you|one|someone|a |an |the )|how to\b", core):
        return False
    # ... and after a clause: "my desktop runs gnoc in wsl, how do I let this laptop use its gpu" was pushed with "do
    # it yourself now" and the lead ran `gnoc-engine share on` on the LAPTOP (batch 7, 2026-11-23)
    # "I got an api key in an error page I wasn't supposed to see, what now" ends on a question (batch 8)
    if re.search(r"(?i)[,;:\-]\s*(?:so\s+)?(?:what\s+now|now\s+what|what\s+(?:do|should|can)\s+(?:i|we)\s+do(?:\s+now)?|"
                 r"what\s+next|is\s+(?:that|this|it)\s+(?:bad|ok(?:ay)?|safe|normal|a\s+problem))\s*\??\s*$", core):
        return False
    if re.search(r"(?i)(?:[,;:]\s*|\b(?:so|and|but|then)\s+)how\s+(?:do|can|could|would|should|might)\s+(?:i|we)\b", core) \
            and not re.search(r"(?i)\b(?:do\s+it|set\s+it\s+up|make\s+it\s+so|go\s+ahead)\b", core):
        return False
    # "how often will you check and where do alerts go", "how will I know in the morning": a measure or a way of
    # finding out, asked for. Read as an order, the defender's fixed rule arrived as "do only what it allows"
    # (defense drive 2026-11-22).
    if re.match(r"(?i)how\s+(?:many|much|long|often|old|far|fast|soon|big|bad|sure|likely)\b|"
                r"how\s+(?:will|would|could|can)\s+(?:i|we)\s+(?:know|tell|see|find\s+out|be\s+told)\b", core):
        return False
    if _SAY_IT.match(core) and not _NAMES_A_FILE.search(core):
        return False
    # It ENDS on a question: "I think I found an IDOR: GET /api/orders/123 returns another user's order when I
    # change the id. what do you need from me before this is reportable" tells a story and then asks. It was
    # pre-planned into 6 bots, one of them briefed to "run a GET probe" (the scope gate refused it), 420 s.
    last = re.split(r"(?<=[.!?:;])\s+", core)[-1].strip()
    if last != core and _QUESTION.match(_LEAD_IN.sub("", last, count=1).strip() or last):
        return False
    return bool(t) and not t.endswith("?")


def is_instructions(text):
    """An answer that hands the user steps to run instead of running them."""
    (
        _HOWTO,
    ) = bind(
        "_HOWTO",
    )
    return bool(_HOWTO.search(text or ""))


def is_refusal(text):
    """A bare refusal: short and opening with a refusal formula (a long answer that merely contains one is not)."""
    (
        REFUSAL,
    ) = bind(
        "REFUSAL",
    )
    t = (text or "").strip()
    return bool(t) and len(t) < 400 and bool(REFUSAL.search(t))


# The model lays out how it WILL fix something, then ends the turn without doing it. The old "explained
# instead of acting" nudge missed this twice over: it was gated on `not used_tools`, so any read_file/grep
# the model did while planning switched it off, and it only matched second-person how-to ("you can run ...")
# via _HOWTO, never a first-person plan ("I'll edit X, then run the tests"). Both are the same stall: an
# action was asked for, a plan was produced, nothing changed. (GreyNOC 2026-10-23: "it stops working after
# it's planned out the fix".)
_PLAN_LANG = re.compile(
    r"(\bI(?:['’]?ll| will| am going to| intend to| plan to| would)\b|\b(?:next|then|first|after that|"
    r"finally),?\s+I\b|\bhere(?:['’]?s| is)\s+(?:my|the)\s+plan\b|\b(?:my|the)\s+plan\s+is\b|\bmy approach\b|"
    r"\bthe steps?\s+(?:are|would be)\b|\bI['’]?d\s+(?:then\s+)?(?:edit|change|fix|add|update|run|write)\b|"
    r"\bwe(?:['’]?ll| will| should)\b|"
    # "Now let me add tests and verify:" ending a turn with nothing changed (SWE gauntlet 2026-10-24)
    r"\blet me (?!know\b)(?:now |first |then )?(?:add|apply|write|edit|change|fix|update|run|create|implement|make|"
    r"verify|test)\b)", re.I)


_PLAN_STEP = re.compile(r"(?m)^\s*(?:\d+[.)]|[-*]\s+(?:first|then|next|step\b)|step\s+\d+\b)", re.I)


_PLAN_ONLY = re.compile(
    r"(\b(?:just|only|first)\s+(?:give me |show me |draft |make )?(?:a |the |your )?(?:plan|outline|approach)\b|"
    r"\bplan\s+(?:it|this|out|first)\b|\boutline\b|\bpropose\b|\bsketch\b|\bthink (?:it |this )?through\b|"
    r"\b(?:plan|steps|commands?|outline|proposal)\s+only\b|"
    r"\bwalk me through\b|\bwhat(?:['’]s| is)\s+your\s+plan\b|\bhow would you\b|\bdon['’]?t\s+"
    r"(?:change|edit|touch|modify|write|run|apply)\b|\bread[- ]?only\b|\bdry[- ]?run\b|\bno changes\b)", re.I)


# A numbered item is a STEP when it starts with what to do ("1. Add the null check", "2. I'll run the tests"), not
# with what is now true ("1. **`total_skus()`** now returns 0", "2. Fixed the import"): a results report with a
# numbered list was read as a plan on "run the tests", and the push made the lead edit report.py again and sit
# through a second review (2026-11-20 SWE drive).
_STEP_VERB = re.compile(
    r"[ \t]*(?:\*\*|__)?[ \t]*(?:(?:first|then|next|finally),?\s+)?(?:I(?:['’]?ll| will| would| need to| should)\s+|"
    r"we(?:['’]?ll| will| should)\s+|let me\s+)?(?:add|apply|back ?up|build|change|check|clean|commit|compare|"
    r"configure|confirm|convert|create|debug|delete|deploy|determine|document|edit|ensure|examine|extract|find|fix|"
    r"grep|identify|implement|inspect|install|investigate|look|make|measure|merge|migrate|modify|move|open|patch|"
    r"profile|push|read|refactor|remove|rename|replace|reproduce|resolve|restart|review|rewrite|run|search|set|split|"
    r"start|stop|test|trace|update|verify|write)\b", re.I)


def looks_like_plan(text):
    """True when the answer is a statement of intent / a step list rather than work that was done."""
    (
        _PLAN_LANG, _PLAN_STEP,
    ) = bind(
        "_PLAN_LANG", "_PLAN_STEP",
    )
    t = (text or "").strip()
    if len(t) < 40:
        return False
    if _PLAN_LANG.search(t):
        return True
    steps = 0
    for m in _PLAN_STEP.finditer(t):
        if m.group(0).strip()[:1].isdigit() and not _STEP_VERB.match(t, m.end()):
            continue            # "1. `empty()` now returns True": a result, not a step
        steps += 1
    return steps >= 2


def needs_plan_push(answer, used_tools):
    """Whether the plan nudge should send the turn back to do work.

    A first-person plan is a stall whether or not files were read first. A second-person how-to is only
    actionable when nothing has run: after a read-only tool, a normal closing such as "let me know if you
    need help with the other files" was read as instructions, and a missing-file report was pushed into
    editing/testing an unrelated file (2026-11-19 drive).
    """
    (
        is_instructions, looks_like_plan,
    ) = bind(
        "is_instructions", "looks_like_plan",
    )
    return looks_like_plan(answer) or (is_instructions(answer) and not used_tools)


# "tell me what I should close", "what would you recommend": the answer IS the deliverable. The plan nudge pushed
# "make the edits with edit_file" at a port audit and the agent started editing systemd units (2026-10-24).
_ADVICE = re.compile(r"\b(tell me|what (?:should|do|would|could) I|should I|recommend|suggest|advise|"
                     r"what(?:'s| is) (?:exposed|open|wrong|risky)|which \w+ (?:should|to)|"
                     # informational asks: an explanation that offers "want me to run the tests?" is finished,
                     # not a stalled plan (the nudge ran tests and planned edits on "explain every function")
                     r"explain|describe|summari[sz]e|walk me through|give me an overview|"
                     r"\b(?:list|show)\b(?!.*(?:\band\b|\bthen\b|[,;])\s*(?:then\s+)?(?:fix|change|edit|update|delete|"
                     r"remove|add|write|create|run|execute|apply|patch|repair|implement|refactor|move|rename|install|"
                     r"build)\b))\b",
                     re.I)


def wants_advice(text):
    """The user asked to be TOLD (an assessment or a recommendation), not for a change to be made."""
    (
        _ADVICE,
    ) = bind(
        "_ADVICE",
    )
    return bool(_ADVICE.search((text or "").rsplit("\n\n", 1)[-1]))


def wants_plan_only(text):
    """The user explicitly asked for only a plan (then executing would be wrong)."""
    (
        _PLAN_ONLY,
    ) = bind(
        "_PLAN_ONLY",
    )
    t = (text or "").rsplit("\n\n", 1)[-1]
    return bool(_PLAN_ONLY.search(t))


# A mid-task answer that REPORTS progress but still names work it has not carried out ("next I'll ...",
# "I still need to ...", "the remaining steps are ..."). Distinct from looks_like_plan (pre-action intent):
# this is the half-done stall. The plan nudge is gated on `not edited`, so once one step is done it goes
# quiet; this is what the finish-through nudge keys on to make a multi-step task run to the end.
_REMAINING = re.compile(
    r"(\bI(?:['\u2019]?ll| will| am going to| intend to| need to| still need| have yet| am about to)\b|"
    r"\b(?:next|now|then|after that|finally)\s*,?\s*I\b|"
    r"\bstill\s+(?:need|have|to|left)\b|\b(?:remaining|next)\s+steps?\b|"
    r"\b(?:have\s+not|haven['\u2019]?t)\s+(?:yet\b|done|finished|completed)|"
    r"\bnot\s+(?:yet\s+)?(?:done|finished|complete)\b|\bleft\s+to\s+(?:do|complete)\b|"
    r"\bto\s+(?:do|complete)\s*:|\bTODO\b|\bstep\s+[2-9]\b|\bI['\u2019]?ll\s+now\b|\bthe\s+next\s+step\b)", re.I)


def work_remaining(text):
    """True when an answer announces work it has NOT done yet (the half-finished-task tell)."""
    (
        _REMAINING,
    ) = bind(
        "_REMAINING",
    )
    t = (text or "").strip()
    return len(t) >= 20 and bool(_REMAINING.search(t))


def suggest_next_prompt(agent, answer):
    """One short prompt to pre-fill the input with when a turn ends, so the next step is one keystroke away.
    Instant and model-free: when the bot stopped with work left it offers 'continue' (the highest-value
    follow-up, and the complement of the finish-through nudge); on a live standing goal it offers to carry
    the goal on; otherwise nothing, so a clean finish leaves the prompt blank as before."""
    (
        gnoc_goal, gnoc_plan, os, work_remaining,
    ) = bind(
        "gnoc_goal", "gnoc_plan", "os", "work_remaining",
    )
    if os.environ.get("GNOC_SUGGEST", "1") == "0":
        return ""
    try:
        if answer and work_remaining(answer):
            return "continue"
        if gnoc_goal._owned(gnoc_goal.load(), agent.s.get("sid")):
            return "continue with the next step of the goal"
        plan = gnoc_plan.load(agent.s.get("sid"))
        i, step = gnoc_plan.next_step(plan) if plan else (None, None)
        if step:
            return f"continue with plan step {i}"
    except Exception:
        pass
    return ""


def _last_answer(agent):
    for m in reversed(agent.s.get("history") or []):
        if m.get("role") == "assistant" and (m.get("content") or "").strip():
            return m["content"]
    return ""


# an acknowledgement may lead the order: "thanks, now hunt globex" and "ok hunt gatewayco" are work, not small talk
_AUTO_HUNT = re.compile(r"^\s*(?:(?:ok(?:ay)?|cool|nice|great|thanks?|thank you|thx|ty|alright|right|good|so|and|"
                        r"then|now|please|go|yes|yep|sure)[\s,.!;:-]+)*(?:auto[- ]?hunt|live[- ]?hunt|hunt)\b\s*(.*)$",
                        re.I)


_BACKGROUND = re.compile(r"\b(background|orch|bot\s+hunt|in the background)\b", re.I)


# English words that start a sentence after "hunt" and would otherwise prefix-match a handle (for -> forescout)
_NOT_PROGRAM = {"for", "down", "the", "this", "that", "it", "them", "bugs", "bug", "something", "some", "now",
                "more", "again", "around", "through", "with", "and", "a", "an", "all", "any", "me", "here", "there"}


def auto_hunt_request(line):
    """'auto hunt gatewayco', 'live hunt meta oauth flows', 'hunt globex' -> (program or None, goal): the chat agent
    hunts it live itself (the /hunt loop with fan-out). 'auto hunt in the background' stays a request for the
    orch-bot, answered by a normal turn."""
    (
        _AUTO_HUNT, _BACKGROUND, _NOT_PROGRAM, resolve_program,
    ) = bind(
        "_AUTO_HUNT", "_BACKGROUND", "_NOT_PROGRAM", "resolve_program",
    )
    m = _AUTO_HUNT.match(line or "")
    if not m or _BACKGROUND.search(line) or line.rstrip().endswith("?"):
        return None  # "hunt globex?" asks; only an order starts the endless live loop
    rest = m.group(1).strip().strip(".!")
    words = rest.split()
    if words and words[0].lower() in ("on", "the", "program"):
        words = words[1:]
    first = words[0].lower() if words else ""
    prog = resolve_program(words[0]) if words and first not in _NOT_PROGRAM and len(first) >= 3 else None
    if not prog and words:
        # 'hunt for the bug that broke the website' is a sentence, and 'hunt kongg' is a typo: neither may start
        # an endless live hunt on whatever program happens to be active. A normal turn answers (or asks).
        return None
    return prog, " ".join(words[1:])
