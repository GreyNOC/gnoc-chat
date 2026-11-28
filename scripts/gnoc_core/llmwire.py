"""Model-wire shaping and repair: OpenAI conversion, think-stream filters, degenerate-output detection."""
import http.client
import json
import re
import socket

import llm_endpoints


def _ctx_overflow_fix(host, body, n_tokens, cap=None):
    """Repair an exceed_context_size refusal in place. Returns True when the request changed and is worth a retry.
    Within the host's ceiling (llm_endpoints.CTX_MAX) the window grows to the prompt plus reply room; at the ceiling
    the oldest tool outputs are trimmed instead, because a bigger runner on the desktop card does not start (D74)."""
    want = ((int(n_tokens) + 2048) // 1024 + 1) * 1024
    # cap= is the window the SERVER says it has (n_ctx in its refusal): gnoc's engine keeps the context it loaded
    # with, so asking it for a bigger num_ctx changes nothing and the same refusal comes back (SWE batch 1)
    cap = int(cap) if cap else llm_endpoints.ctx_max(host)
    opts = body.setdefault("options", {})
    if want <= cap:
        opts["num_ctx"] = want
        return True
    opts["num_ctx"] = cap
    # trim: drop the content of the oldest tool results (then the oldest assistant turns) until the rough token
    # estimate (4 chars per token) fits under the cap with reply room; the system prompt and the last 6 turns stay.
    msgs = body.get("messages") or []
    # the tool schemas ride in the same window: counting only the messages, an 18.1k-token request against 16k
    # looked like it already fit, nothing was trimmed and the retry failed the same way (drive 2026-11-23). And
    # ~3.2 chars a token, not 4: JSON and code tokenize denser than prose.
    over = max(0, int(n_tokens) - cap + 2048)
    budget = int((cap - 2048) * 3.2) - len(json.dumps(body.get("tools") or []))
    # tool-call ARGUMENTS ride in the window too: a 9B lead wrote one long document into write_file and again into a
    # bash heredoc; counting only content, the 16.6k-token request looked trimmable to nothing (batch 5, 2026-11-23)
    def _args_len(m):
        return sum(len(json.dumps((c.get("function") or {}).get("arguments") or "", default=str))
                   for c in (m.get("tool_calls") or []) if isinstance(c, dict))

    def _size():
        return sum(len(str(m.get("content") or "")) + _args_len(m) for m in msgs)
    budget = min(budget, int(_size() - over * 3.2))
    trimmed = 0
    for role in ("tool", "assistant"):
        for m in msgs[1:-6]:
            if _size() <= budget:
                break
            if m.get("role") == role and len(str(m.get("content") or "")) > 200:
                m["content"] = "(trimmed: this output exceeded the context window; re-run the tool if it is needed)"
                trimmed += 1
    # Still over: the bulk is in THIS turn (a desktop that failed mid-turn handed a 16.9k-token turn to the 16k laptop,
    # and with nothing old left to trim the turn died, drive 2026-11-22). Cut this turn's biggest tool outputs to their
    # head, largest first; the user's message and the system prompt are never touched.
    if _size() > budget:
        recent = sorted((m for m in msgs[-6:] if m.get("role") == "tool"),
                        key=lambda m: -len(str(m.get("content") or "")))
        for m in recent:
            if _size() <= budget:
                break
            text = str(m.get("content") or "")
            if len(text) > 2000:
                m["content"] = text[:1500] + ("\n(the rest of this output was cut to fit the context window; ask for "
                                              "a narrower read if it is needed)")
                trimmed += 1
    # Still over: long string arguments of earlier tool calls (a whole document passed to write_file or a heredoc).
    # The call stays, so the history still pairs each tool result with its call; only the long value is shortened.
    if _size() > budget:
        for m in msgs[1:]:
            if _size() <= budget:
                break
            for c in (m.get("tool_calls") or []):
                fn = c.get("function") if isinstance(c, dict) else None
                a = fn.get("arguments") if isinstance(fn, dict) else None
                if isinstance(a, dict):
                    for k, v in list(a.items()):
                        if isinstance(v, str) and len(v) > 1500:
                            a[k] = v[:600] + "\n(... cut to fit the context window ...)"
                            trimmed += 1
                elif isinstance(a, str) and len(a) > 1500:
                    fn["arguments"] = a[:600] + "(... cut to fit the context window ...)"
                    trimmed += 1
    return trimmed > 0


def _to_openai(messages):
    """Ollama-shaped history -> OpenAI chat messages (tool calls need ids and string arguments)."""
    out, pending = [], []
    for i, m in enumerate(messages):
        if m["role"] == "assistant" and m.get("tool_calls"):
            calls = []
            for j, c in enumerate(m["tool_calls"]):
                cid = c.get("id") or f"call_{i}_{j}"
                args = c.get("function", {}).get("arguments", {})
                calls.append({"id": cid, "type": "function", "function": {
                    "name": c.get("function", {}).get("name", ""),
                    "arguments": args if isinstance(args, str) else json.dumps(args)}})
            pending = [c["id"] for c in calls]
            out.append({"role": "assistant", "content": m.get("content") or "", "tool_calls": calls})
        elif m["role"] == "tool":
            out.append({"role": "tool", "content": m["content"],
                        "tool_call_id": pending.pop(0) if pending else f"call_{i}"})
        else:
            out.append({"role": m["role"], "content": m.get("content") or ""})
    return out


def _strip_think_stream(state, tok):
    """Live-stream filter: drop <think>...</think> blocks and stray tags (the 8B worker leaks a bare </think>
    when thinking is off). Holds back a possible partial tag split across two chunks."""
    tok, keep = state.get("carry", "") + tok, []
    state["carry"] = ""
    while tok:
        if state.get("in_think"):
            j = tok.find("</think>")
            if j < 0:
                state["carry"] = tok[-8:] if "<" in tok[-8:] else ""
                return "".join(keep)
            tok, state["in_think"] = tok[j + 8:], False
            continue
        i, j = tok.find("<think>"), tok.find("</think>")
        if j >= 0 and (i < 0 or j < i):
            keep.append(tok[:j])
            tok = tok[j + 8:]
            continue
        if i >= 0:
            keep.append(tok[:i])
            tok, state["in_think"] = tok[i + 7:], True
            continue
        k = tok.rfind("<")
        if k >= 0 and any(t.startswith(tok[k:]) for t in ("<think>", "</think>")):
            keep.append(tok[:k])
            state["carry"] = tok[k:]
        else:
            keep.append(tok)
        tok = ""
    return "".join(keep)


# An UNTAGGED reasoning preamble: a model asked for no reasoning pass that reasons anyway, in its CONTENT, with no
# <think> tag ("The user has sent a simple greeting. I need to respond as GNOC..." then the real "Hello! ..."). The
# Opus-distilled Qwen3.5 lead did it on every small-talk turn, so /thoughts off could not hide it and it was saved
# into the history (GreyNOC 2026-11-25). The openers are third-person talk ABOUT the request or first-person talk
# about RESPONDING to it - never a bare "The user" or "I need to", which also open real answers ("The user guide
# says...", "I need to see the file first").
_PREAMBLE_OPEN = re.compile(
    r"^(?:(?:okay|ok|alright|all right|hmm+|so|well|now)[,.!]?\s+(?:so[,]?\s+)?)?(?:"
    r"(?:the\s+)?user(?:\s+(?:has|have|just|simply|now|again|is|was))*\s+(?:said|says|sent|sends|asked|asks|"
    r"wants|wanted|greeted|greets|typed|types|wrote|writes|repeated|repeats|is\s+(?:asking|saying|greeting|"
    r"sending|just)|needs|would\s+like|seems|said\s+\S+\s+again|sent\s+\S+\s+again|"
    r"responded|replied|has\s+(?:sent|said|asked|greeted))\b"
    r"|i\s+(?:need|should|must|will|want|have|ought)\s+(?:to\s+)?(?:respond|reply|answer|greet|keep\s+(?:it|this|my)|"
    r"introduce|acknowledge|be\s+(?:brief|concise|friendly|warm|short|helpful)|follow|mention|offer)\b"
    r"|i'll\s+(?:respond|reply|answer|greet|keep\s+it|introduce|acknowledge)\b"
    r"|let\s+me\s+(?:think|respond|reply|answer|craft|draft|compose|figure\s+out|consider|greet|introduce)\b"
    # "Let me analyze the conversation context:" then a numbered list about the system prompt, shown above "Hello!"
    # with /thoughts off (2026-11-27): an analysis verb aimed at the conversation itself, never at his files
    r"|(?:let\s+me\s+|i(?:'ll|\s+will)\s+)?(?:analy[sz]e|analy[sz]ing|review|reviewing|look\s+at|looking\s+at|"
    r"go\s+over|break\s+down|process|understand|parse)\s+(?:the|this)\s+(?:conversation|context|request|"
    r"message|greeting|situation|prompt|system\s+prompt|user(?:'s)?\s+(?:message|request|greeting))\b"
    r"|let's\s+(?:think|respond|reply|craft|draft|compose)\b"
    r"|we\s+(?:need|should|must)\s+(?:to\s+)?(?:respond|reply|answer|greet)\b"
    r"|key\s+points\b|(?:according\s+to|per|from)\s+the\s+system\s+prompt\b|the\s+system\s+prompt\s+"
    r"(?:says|said|asks|tells|wants|requires)\b|the\s+(?:instructions|guidelines)\s+(?:say|ask|tell)\b"
    r"|this\s+is\s+(?:just\s+)?(?:a\s+)?(?:simple\s+)?(?:greeting|small\s+talk)\b)", re.I)
_BULLET = re.compile(r"^(?:[-*•◦‣]|\d+[.)])\s")


def _preamble_lines(text):
    """How many leading lines of text are an untagged reasoning preamble (blank lines inside it included), and
    whether a non-preamble line follows them. A line belongs when it opens like reasoning (_PREAMBLE_OPEN), or it
    is a bullet / continuation of a preamble line just before it (the "Key points:" list)."""
    lines = text.split("\n")
    n, meta, prev = 0, 0, ""
    for i, line in enumerate(lines):
        s = line.strip()
        if not s:
            n = i + 1 if meta else n
            continue
        cont = meta and (_BULLET.match(s) or prev.endswith(":") or s[:1].islower())
        if _PREAMBLE_OPEN.match(s) or cont:
            meta, prev, n = meta + 1, s, i + 1
            continue
        return (n if meta else 0), True
    return n, False


def split_untagged_reasoning(text):
    """(reasoning, answer) when the reply OPENS with an untagged reasoning preamble and a real answer follows it on
    a later line; ("", text) otherwise. Conservative by construction: one line is never split, a reply that is all
    preamble is kept whole (it IS the answer then), and only the openers in _PREAMBLE_OPEN count."""
    raw = text or ""
    s = raw.lstrip()
    if "\n" not in s.strip():
        return "", raw
    n, more = _preamble_lines(s)
    if not n or not more:
        return "", raw
    lines = s.split("\n")
    reasoning, answer = "\n".join(lines[:n]).strip(), "\n".join(lines[n:]).strip()
    if not reasoning or len(answer) < 2:
        return "", raw
    return reasoning, answer


class PreambleGate:
    """Live-stream hold for a call sent with thinking OFF: the text is held until its first line shows whether it
    opens with an untagged reasoning preamble. Not a preamble: everything is released at once (a normal answer is
    delayed by one line). A preamble: held until the first non-preamble line, then the answer streams and the
    preamble is in .reasoning (the caller shows it as the thinking block or drops it). Capped, so a reply that never
    resolves is still shown."""
    CAP = 2000

    def __init__(self):
        self.buf, self.open, self.reasoning = "", False, ""

    def feed(self, text):
        if self.open:
            return text
        self.buf += text or ""
        s = self.buf.lstrip()
        if not s:
            return ""
        first = s.split("\n", 1)[0].strip()
        if "\n" not in s and len(s) < 400:
            return ""                                   # the first line is not finished: undecided
        if not _PREAMBLE_OPEN.match(first):
            return self._release(self.buf)
        done = s[:s.rfind("\n") + 1]                    # whole lines only: a half-streamed line is not judged
        n, more = _preamble_lines(done)
        if more and n:
            lines = s.split("\n")
            self.reasoning = "\n".join(lines[:n]).strip()
            return self._release("\n".join(lines[n:]).lstrip("\n"))
        if len(self.buf) >= self.CAP:
            return self.finish()
        return ""

    def finish(self):
        """The stream ended (or hit the cap): decide on what arrived and return what is left to show."""
        if self.open:
            return ""
        reasoning, answer = split_untagged_reasoning(self.buf)
        if reasoning:
            self.reasoning = reasoning
            return self._release(answer)
        return self._release(self.buf)

    def _release(self, text):
        self.open, self.buf = True, ""
        return text


def _ensure_user_turn(messages):
    """Qwen3/3.5 GGUF chat templates (Jinja, rendered by Ollama and llama-server) RAISE "No user query found in
    messages." when no user turn holds plain text: a goal-driven continuation or a compacted history of only
    system/assistant/tool messages died with HTTP 500 on the Huihui lead (2026-10-22). The Go templates of
    the older -oc wrappers never checked. Add a neutral user turn to the request copy; the history is untouched."""
    msgs = list(messages or [])
    # the same templates also raise "System message must be at the beginning.": a later system message is sent as a
    # user note instead (the leading run of system messages is left alone)
    lead = 0
    while lead < len(msgs) and msgs[lead].get("role") == "system":
        lead += 1
    msgs = msgs[:lead] + [dict(m, role="user", content="[system note] " + str(m.get("content") or ""))
                          if m.get("role") == "system" else m for m in msgs[lead:]]
    if any(m.get("role") == "user" and isinstance(m.get("content"), str) and m["content"].strip()
           and not m["content"].lstrip().startswith("<tool_response>") for m in msgs):
        return msgs
    i = 0
    while i < len(msgs) and msgs[i].get("role") == "system":
        i += 1
    return msgs[:i] + [{"role": "user", "content": "Continue the current task."}] + msgs[i:]


def _approx_tokens(messages, reply=""):  # ECON: no usage block -> characters / 4
    return (sum(len(str(m.get("content") or "")) for m in messages or [] if isinstance(m, dict)) + len(reply)) // 4


_DEGEN_TAIL = 600       # how much of the end to examine


_DEGEN_MIN_RUN = 240    # a unit repeating over this many characters is not prose


_DEGEN_LINES = 8        # this many trailing lines that normalise to one or two distinct strings = a loop


_DEGEN_LINE_TAIL = 4000


def _degenerate_lines(chunks):
    """True when the trailing lines of the stream are one line repeated with only its list number changing. Drive
    cycle 12 (2026-10-26 02:10Z): the lead produced "26. The seam /oauth/vault/callback returned 200 ..." through
    "80. ..." in one answer; the short-cycle check below never fires on a 120-character unit."""
    tail = "".join(chunks[-80:])[-_DEGEN_LINE_TAIL:]
    lines = [re.sub(r"^\W*\d+[.)]?\s*|^[-*\u2022]\s*", "", l.strip()) for l in tail.splitlines() if l.strip()]
    lines = [l for l in lines if len(l) > 20][-_DEGEN_LINES:]
    return len(lines) >= _DEGEN_LINES and len(set(lines)) <= 2


_DEGEN_BLOCK_TAIL = 16000   # characters of the end examined for a repeating paragraph


_DEGEN_BLOCK_PROBE = 120    # the closing text that must recur for a block to count as repeating


def _degenerate_block(chunks):
    """True when the end of the stream is one PARAGRAPH said over and over: the same block, character for character,
    at least three times in a row (twice for a block over 1,500 characters). The user 2026-11-18, `defend`: the
    thinking-off retry answered "Let me try calling defend with action=respond and apply=true again ..." as a
    ~1,000-character, eleven-line block and repeated it 40+ times until Ctrl-C. Ten different lines per cycle is too
    many distinct lines for _degenerate_lines and too long a unit for the 12-character check, so neither fired."""
    tail = "".join(chunks[-4000:])[-_DEGEN_BLOCK_TAIL:]
    if len(tail) < 3 * _DEGEN_BLOCK_PROBE:
        return False
    probe = tail[-_DEGEN_BLOCK_PROBE:]
    prev = tail.rfind(probe, 0, len(tail) - 1)
    if prev < 0:
        return False
    period = len(tail) - _DEGEN_BLOCK_PROBE - prev
    if period < 60:
        return False            # a short cycle is the character check's job
    reps = 3 if period < 1500 else 2
    if reps * period > len(tail):
        return False
    unit = tail[-period:]
    if len(unit.strip()) < 40:
        return False
    return all(tail[-(k + 1) * period:-k * period] == unit for k in range(1, reps))


def _degenerate(chunks):
    """True when the end of the stream is one short string repeated past any legitimate use, one line repeated
    under changing list numbers, or one paragraph repeated whole."""
    if _degenerate_lines(chunks):
        return True
    if len(chunks) % 16 == 0 and _degenerate_block(chunks):   # every 16th chunk: the scan is a few joins
        return True
    # 600 chunks, not 40: a stream arrives a token at a time, and forty 3-character tokens are 120 characters,
    # under the 240 the check needs. `|\/var` (as "|\\", "/var") ran 21,000 tokens and five minutes uncut
    # (defense drive 2026-11-22).
    tail = "".join(chunks[-600:])[-_DEGEN_TAIL:]
    if len(tail) < _DEGEN_MIN_RUN:
        return False
    for unit in range(1, 13):          # "a", "ab", ... up to a 12-char cycle
        piece = tail[-unit:]
        if not piece.strip():
            continue
        run = 0
        while tail.endswith(piece * (run + 1)) and (run + 1) * unit <= len(tail):
            run += 1
        if run * unit >= _DEGEN_MIN_RUN:
            return True
    return False


def _think_loop(tail):
    """True when the end of a model's REASONING is one sentence said over and over: the same 8 to 400 characters,
    at least 8 times in a row and over at least 500 characters. gpt-oss at think=high ended its reasoning about
    "give one command to test nginx config" with "Provide the command. " hundreds of times, 24,000 tokens and
    seven minutes, then no answer at all (general-chat drive 2026-11-21). A 21 or 50 character sentence is too
    long for the 12-character cycle check and too short for the paragraph check, and those read the answer, not
    the reasoning. tail: the last ~2,000 characters of the reasoning."""
    tail = tail[-2000:]
    n = len(tail)
    if n < 500:
        return False
    for period in range(8, 401):
        reps = max(8, -(-500 // period))
        if reps * period > n:
            break
        unit = tail[n - period:]
        if len(unit.strip()) < 6:
            continue
        if all(tail[n - (k + 1) * period:n - k * period] == unit for k in range(1, reps)):
            return True
    return False


def _transient_cloud_error(e):
    """True for the errors a cloud endpoint recovers from by itself (F9). 429 (rate limit) and 529 (Anthropic
    "overloaded") join the 5xx: both clear with a wait, and _cloud_call honours the wait the server asks for. A
    spend-cap 429 does not clear by waiting and stays an immediate error."""
    import urllib.error
    if isinstance(e, urllib.error.HTTPError):
        if e.code == 429:
            return "enforced_spend_limit_reached" not in str(e)
        return e.code in (502, 503, 504, 529)
    if isinstance(e, (http.client.RemoteDisconnected, ConnectionResetError, ConnectionAbortedError,
                      BrokenPipeError, socket.timeout, TimeoutError, http.client.IncompleteRead)):
        return True
    if isinstance(e, urllib.error.URLError):
        r = e.reason
        return isinstance(r, (ConnectionResetError, ConnectionAbortedError, socket.timeout, TimeoutError)) \
            or "timed out" in str(r).lower()
    return bool(re.search(r"RemoteDisconnected|Remote end closed connection|Connection reset by peer|"
                          r"read operation timed out|HTTP (Error )?(50[234]|529)\b|overloaded_error", str(e)))
