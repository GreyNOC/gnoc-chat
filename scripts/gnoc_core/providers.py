"""Provider adapters: gnoc's one internal chat format in, one provider's wire out.

THE INTERNAL FORMAT is what every caller already holds, so no caller changes:
  messages  Ollama-shaped history. {"role": "system"|"user"|"assistant"|"tool", "content": str}; an assistant turn may
            carry "tool_calls": [{"id"?: str, "function": {"name": str, "arguments": dict}}]; a user turn may carry
            "images": [base64]. A tool message answers the OLDEST unanswered call of the assistant turn before it:
            the history stores no call ids on tool messages (dispatch appends {"role": "tool", "tool_name", ...}).
  tools     OpenAI-style schemas, {"type": "function", "function": {"name", "description", "parameters"}}.
  result    {"role": "assistant", "content": str, "tool_calls"?: [...the same shape...], "usage": normalize_usage()}.
            A call whose arguments did not parse carries {MALFORMED_ARGS: raw[:300]} so run_tools tells the model.

THE WIRES. "openai" (gnoc_core.llm._openai_chat: every OpenAI-compatible cloud and the split llama-server) and
"ollama" (gnoc_core.llm._ollama_chat) are the two paths that existed before this module; llm._wire_chat routes to
them unchanged. "anthropic" (Messages API) and "gemini" (generateContent) are native adapters here, because the
OpenAI-compatible shims of both providers drop what this phase is for: Anthropic's cache_control breakpoints and
thinking blocks, Gemini's thought signatures, and both providers' cache counters in the usage block.

What this module does NOT do, on purpose: no secret redaction and no privacy check. Both run in
llm._llm_chat_once BEFORE any adapter is chosen (gnoc_privacy.why_not, then gnoc_cloud.redact_messages), so a new
wire cannot be a way around them. Stdlib only (urllib), a timeout on every request, and the caller's cancel check
is read before every streamed line, exactly like the two older stream loops.
"""
import base64
import json
import re
import urllib.error
import urllib.parse
import urllib.request

WIRES = ("openai", "anthropic", "gemini")
MALFORMED_ARGS = "_malformed_json"  # the same marker gnoc_core.llm uses; run_tools reads it

# Kept on the assistant message so the NEXT request can return them unchanged (the provider checks them):
THINKING_KEY = "_thinking_blocks"   # Anthropic: signed thinking / redacted_thinking blocks of that turn
SIGNATURE_KEY = "_thought_signature"  # Gemini: the thoughtSignature of one functionCall part, on that tool call

# The API version this adapter is written against. 2026-10-21 refuses temperature/top_p/top_k on every model, which
# is why no sampling parameter is sent to Anthropic (the OpenAI path keeps its temperature 0.3).
ANTHROPIC_VERSION = "2026-10-21"
DEFAULT_MAX_TOKENS = 16000          # Anthropic requires max_tokens; a lead answer or a tool call fits easily
RETRY_AFTER_CAP = 30.0              # a server asking for longer than this is not waited out inside one call

# Adaptive thinking (Claude 4.6 and later) takes an effort word; the older "budget" style takes a token budget.
_EFFORT = {"low": "low", "medium": "medium", "high": "high"}
_BUDGET = {"low": 1024, "medium": 4096, "high": 16000, True: 4096}
_GEMINI_BUDGET = {"low": 1024, "medium": 8192, "high": 24576, True: -1}   # -1 = the model decides (dynamic)

# A context-window refusal, in each provider's words (Anthropic: "prompt is too long: 210000 tokens > 200000
# maximum"; Gemini: "The input token count (1200000) exceeds the maximum number of tokens allowed (1048576)").
_OVERFLOW = re.compile(r"prompt is too long|input token count.{0,40}exceeds|exceeds the maximum number of tokens|"
                       r"context[ _]length|context window|too many (input )?tokens", re.I)


class ContextOverflow(urllib.error.HTTPError):
    """The request is bigger than the model's window. An HTTPError (code 400) so every caller that handled the
    OpenAI path's refusal handles this one the same way; the retry loop never repeats it (same request, same
    answer). .tokens and .limit are the two numbers when the provider said them."""

    def __init__(self, url, code, msg, hdrs, tokens=None, limit=None):
        super().__init__(url, code, msg, hdrs, None)
        self.tokens, self.limit = tokens, limit


# ---------------------------------------------------------------- usage

def _int(v):
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def normalize_usage(wire, raw):
    """One shape for every provider's usage block, {} when it sent none.

    input_tokens  everything the provider read, cached reads and cache writes INCLUDED (Anthropic reports the
                  three apart, OpenAI and Gemini report the total and the cached part of it)
    cached_tokens the part of the input served from the provider's prompt cache
    cache_write_tokens  the part written to the cache this call (Anthropic only)
    output_tokens everything generated, reasoning included (Gemini reports thoughts apart)
    prompt_tokens / completion_tokens  the same two totals under the OpenAI names, which older callers read."""
    if not isinstance(raw, dict) or not raw:
        return {}
    reasoning = 0
    write = 0
    if wire == "anthropic":
        cached, write = _int(raw.get("cache_read_input_tokens")), _int(raw.get("cache_creation_input_tokens"))
        inp, out = _int(raw.get("input_tokens")) + cached + write, _int(raw.get("output_tokens"))
    elif wire == "gemini":
        inp = _int(raw.get("promptTokenCount")) + _int(raw.get("toolUsePromptTokenCount"))
        cached = _int(raw.get("cachedContentTokenCount"))
        reasoning = _int(raw.get("thoughtsTokenCount"))
        out = _int(raw.get("candidatesTokenCount")) + reasoning
    elif wire == "ollama":
        inp, out, cached = _int(raw.get("prompt_eval_count")), _int(raw.get("eval_count")), 0
    else:   # openai-compatible: prompt_tokens already includes the cached part
        inp, out = _int(raw.get("prompt_tokens")), _int(raw.get("completion_tokens"))
        det = raw.get("prompt_tokens_details") if isinstance(raw.get("prompt_tokens_details"), dict) else {}
        # OpenAI says prompt_tokens_details.cached_tokens; DeepSeek says prompt_cache_hit_tokens
        cached = _int(det.get("cached_tokens")) or _int(raw.get("prompt_cache_hit_tokens"))
        cdet = raw.get("completion_tokens_details") if isinstance(raw.get("completion_tokens_details"), dict) else {}
        reasoning = _int(cdet.get("reasoning_tokens"))
    if not (inp or out):
        return {}
    return {"wire": wire, "input_tokens": inp, "cached_tokens": cached, "cache_write_tokens": write,
            "output_tokens": out, "reasoning_tokens": reasoning, "prompt_tokens": inp, "completion_tokens": out}


def usage_tokens(u):
    """Total tokens a usage dict accounts for (input incl. cached + output); 0 when there is none."""
    if not isinstance(u, dict):
        return 0
    return _int(u.get("input_tokens", u.get("prompt_tokens"))) + _int(u.get("output_tokens",
                                                                             u.get("completion_tokens")))


def retry_after(e, cap=RETRY_AFTER_CAP):
    """Seconds the provider asked us to wait (Retry-After header, or Gemini's RetryInfo retryDelay in the body),
    capped; None when it said nothing."""
    hdrs = getattr(e, "headers", None)
    v = None
    try:
        # an HTTPError carries an email.message.Message (case-insensitive); a plain dict is not
        v = (hdrs.get("retry-after") or hdrs.get("Retry-After")) if hdrs is not None else None
    except Exception:  # noqa: BLE001 - a headers object of an odd type is "no header"
        v = None
    if v:
        try:
            return min(float(cap), max(0.0, float(str(v).strip())))
        except ValueError:
            pass   # an HTTP-date Retry-After: the caller's own backoff applies
    m = re.search(r'"retryDelay"\s*:\s*"(\d+(?:\.\d+)?)s"', str(e))
    return min(float(cap), float(m.group(1))) if m else None


def spend_capped(e):
    """True for a 429 that waiting does not cure: Anthropic's monthly spend cap. Retrying it only delays the error."""
    return "enforced_spend_limit_reached" in str(e)


# ---------------------------------------------------------------- shared plumbing

def _mime(b64):
    head = (b64 or "")[:16]
    for sig, mime in (("iVBOR", "image/png"), ("/9j/", "image/jpeg"), ("R0lG", "image/gif"), ("UklG", "image/webp")):
        if head.startswith(sig):
            return mime
    return "image/png"


def _images(m):
    """(mime, base64) for each image of a user turn; a data: URL prefix is stripped, garbage is skipped."""
    out = []
    for im in m.get("images") or []:
        s = str(im or "")
        if s.startswith("data:") and "," in s:
            s = s.split(",", 1)[1]
        try:
            base64.b64decode(s[:64] + "=" * (-len(s[:64]) % 4), validate=False)
        except (ValueError, TypeError):
            continue
        if s:
            out.append((_mime(s), s))
    return out


def _text(v):
    return v if isinstance(v, str) else ("" if v is None else str(v))


def _args(a):
    """Tool-call arguments as a dict for the wire: the history keeps a dict; a string is parsed, anything else
    (or a string that is not a JSON object) is carried under the malformed marker so it is not lost."""
    if isinstance(a, dict):
        return a
    if isinstance(a, str):
        try:
            d = json.loads(a or "{}")
        except ValueError:
            return {MALFORMED_ARGS: a[:300]}
        return d if isinstance(d, dict) else {MALFORMED_ARGS: a[:300]}
    return {} if a is None else {MALFORMED_ARGS: str(a)[:300]}


def _parse_args(raw):
    """A streamed arguments string -> dict, or the malformed marker (the same rule as the OpenAI path)."""
    try:
        d = json.loads(raw or "{}")
    except ValueError:
        return {MALFORMED_ARGS: (raw or "")[:300]}
    return d if isinstance(d, dict) else {MALFORMED_ARGS: (raw or "")[:300]}


def _fn(t):
    return (t.get("function") if isinstance(t.get("function"), dict) else t) if isinstance(t, dict) else {}


def open_stream(url, body, headers, timeout):
    """POST body and return the open response. An HTTP error is read (the provider's REASON is the useful part),
    closed, and re-raised as the same HTTPError the OpenAI path raises, or as ContextOverflow for a window refusal."""
    req = urllib.request.Request(url, json.dumps(body).encode(), dict(headers or {}), method="POST")
    try:
        return urllib.request.urlopen(req, timeout=float(timeout))
    except urllib.error.HTTPError as e:
        with e:
            detail = e.read(4000).decode("utf-8", "replace").strip()
        if e.code in (400, 413) and _OVERFLOW.search(detail):
            nums = [int(n) for n in re.findall(r"\d{3,}", detail)[:2]]
            raise ContextOverflow(e.url, e.code, f"{e.reason}: context length exceeded: {detail[:600]}", e.headers,
                                  tokens=nums[0] if nums else None,
                                  limit=nums[1] if len(nums) > 1 else None) from None
        raise urllib.error.HTTPError(e.url, e.code, f"{e.reason}: {detail[:800]}" if detail else e.reason, e.headers,
                                     None) from None


def sse_events(resp, cancelled):
    """(event, data) for each Server-Sent Event; stops early, quietly, when cancelled() turns true (Ctrl-C or this
    worker's cancel event), which is checked before every line like the older stream loops do."""
    event, data = "", []
    for raw in resp:
        if cancelled():
            return
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        if not line:
            if data:
                yield event, "\n".join(data)
            event, data = "", []
            continue
        if line.startswith(":"):
            continue   # an SSE comment (keep-alive)
        field, _, val = line.partition(":")
        val = val[1:] if val.startswith(" ") else val
        if field == "event":
            event = val
        elif field == "data":
            data.append(val)
    if data:
        yield event, "\n".join(data)


def _chunk(wire, data):
    try:
        return json.loads(data)
    except ValueError:
        raise RuntimeError(f"{wire}: the provider sent a malformed stream chunk: {data[:80]!r}") from None


def _push(out, role, parts, key):
    """Append a turn, merging into the previous one of the same role (both APIs want the roles to alternate)."""
    if out and out[-1]["role"] == role:
        out[-1][key].extend(parts)
    else:
        out.append({"role": role, key: list(parts)})


class Adapter:
    """The interface: chat(messages, tools, url=, model=, headers=, ...) -> the result dict described above.
    build() is separate so the request body can be tested without a socket."""
    wire = ""

    def build(self, messages, tools, model, num_predict=None, think=None, style="adaptive"):
        raise NotImplementedError

    def chat(self, messages, tools, *, url, model, headers, on_text=None, on_think=None, num_predict=None,
             think=None, timeout=360.0, cancelled=lambda: False, tick=lambda: None, style="adaptive"):
        raise NotImplementedError


# ---------------------------------------------------------------- Anthropic Messages

def _tool_id(cid, i, j):
    # Anthropic ids must match ^[a-zA-Z0-9_-]+$; an OpenAI-style "call_..." passes, anything else is cleaned
    s = re.sub(r"[^A-Za-z0-9_-]", "_", str(cid or ""))[:64]
    return s or f"toolu_gnoc_{i}_{j}"


def anthropic_messages(messages):
    """(system_text, messages) in Messages-API shape. Leading system turns become the system prompt; a later one
    becomes a user note (the same rule _ensure_user_turn applies). A tool_use with no result after it (a turn that
    was interrupted) gets a "not run" result, because the API refuses an unanswered tool_use."""
    system, out, pending = [], [], []

    def flush():
        if pending:
            _push(out, "user", [{"type": "tool_result", "tool_use_id": cid, "content": "(not run)",
                                 "is_error": True} for cid in pending], "content")
            del pending[:]

    for i, m in enumerate(messages or []):
        if not isinstance(m, dict):
            continue
        role, text = m.get("role"), _text(m.get("content"))
        if role == "tool":
            if pending:
                _push(out, "user", [{"type": "tool_result", "tool_use_id": pending.pop(0),
                                     "content": text or "(no output)"}], "content")
            else:   # a result with no call to pair with: keep its words rather than drop them
                _push(out, "user", [{"type": "text", "text": "[tool result] " + (text or "(no output)")}], "content")
            continue
        flush()
        if role == "system":
            if not out:
                if text.strip():
                    system.append(text)
                continue
            role, text = "user", "[system note] " + text
        if role == "assistant":
            blocks = [dict(b) for b in (m.get(THINKING_KEY) or []) if isinstance(b, dict)
                      and b.get("type") in ("thinking", "redacted_thinking")]
            if text.strip():
                blocks.append({"type": "text", "text": text})
            ids = []
            for j, c in enumerate(m.get("tool_calls") or []):
                if not isinstance(c, dict):
                    continue
                fn = c.get("function") if isinstance(c.get("function"), dict) else {}
                cid = _tool_id(c.get("id"), i, j)
                blocks.append({"type": "tool_use", "id": cid, "name": str(fn.get("name") or "tool"),
                               "input": _args(fn.get("arguments"))})
                ids.append(cid)
            if not any(b["type"] in ("text", "tool_use") for b in blocks):
                continue   # an empty assistant turn: the API refuses an empty text block, and thinking alone is no turn
            _push(out, "assistant", blocks, "content")
            pending[:] = ids
            continue
        blocks = [{"type": "image", "source": {"type": "base64", "media_type": mt, "data": d}}
                  for mt, d in _images(m)]
        if text.strip() or not blocks:
            blocks.append({"type": "text", "text": text if text.strip() else "(empty message)"})
        _push(out, "user", blocks, "content")
    flush()
    if not out or out[0]["role"] != "user":
        out.insert(0, {"role": "user", "content": [{"type": "text", "text": "Continue the current task."}]})
    if out[-1]["role"] != "user":
        # an assistant turn last would be a prefill, which current models refuse with a 400
        out.append({"role": "user", "content": [{"type": "text", "text": "Continue the current task."}]})
    return "\n\n".join(system), out


def anthropic_tools(tools):
    out = []
    for t in tools or []:
        fn = _fn(t)
        if not fn.get("name"):
            continue
        schema = fn.get("parameters") if isinstance(fn.get("parameters"), dict) else {}
        schema = dict(schema) or {"type": "object", "properties": {}}
        schema.setdefault("type", "object")
        out.append({"name": str(fn["name"]), "description": str(fn.get("description") or ""), "input_schema": schema})
    return out


_CACHEABLE = ("text", "tool_result", "tool_use", "image")


def cache_breakpoints(body):
    """Mark the stable prefix for Anthropic's prompt cache. Render order is tools, system, messages, and a breakpoint
    caches everything up to it, so: the last tool schema, the system prompt, and the last block of the two newest
    user turns. The newest one is what the NEXT call of this tool loop (this request plus the answer plus its tool
    results) reads back; the one before it still hits when the newest block lies past the API's 20-block lookback.
    Four breakpoints is the API maximum. A prefix under the model's minimum is simply not cached (no error)."""
    cc = {"type": "ephemeral"}
    if body.get("tools"):
        body["tools"][-1]["cache_control"] = dict(cc)
    if body.get("system"):
        body["system"][-1]["cache_control"] = dict(cc)
    marked = 0
    for m in reversed(body.get("messages") or []):
        if m.get("role") != "user":
            continue
        for b in reversed(m["content"]):
            if b.get("type") in _CACHEABLE:
                b["cache_control"] = dict(cc)
                marked += 1
                break
        if marked >= 2:
            break
    return body


class AnthropicAdapter(Adapter):
    wire = "anthropic"

    def build(self, messages, tools, model, num_predict=None, think=None, style="adaptive"):
        system, msgs = anthropic_messages(messages)
        body = {"model": model, "max_tokens": int(num_predict or DEFAULT_MAX_TOKENS), "messages": msgs,
                "stream": True}
        if system:
            body["system"] = [{"type": "text", "text": system}]
        at = anthropic_tools(tools)
        if at:
            body["tools"] = at
        if think and style != "off":
            if style == "budget":
                # pre-4.6 models: an explicit budget below max_tokens. With tool use, the turn that made the calls must
                # start with its signed thinking block; a history from another model has none, so thinking stays off.
                last = next((m for m in reversed(msgs) if m["role"] == "assistant"), None)
                if not (last and any(b["type"] == "tool_use" for b in last["content"])
                        and not any(b["type"] in ("thinking", "redacted_thinking") for b in last["content"])):
                    budget = _BUDGET.get(think, _BUDGET[True])
                    body["thinking"] = {"type": "enabled", "budget_tokens": budget}
                    body["max_tokens"] = max(body["max_tokens"], budget + 1024)
            else:
                # adaptive thinking; "summarized" so the reasoning shows in the thinking block (the default on current
                # models is "omitted": empty text, which looks like a long silent pause)
                body["thinking"] = {"type": "adaptive", "display": "summarized"}
                if think in _EFFORT:
                    body["output_config"] = {"effort": _EFFORT[think]}
        return cache_breakpoints(body)

    def chat(self, messages, tools, *, url, model, headers, on_text=None, on_think=None, num_predict=None,
             think=None, timeout=360.0, cancelled=lambda: False, tick=lambda: None, style="adaptive"):
        body = self.build(messages, tools, model, num_predict, think, style)
        blocks, order, usage = {}, [], {}
        content, stop, thinking = [], None, False
        with open_stream(url, body, headers, timeout) as resp:
            for event, data in sse_events(resp, cancelled):
                d = _chunk("anthropic", data)
                kind = d.get("type") or event
                if kind == "ping":
                    continue
                tick()
                if kind == "error":
                    err = d.get("error") if isinstance(d.get("error"), dict) else {}
                    raise RuntimeError(f"anthropic: the model server reported an error mid-stream: "
                                       f"{err.get('type', '')} {str(err.get('message') or d)[:300]}")
                if kind == "message_start":
                    usage.update((d.get("message") or {}).get("usage") or {})
                elif kind == "content_block_start":
                    idx = d.get("index", len(order))
                    cb = dict(d.get("content_block") or {})
                    if cb.get("type") == "text":
                        cb.setdefault("text", "")
                    elif cb.get("type") == "tool_use":
                        cb["json"] = ""
                    blocks[idx] = cb
                    order.append(idx)
                elif kind == "content_block_delta":
                    b = blocks.setdefault(d.get("index", 0), {"type": "text", "text": ""})
                    delta = d.get("delta") or {}
                    dt = delta.get("type")
                    if dt == "text_delta" and delta.get("text"):
                        b["text"] = b.get("text", "") + delta["text"]
                        content.append(delta["text"])
                        if on_text:
                            on_text(delta["text"])
                    elif dt == "thinking_delta" and delta.get("thinking"):
                        b["thinking"] = b.get("thinking", "") + delta["thinking"]
                        if not thinking and on_text:
                            thinking = True
                            on_text(None)
                        if on_think:
                            on_think(delta["thinking"])
                    elif dt == "signature_delta":
                        b["signature"] = delta.get("signature") or ""
                    elif dt == "input_json_delta":
                        b["json"] = b.get("json", "") + (delta.get("partial_json") or "")
                elif kind == "message_delta":
                    stop = (d.get("delta") or {}).get("stop_reason") or stop
                    usage.update(d.get("usage") or {})
                elif kind == "message_stop":
                    break
        out = {"role": "assistant", "content": "".join(content)}
        calls, kept = [], []
        for idx in sorted(blocks):
            b = blocks[idx]
            if b.get("type") == "tool_use":
                args = _parse_args(b["json"]) if b.get("json") else (b.get("input") if isinstance(b.get("input"),
                                                                                                  dict) else {})
                calls.append({"id": b.get("id"), "function": {"name": b.get("name") or "", "arguments": args}})
            elif b.get("type") == "thinking" and b.get("signature"):
                kept.append({"type": "thinking", "thinking": b.get("thinking", ""), "signature": b["signature"]})
            elif b.get("type") == "redacted_thinking" and b.get("data"):
                kept.append({"type": "redacted_thinking", "data": b["data"]})
        if calls:
            out["tool_calls"] = calls
        if kept:
            out[THINKING_KEY] = kept   # returned unchanged on the next request; signed, so never edited or redacted
        if stop == "refusal" and not out["content"] and not calls:
            out["content"] = "(the provider declined to answer this request)"
        out["usage"] = normalize_usage("anthropic", usage)
        return out


# ---------------------------------------------------------------- Gemini generateContent

_GEMINI_KEYS = {"type", "format", "description", "nullable", "enum", "properties", "required", "items", "minItems",
                "maxItems", "minimum", "maximum", "anyOf", "title", "minLength", "maxLength", "pattern", "default",
                "minProperties", "maxProperties", "propertyOrdering"}


def gemini_schema(s):
    """A JSON Schema reduced to the OpenAPI subset Gemini's FunctionDeclaration.parameters accepts: unknown keys
    (additionalProperties, $schema, examples) are dropped, a ["x", "null"] type becomes x + nullable, types are
    upper-case enum names."""
    if not isinstance(s, dict):
        return {"type": "STRING"}
    out = {}
    t = s.get("type")
    if isinstance(t, list):
        if "null" in t:
            out["nullable"] = True
        t = next((x for x in t if x != "null"), "string")
    if t:
        out["type"] = str(t).upper()
    for k, v in s.items():
        if k == "type" or k not in _GEMINI_KEYS:
            continue
        if k == "properties" and isinstance(v, dict):
            out[k] = {str(n): gemini_schema(p) for n, p in v.items()}
        elif k == "items":
            out[k] = gemini_schema(v)
        elif k == "anyOf" and isinstance(v, list):
            out[k] = [gemini_schema(x) for x in v]
        elif k == "enum" and isinstance(v, list):
            if out.get("type", "STRING") == "STRING":
                out[k] = [str(x) for x in v]
        else:
            out[k] = v
    if "type" not in out and "properties" in out:
        out["type"] = "OBJECT"
    if isinstance(out.get("required"), list):
        props = out.get("properties") or {}
        out["required"] = [r for r in out["required"] if r in props]
    return out


def gemini_tools(tools):
    decls = []
    for t in tools or []:
        fn = _fn(t)
        if not fn.get("name"):
            continue
        d = {"name": str(fn["name"]), "description": str(fn.get("description") or "")}
        params = fn.get("parameters") if isinstance(fn.get("parameters"), dict) else {}
        if params.get("properties"):
            # an OBJECT with no properties is refused, so a no-argument tool declares no parameters at all
            d["parameters"] = gemini_schema(params)
        decls.append(d)
    return [{"functionDeclarations": decls}] if decls else []


def gemini_contents(messages):
    """(system_text, contents) in generateContent shape: role user|model, parts. A functionResponse is named after
    the call it answers; an unanswered call gets a "not run" response (Gemini requires one response per call)."""
    system, out, pending = [], [], []

    def flush():
        if pending:
            _push(out, "user", [{"functionResponse": {"name": n, "response": {"result": "(not run)"}}}
                                for n in pending], "parts")
            del pending[:]

    for m in messages or []:
        if not isinstance(m, dict):
            continue
        role, text = m.get("role"), _text(m.get("content"))
        if role == "tool":
            name = pending.pop(0) if pending else str(m.get("tool_name") or "tool")
            _push(out, "user", [{"functionResponse": {"name": name, "response": {"result": text}}}], "parts")
            continue
        flush()
        if role == "system":
            if not out:
                if text.strip():
                    system.append(text)
                continue
            role, text = "user", "[system note] " + text
        if role == "assistant":
            parts, names = [], []
            if text.strip():
                parts.append({"text": text})
            for c in m.get("tool_calls") or []:
                if not isinstance(c, dict):
                    continue
                fn = c.get("function") if isinstance(c.get("function"), dict) else {}
                part = {"functionCall": {"name": str(fn.get("name") or "tool"), "args": _args(fn.get("arguments"))}}
                if c.get(SIGNATURE_KEY):
                    part["thoughtSignature"] = c[SIGNATURE_KEY]   # returned on the part it came with
                parts.append(part)
                names.append(part["functionCall"]["name"])
            if parts:
                _push(out, "model", parts, "parts")
                pending[:] = names
            continue
        parts = [{"inlineData": {"mimeType": mt, "data": d}} for mt, d in _images(m)]
        if text.strip() or not parts:
            parts.append({"text": text if text.strip() else "(empty message)"})
        _push(out, "user", parts, "parts")
    flush()
    if not out or out[0]["role"] != "user":
        out.insert(0, {"role": "user", "parts": [{"text": "Continue the current task."}]})
    return "\n\n".join(system), out


def gemini_url(base, model, stream=True):
    """The generateContent URL for a base (https://generativelanguage.googleapis.com, or one already ending in
    /v1beta or /v1, or a full ...:streamGenerateContent URL a gateway documents)."""
    base = str(base or "").rstrip("/")
    if ":streamGenerateContent" in base or ":generateContent" in base:
        return base
    m = urllib.parse.quote(str(model or "").split("models/")[-1], safe="-._")
    if not re.search(r"/v1(beta\d*|alpha)?$", base):
        base += "/v1beta"
    return f"{base}/models/{m}:" + ("streamGenerateContent?alt=sse" if stream else "generateContent")


_MALFORMED_CALL_NAME = re.compile(r"default_api\.([A-Za-z_][\w-]*)|call:\s*([A-Za-z_][\w-]*)")


class GeminiAdapter(Adapter):
    """Caching: Gemini 2.5 models cache a repeated prompt prefix IMPLICITLY and report the hit as
    cachedContentTokenCount, which is recorded. Explicit cachedContents are not created: they are a separate
    resource with a TTL, a storage charge and a minimum size, which would mean server-side state that outlives the
    chat and has to be cleaned up; the request is instead built in a fixed order (system instruction, tools,
    contents) so the implicit cache can hit on every step of a tool loop."""
    wire = "gemini"

    def build(self, messages, tools, model, num_predict=None, think=None, style="adaptive"):
        system, contents = gemini_contents(messages)
        body = {"contents": contents}
        if system:
            body["systemInstruction"] = {"parts": [{"text": system}]}
        gt = gemini_tools(tools)
        if gt:
            body["tools"] = gt
        cfg = {"temperature": 0.3}
        if num_predict:
            cfg["maxOutputTokens"] = int(num_predict)
        if think and style != "off":
            cfg["thinkingConfig"] = {"includeThoughts": True, "thinkingBudget": _GEMINI_BUDGET.get(think, -1)}
        body["generationConfig"] = cfg
        return body

    def chat(self, messages, tools, *, url, model, headers, on_text=None, on_think=None, num_predict=None,
             think=None, timeout=360.0, cancelled=lambda: False, tick=lambda: None, style="adaptive"):
        body = self.build(messages, tools, model, num_predict, think, style)
        content, calls, usage = [], [], {}
        finish, finish_msg, blocked, thinking = None, "", None, False
        with open_stream(url, body, headers, timeout) as resp:
            for _event, data in sse_events(resp, cancelled):
                d = _chunk("gemini", data)
                tick()
                if isinstance(d, dict) and d.get("error"):
                    err = d["error"] if isinstance(d["error"], dict) else {"message": d["error"]}
                    raise RuntimeError(f"gemini: the model server reported an error mid-stream: "
                                       f"{err.get('status', '')} {str(err.get('message'))[:300]}")
                if not isinstance(d, dict):
                    continue
                if isinstance(d.get("usageMetadata"), dict):
                    usage = d["usageMetadata"]   # each chunk carries the running total; the last one is final
                blocked = (d.get("promptFeedback") or {}).get("blockReason") or blocked
                for cand in (d.get("candidates") or [])[:1]:
                    for part in ((cand.get("content") or {}).get("parts") or []):
                        if not isinstance(part, dict):
                            continue
                        if isinstance(part.get("functionCall"), dict):
                            calls.append(part)
                        elif part.get("thought") and isinstance(part.get("text"), str):
                            if not thinking and on_text:
                                thinking = True
                                on_text(None)
                            if on_think:
                                on_think(part["text"])
                        elif isinstance(part.get("text"), str) and part["text"]:
                            content.append(part["text"])
                            if on_text:
                                on_text(part["text"])
                    if cand.get("finishReason"):
                        finish = cand["finishReason"]
                        finish_msg = str(cand.get("finishMessage") or "")
        out = {"role": "assistant", "content": "".join(content)}
        tool_calls = []
        for k, part in enumerate(calls):
            fc = part["functionCall"]
            a = fc.get("args")
            args = a if isinstance(a, dict) else (_parse_args(a) if isinstance(a, str) else
                                                   ({} if a is None else {MALFORMED_ARGS: str(a)[:300]}))
            call = {"id": fc.get("id") or f"call_gemini_{k}", "function": {"name": str(fc.get("name") or ""),
                                                                            "arguments": args}}
            if part.get("thoughtSignature"):
                call[SIGNATURE_KEY] = part["thoughtSignature"]
            tool_calls.append(call)
        if finish == "MALFORMED_FUNCTION_CALL":
            # Gemini caught the call itself not parsing and sends only its text: hand it to run_tools as a malformed
            # call, which tells the model to send it again, instead of ending the turn with nothing
            # "Malformed function call: print(default_api.read_file(path=src/))": the tool is after default_api.
            hits = [m.group(1) or m.group(2) for m in _MALFORMED_CALL_NAME.finditer(finish_msg)]
            name = next((h for h in hits if h != "print"), hits[0] if hits else "unknown_tool")
            tool_calls.append({"id": f"call_gemini_{len(tool_calls)}",
                               "function": {"name": name,
                                            "arguments": {MALFORMED_ARGS: finish_msg[:300] or "(no text)"}}})
        if tool_calls:
            out["tool_calls"] = tool_calls
        if not out["content"] and not tool_calls and (blocked or finish in ("SAFETY", "PROHIBITED_CONTENT",
                                                                              "BLOCKLIST", "RECITATION", "SPII")):
            out["content"] = f"(the provider declined to answer this request: {blocked or finish})"
        out["usage"] = normalize_usage("gemini", usage)
        return out


ADAPTERS = {"anthropic": AnthropicAdapter(), "gemini": GeminiAdapter()}


# ---------------------------------------------------------------- OpenAI-compatible hosts that differ
# Each host's documented departures from the plain chat-completions body. OpenAI's GPT-5 and o-series models reject
# max_tokens (they take max_completion_tokens) and any temperature but the default; Mistral's API rejects fields it
# does not define, stream_options among them. Matched on the URL's host, so a proxy in front keeps its own shape.
OPENAI_HOST_QUIRKS = {
    "app.example.com": {"max_tokens_as": "max_completion_tokens", "drop": ("temperature",)},
    "api.mistral.ai": {"drop": ("stream_options",)},
}


def openai_fixups(url, body):
    """body adjusted for the host the OpenAI-shaped request goes to (a new dict; the caller's is not changed)."""
    import urllib.parse
    host = (urllib.parse.urlsplit(str(url or "")).hostname or "").lower()
    q = OPENAI_HOST_QUIRKS.get(host)
    if not q:
        return body
    out = {k: v for k, v in body.items() if k not in q.get("drop", ())}
    new = q.get("max_tokens_as")
    if new and "max_tokens" in out:
        out[new] = out.pop("max_tokens")
    return out


# ---------------------------------------------------------------- the one-shot key check (/cloud <name> check)

def check_request(wire, url, model):
    """(url, body) of the smallest non-streaming request that proves a key works."""
    if wire == "anthropic":
        return url, {"model": model, "max_tokens": 16, "messages": [{"role": "user", "content": "reply with OK"}]}
    if wire == "gemini":
        return (url.replace(":streamGenerateContent?alt=sse", ":generateContent"),
                {"contents": [{"role": "user", "parts": [{"text": "reply with OK"}]}],
                 "generationConfig": {"maxOutputTokens": 16}})
    # 64, not 5: a reasoning model (gpt-5, deepseek-reasoner, grok-4) spends its first tokens thinking and a 5-token
    # cap came back empty, which read as a broken key
    return url, openai_fixups(url, {"model": model, "messages": [{"role": "user", "content": "reply with OK"}],
                                    "max_tokens": 64, "stream": False})


def check_text(wire, d):
    """The answer text of a check_request response."""
    if not isinstance(d, dict):
        return ""
    if wire == "anthropic":
        return "".join(b.get("text", "") for b in d.get("content") or [] if isinstance(b, dict)).strip()
    if wire == "gemini":
        cand = (d.get("candidates") or [{}])[0] or {}
        return "".join(p.get("text", "") for p in (cand.get("content") or {}).get("parts") or []
                       if isinstance(p, dict) and not p.get("thought")).strip()
    return (((d.get("choices") or [{}])[0].get("message") or {}).get("content") or "").strip()
