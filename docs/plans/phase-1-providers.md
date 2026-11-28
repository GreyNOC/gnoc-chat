# Phase 1: native providers, prompt caching, real usage

## Plan

- Add `gnoc_core/providers.py`: one adapter interface (gnoc's Ollama-shaped history and OpenAI-style tool
  schemas in, an Ollama-shaped assistant message with a normalized `usage` out). The OpenAI-compatible call
  (`_openai_chat`) and the Ollama call (the body of `_llm_chat_once`, moved verbatim into `_ollama_chat`)
  are registered as adapters unchanged; Anthropic Messages and Gemini `streamGenerateContent` are new native
  adapters (stdlib `urllib`, SSE parsing, timeouts, the existing cancel checks).
- Native adapters: tool use with a tool-result round trip, streaming text and reasoning, extended thinking
  (Anthropic adaptive thinking with thinking blocks kept for the tool loop; Gemini `thinkingConfig` with
  thought signatures kept on the call), and prompt caching (Anthropic `cache_control` breakpoints on the tool
  schemas, the system prompt and the newest message; Gemini implicit caching, recorded from
  `cachedContentTokenCount`).
- Fix the billing bug from the audit: `_openai_chat` now returns its `usage`; every adapter's usage is
  normalized (input incl. cached, cached reads, cache writes, output) and the economy and `/usage` are fed the
  real numbers; characters/4 stays only as the fallback when a provider sends none.
- `gnoc_cloud`: builtin `anthropic` and `gemini` providers plus a `wire` field on custom providers
  (`openai` default, so every existing config is unchanged); same key storage (`secrets.env` /
  `cloud-providers.json`, chmod 600); the privacy switch and `redact_messages` run before any adapter.
  429 (with `Retry-After` / Gemini `retryDelay`) and 529 join the transient errors the cloud retry covers.
- Tests in `scripts/test_gnoc_phase1_providers.py` against an in-process HTTP server serving hand-built
  fixtures (`scripts/fixtures/providers/`), per adapter: text, tool call, tool-result round trip, stream
  cancel, 429 then retry, context overflow, malformed tool JSON; plus redaction, kill-switch and the
  usage-billing regression.

## What was built

- `scripts/gnoc_core/providers.py` (new): the adapter interface, `normalize_usage`, `retry_after`,
  `ContextOverflow`, and the native `AnthropicAdapter` and `GeminiAdapter` (request builders kept separate from
  the stream loop so bodies are testable without a socket).
- `gnoc_core/llm.py`: `_wire_chat` is the seam for cloud providers ("openai" calls `_openai_chat` exactly as
  before; "anthropic"/"gemini" go to the native adapters); the Ollama branch of `_llm_chat_once` moved verbatim
  into `_ollama_chat`; `_openai_chat` now returns its usage; every path takes the usage off the message
  (`last_usage()` keeps it per thread) so it never joins a saved history, and the economy is billed
  `input + output` from it, characters/4 only when a provider sends none. `_cloud_call` waits the
  `Retry-After` / `retryDelay` a 429 asks for (never less than the backoff, at most 30 s; Ctrl-C still cuts the
  wait short).
- `gnoc_core/llmwire.py`: 429 (except Anthropic's spend cap) and 529 / a mid-stream `overloaded_error` are
  transient for the cloud retry.
- `gnoc_cloud.py`: builtin `anthropic` (`ANTHROPIC_API_KEY`, `claude-sonnet-5-5`) and `gemini`
  (`GEMINI_API_KEY`, `gemini-2.5-flash`); `wire_for`, `thinking_style`; a `wire` (and optional `thinking`:
  adaptive | budget | off) field on custom providers, absent = openai; per-wire URL and auth header (the key is
  never put in a URL); `check()` speaks each wire. `/cloud add ... wire=anthropic|gemini`.
- `gnoc_monitor.record(..., cached=)` and `/usage` show cached input tokens.
- Thinking: Anthropic uses adaptive thinking (`{"type": "adaptive", "display": "summarized"}`, effort from
  the dial) and returns the signed thinking blocks unchanged on the next request (kept on the message under
  `_thinking_blocks`); the older `budget_tokens` style is opt-in per custom provider. Gemini uses
  `thinkingConfig` and returns each call's `thoughtSignature` on its part. No sampling parameters go to
  Anthropic (API version 2026-10-21 refuses them).
- Gemini caching: implicit caching only, recorded from `cachedContentTokenCount`. Explicit `cachedContents`
  were not built: they are a server-side resource with a TTL, a storage charge and a minimum size, which would
  leave state outliving the chat to clean up; the request is built in a fixed order so the implicit cache hits.
- Fixtures in `scripts/fixtures/providers/` are hand-built to each provider's documented shapes (Anthropic
  Messages streaming events incl. `thinking_delta`, `signature_delta`, `input_json_delta` and the cache usage
  fields; Gemini `streamGenerateContent?alt=sse` chunks with `functionCall`, `thoughtSignature`,
  `cachedContentTokenCount`, `thoughtsTokenCount`, `MALFORMED_FUNCTION_CALL`; OpenAI chat-completion chunks),
  not captured from a live account.
- Tests: `scripts/test_gnoc_phase1_providers.py`, 52 tests. The billing regression
  (`UsageIsBilledNotEstimated`) fails on the old code (verified by reverting the one line).

## Security impact

No gate was loosened. The privacy kill-switch and `redact_messages` still run in `_llm_chat_once` before the
wire is chosen, so both native adapters only ever see the redacted copy (tested per wire: a registered secret in
content, tool-call arguments and tool results never reaches the fake server; with cloud off, zero requests are
made). Keys use the existing store (`secrets.env` for builtins, `cloud-providers.json` for custom, chmod 600)
and travel only in a header. New surface: two builtin provider names; a key for them must still be set and the
lead switched with `/cloud <name> on`, so nothing is sent without the user asking. Signed thinking blocks and
thought signatures are returned to the provider that produced them, unredacted, because the signature covers
them; they originate from that provider's own output on redacted input.

## Rollback

Revert the phase commits. Saved sessions stay readable: the extra `_thinking_blocks` / `_thought_signature`
keys are ignored by the other wires. The reverted code ignores a custom provider's `wire` field, so an entry
added with `wire=anthropic|gemini` is then called as an OpenAI-compatible endpoint and fails until it is removed
with `/cloud rm <name>`; keys in `secrets.env` are left as they are.

## What is left

- Cloud hosts still get the 16k default context window from `ctx_for`, so long chats are compacted early, which
  also rewrites the cached prefix. Per-provider windows belong with Phase 2 (compaction).
- The Anthropic model-specific thinking rules (Opus 5.5 cannot turn thinking off; Sonnet 5.5 turns it off with
  `between_tools`) are handled by omitting `thinking` when thinking is off; the model's default then applies.
- Refusal fallbacks (`fallbacks` beta), Anthropic message threads and Gemini explicit caches are not used.

## Release note

gnoc chat now talks to Anthropic (Claude) and Google Gemini natively: `/cloud anthropic api <key>` then
`/cloud anthropic on`, or the same with `gemini`. Both stream text and reasoning, run tools, and use the
provider's prompt cache, and a gateway in front of either is added with `wire=anthropic|gemini` on
`/cloud add`. `/usage` and the usage accounting now record the tokens each provider actually reports, cached
tokens included; before this, cloud calls were estimated from message length. A rate-limited provider is
retried after the wait it asks for. Secret scrubbing and the `/privacy` cloud switch cover the new providers
exactly as they cover the others. Development: GreyNOC (Brad), with Claude (Anthropic) as a development contributor.
