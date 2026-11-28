"""MCP: the mcp tool, and every configured server's tools offered to the model as native tools."""
import os
from gnoc_core.runtime import bind


def t_mcp(ctx, action="servers", server="", tool="", arguments=None, uri=""):
    """MCP servers and their tools: list, inspect a server's tool schemas, or call one tool; resources too."""
    (
        MCP_DIRTY, WS, _spill, json, web_bytes,
    ) = bind(
        "MCP_DIRTY", "WS", "_spill", "json", "web_bytes",
    )
    import gnoc_mcp
    gnoc_mcp.WS = WS
    action = str(action or "servers").strip().lower()
    try:
        if action in ("servers", "list"):
            text = gnoc_mcp.servers_text(probe_live=True)
            got = gnoc_mcp.refresh_cache()
            # the registry is swapped in at the start of the NEXT turn, on the main thread: this call runs in a
            # tool thread beside others that iterate TOOLS (QAQC 2026-11-19: "dictionary changed size")
            MCP_DIRTY[0] = True
            n = sum(v for v in got.values() if isinstance(v, int))
            return text + (f"\n{n} MCP tool(s) will be offered as native tools (mcp__<server>__<tool>) from your "
                           "next message" if n else "")
        if action in ("tools", "ls"):
            if not server:
                return "bad arguments: mcp action=tools needs server"
            text = gnoc_mcp.tools_text(str(server))
            gnoc_mcp.refresh_cache(str(server))
            MCP_DIRTY[0] = True
            return text
        if action == "resources":
            if not server:
                return "bad arguments: mcp action=resources needs server"
            conf = gnoc_mcp.servers()
            if server not in conf:
                return f"no MCP server {server!r}"
            rows = gnoc_mcp.list_resources(conf[server])
            return ("\n".join(f"  {r.get('uri')}  {r.get('name') or ''}  {r.get('mimeType') or ''}".rstrip()
                              for r in rows[:200]) or f"{server}: no resources")
        if action == "read":
            if not server or not uri:
                return "bad arguments: mcp action=read needs server and uri"
            conf = gnoc_mcp.servers()
            if server not in conf:
                return f"no MCP server {server!r}"
            # a server's bytes are someone else's text: fenced and remembered for the copy gate, like a web page
            return _spill(web_bytes(f"MCP resource {server} {uri}",
                                    gnoc_mcp.read_resource(conf[server], uri) or "(empty resource)", ctx),
                          "mcp-resource")
        if action in ("call", "run"):
            if not server or not tool:
                return "bad arguments: mcp action=call needs server and tool"
            args = arguments if isinstance(arguments, dict) else {}
            if isinstance(arguments, str) and arguments.strip():
                try:
                    args = json.loads(arguments)
                except ValueError:
                    return "bad arguments: arguments must be a JSON object"
            return _mcp_result(ctx, str(server), str(tool), gnoc_mcp.call_text(str(server), str(tool), args))
        return "bad arguments: mcp action is one of servers, tools, call, resources, read"
    except Exception as e:  # noqa: BLE001 - a broken server must never kill the turn
        return f"mcp {action} failed: {type(e).__name__}: {str(e)[:300]}"


MCP_PREFIX = "mcp__"


MCP_TOOLS_MAX = int(os.environ.get("GNOC_MCP_TOOLS_MAX") or 60)


def _mcp_name(server, tool):
    (
        MCP_PREFIX, re,
    ) = bind(
        "MCP_PREFIX", "re",
    )
    return re.sub(r"[^A-Za-z0-9_-]", "_", f"{MCP_PREFIX}{server}__{tool}")[:64]


def _mcp_result(ctx, server, tool, text):
    """A tool's answer from an MCP server, as the model must see it: the result head stays plain, the server's
    own text is fenced as untrusted, and the turn is tainted, so nothing it says runs unattended afterwards
    (QAQC 2026-11-19: MCP output reached the model bare and armed neither gate)."""
    (
        taint, web_bytes,
    ) = bind(
        "taint", "web_bytes",
    )
    head, _, body = str(text).partition("\n")
    taint(ctx, "mcp")
    return head + ("\n" + web_bytes(f"MCP {server}/{tool}", body, ctx) if body else "")


def _mcp_impl(server, tool):
    import functools

    def raw(ctx, **arguments):
        import gnoc_mcp
        (WS, _mcp_result) = bind("WS", "_mcp_result")
        gnoc_mcp.WS = WS
        return _mcp_result(ctx, server, tool,
                           gnoc_mcp.call_text(server, tool, {k: v for k, v in arguments.items() if v is not None}))

    @functools.wraps(raw)   # every registered tool is a wrapper over its implementation (the registry's contract)
    def call(ctx, **arguments):
        try:
            return raw(ctx, **arguments)
        except Exception as e:  # noqa: BLE001 - a dead server is a result, never a crash
            return f"mcp {server}/{tool} failed: {type(e).__name__}: {str(e)[:300]}"
    return call


def register_mcp_tools(refresh=False, server=None):
    """Offer every cached MCP tool to the model as a tool of its own (mcp__<server>__<tool>, the server's own
    schema), so it is called like any other tool instead of through mcp action=call with a guessed argument
    shape. refresh=True lists the servers first. Returns how many are registered. Approval: like mcp, asked
    unless /auto."""
    (
        ACTING_TOOLS, CODE_TOOLS, MCP_PREFIX, MCP_TOOLS_MAX, TOOLS, WS, _COPY_GATED, _mcp_impl, _mcp_name,
    ) = bind(
        "ACTING_TOOLS", "CODE_TOOLS", "MCP_PREFIX", "MCP_TOOLS_MAX", "TOOLS", "WS", "_COPY_GATED", "_mcp_impl",
        "_mcp_name",
    )
    import gnoc_mcp
    gnoc_mcp.WS = WS
    if refresh:
        try:
            gnoc_mcp.refresh_cache(server)
        except Exception:  # noqa: BLE001
            pass
    for n in [n for n in TOOLS if n.startswith(MCP_PREFIX)]:
        TOOLS.pop(n, None)
        CODE_TOOLS.discard(n)
        ACTING_TOOLS.discard(n)
        _COPY_GATED.pop(n, None)
    try:
        cached = gnoc_mcp.cached_tools()
    except Exception:  # noqa: BLE001
        return 0
    k = 0
    for srv, tools in sorted(cached.items()):
        for t in tools:
            if k >= MCP_TOOLS_MAX:
                break
            n = _mcp_name(srv, t["name"])
            if n in TOOLS:
                continue
            schema = {"type": "function", "function": {
                "name": n, "description": (f"[MCP server {srv}] " + str(t.get("description") or t["name"])[:700]
                                           + " (a tool of an MCP server you configured; it takes its own arguments)"),
                "parameters": t.get("inputSchema") or {"type": "object", "properties": {}}}}
            TOOLS[n] = (_mcp_impl(srv, t["name"]), schema, "unless_auto")
            _COPY_GATED[n] = tuple(((t.get("inputSchema") or {}).get("properties") or {}).keys())
            CODE_TOOLS.add(n)
            ACTING_TOOLS.add(n)
            k += 1
    return k
