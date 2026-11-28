#!/usr/bin/env python3
"""Bridge a legacy MCP SSE server to Codex's stdio MCP transport.

Burp MCP Server 1.3.0 exposes legacy SSE at GET / and accepts client
messages at the session-specific POST endpoint announced by that stream.
Current Codex CLI accepts local MCP processes over stdio, so this adapter
relays MCP SessionMessage objects in both directions without modifying them.
"""

from __future__ import annotations

import argparse
import json
import sys
from urllib.parse import urlparse

import anyio
from mcp.client.sse import sse_client
from mcp.server.stdio import stdio_server


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "url",
        nargs="?",
        default="http://127.0.0.1:9876/",
        help="legacy MCP SSE endpoint (default: %(default)s)",
    )
    parser.add_argument(
        "--selfcheck",
        action="store_true",
        help="validate dependencies and configuration without opening a socket",
    )
    return parser.parse_args()


def validate_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"invalid MCP SSE URL: {url!r}")


async def run_bridge(url: str) -> None:
    async with stdio_server() as (local_read, local_write):
        async with sse_client(url, timeout=10, sse_read_timeout=3600) as (
            remote_read,
            remote_write,
        ):
            async with anyio.create_task_group() as tasks:

                async def relay(source, destination, label: str) -> None:
                    try:
                        async for item in source:
                            if isinstance(item, Exception):
                                raise item
                            await destination.send(item)
                    except anyio.get_cancelled_exc_class():
                        raise
                    except Exception as exc:
                        print(f"burp-mcp bridge {label} failed: {exc}", file=sys.stderr)
                        raise
                    finally:
                        tasks.cancel_scope.cancel()

                tasks.start_soon(relay, local_read, remote_write, "stdio->sse")
                tasks.start_soon(relay, remote_read, local_write, "sse->stdio")


def main() -> int:
    args = parse_args()
    try:
        validate_url(args.url)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2

    if args.selfcheck:
        print(
            json.dumps(
                {
                    "ok": True,
                    "transport_in": "stdio",
                    "transport_out": "legacy-sse",
                    "url": args.url,
                },
                sort_keys=True,
            )
        )
        return 0

    try:
        anyio.run(run_bridge, args.url)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"burp-mcp bridge failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
