"""Official MCP v1 low-level Server/stdio entry point; no listening sockets."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from pathlib import Path
import sys

import anyio
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp import types

from .config import Config
from .service import Observer, SPECS
from .security import MAX_INPUT_FRAME


class BoundedInput:
    """Bound the SDK's input iterator; leave all MCP parsing to the SDK."""

    def __init__(self, stream):
        self.stream = stream

    def __aiter__(self):
        return self

    async def __anext__(self):
        raw = await anyio.to_thread.run_sync(self.stream.readline, MAX_INPUT_FRAME + 1)
        if not raw:
            raise StopAsyncIteration
        if len(raw) > MAX_INPUT_FRAME or not raw.endswith(b"\n"):
            # Stop rather than buffer or log a potentially secret oversized frame.
            raise ValueError("input_frame_limit_or_incomplete")
        return raw.decode("utf-8", "replace")


async def serve(observer):
    server = Server("local-readonly-observer", version="0.3.3")

    @server.list_tools()
    async def list_tools():
        return [types.Tool(name=name, description=description, inputSchema=schema,
                           annotations=types.ToolAnnotations(readOnlyHint=True, destructiveHint=False,
                                                             idempotentHint=True, openWorldHint=False))
                for name, (description, schema) in SPECS.items()]

    @server.call_tool(validate_input=False)
    async def call_tool(name, arguments):
        # Never let SDK validation errors stringify untrusted input.
        result = observer.call(name, arguments)
        return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(result, ensure_ascii=True, separators=(",", ":")))],
                                    isError=not result.get("ok", False))

    async with stdio_server(stdin=BoundedInput(sys.stdin.buffer)) as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main():
    parser = argparse.ArgumentParser(description="Local read-only stdio observer")
    parser.add_argument("--config", default="observer.example.json", help="Project-relative operator configuration")
    parser.add_argument("--approved-sources", action="store_true", help="Load only the fixed local operator approval registry")
    args = parser.parse_args()
    # SDK logs are disabled: they can include unknown tool names or invalid input.
    logging.disable(logging.CRITICAL)
    config = None
    try:
        config = Config.load(Path.cwd(), args.config, approved_sources=args.approved_sources)
        asyncio.run(serve(Observer(config)))
    except (Exception, KeyboardInterrupt):
        print("observer: startup_or_transport_failure", file=sys.stderr)
        raise SystemExit(1) from None
    finally:
        if config is not None:
            config.close()


if __name__ == "__main__":
    main()
