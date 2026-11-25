#!/usr/bin/env python3
"""Minimal MCP client for scripting the namespace-agent server over stdio.

usage:
  client.py tools
  client.py call <tool> ['{"json": "args"}']

The server is launched as a subprocess with the current environment
(KUBECONFIG, WRITE_MODE, GITEA_TOKEN_FILE, ...), exactly as an MCP host such
as Claude Code would launch it.
"""
import asyncio
import json
import os
import sys

from mcp import Client
from mcp.client.stdio import StdioServerParameters

HERE = os.path.dirname(os.path.abspath(__file__))


async def main(argv: list[str]) -> int:
    params = StdioServerParameters(
        command=sys.executable,
        args=[os.path.join(HERE, "server.py")],
        env=dict(os.environ),
    )
    async with Client(params) as c:
        if argv[:1] == ["tools"]:
            for t in (await c.list_tools()).tools:
                print(f"- {t.name}: {(t.description or '').strip().splitlines()[0]}")
            return 0
        if len(argv) >= 2 and argv[0] == "call":
            args = json.loads(argv[2]) if len(argv) > 2 else {}
            res = await c.call_tool(argv[1], args)
            for block in res.content:
                print(getattr(block, "text", block))
            return 1 if res.is_error else 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1:])))
