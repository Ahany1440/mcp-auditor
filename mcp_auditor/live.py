"""Ask a running stdio MCP server for its tools (initialize -> tools/list).

Warning: this starts the server command, so it runs that server's code on your machine.
"""
from __future__ import annotations

import json
import os
import queue
import shlex
import shutil
import subprocess
import threading
import time

from . import __version__
from .models import Tool, schema_texts

PROTOCOL_VERSION = "2025-06-18"


def list_tools(command: str, timeout: float = 30.0) -> list[Tool]:
    args = shlex.split(command, posix=os.name != "nt")
    if os.name == "nt":
        args = [a.strip('"') for a in args]
    args[0] = shutil.which(args[0]) or args[0]
    proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            text=True, encoding="utf-8")
    lines: queue.Queue[str] = queue.Queue()
    reader = threading.Thread(target=lambda: [lines.put(l) for l in proc.stdout], daemon=True)
    reader.start()
    deadline = time.monotonic() + timeout

    def send(msg: dict) -> None:
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", **msg}) + "\n")
        proc.stdin.flush()

    def reply(msg_id: int) -> dict:
        while True:
            remaining = deadline - time.monotonic()
            if proc.poll() is not None and lines.empty():
                raise RuntimeError(f"server exited with code {proc.returncode} before answering request {msg_id}")
            if remaining <= 0:
                raise TimeoutError(f"no reply from server for request {msg_id} within the timeout")
            try:
                msg = json.loads(lines.get(timeout=min(remaining, 0.5)))
            except (queue.Empty, json.JSONDecodeError):
                continue  # servers sometimes log non-JSON lines to stdout
            if msg.get("id") == msg_id:
                if "error" in msg:
                    raise RuntimeError(f"server error: {msg['error']}")
                return msg["result"]

    try:
        send({"id": 1, "method": "initialize", "params": {
            "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
            "clientInfo": {"name": "mcp-audit", "version": __version__}}})
        reply(1)
        send({"method": "notifications/initialized"})
        tools, cursor, msg_id = [], None, 2
        while True:
            send({"id": msg_id, "method": "tools/list", "params": {"cursor": cursor} if cursor else {}})
            result = reply(msg_id)
            tools += [_to_tool(t) for t in result.get("tools", [])]
            cursor, msg_id = result.get("nextCursor"), msg_id + 1
            if not cursor:
                return tools
    finally:
        proc.kill()
        proc.wait()
        reader.join(timeout=2)  # the reader stops at EOF once the process is gone
        proc.stdin.close()
        proc.stdout.close()


def _to_tool(raw: dict) -> Tool:
    schema = raw.get("inputSchema") or {}
    props = schema.get("properties") or {}
    params = {k: str(v.get("description", "")) for k, v in props.items() if isinstance(v, dict)}
    extra = schema_texts(schema) + schema_texts(raw.get("outputSchema"), "output schema")
    for where, value in (("title", raw.get("title")), ("annotations title", (raw.get("annotations") or {}).get("title"))):
        if isinstance(value, str):
            extra.append((where, value))
    return Tool(name=str(raw.get("name", "")), description=str(raw.get("description") or ""),
                params=params, source="live", extra=extra)
