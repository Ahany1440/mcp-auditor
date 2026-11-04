"""The same notes-helper server as ../vulnerable-server, with each problem fixed."""
import ast
import operator
import os
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import requests
try:
    from mcp.server.fastmcp import FastMCP  # mcp 1.x
except ImportError:
    from mcp.server.mcpserver import MCPServer as FastMCP  # mcp 2.x

AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "")  # from the environment, not the code
NOTES_DIR = Path(os.environ.get("NOTES_DIR", "notes")).resolve()
ALLOWED_REPORTS = {"daily", "weekly"}
ALLOWED_HOSTS = {"docs.python.org", "en.wikipedia.org"}

mcp = FastMCP("notes-helper")  # stdio transport: only the client that started it can talk to it


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b


@mcp.tool()
def run_report(name: str) -> str:
    """Generate one of the predefined reports: daily or weekly."""
    if name not in ALLOWED_REPORTS:
        raise ValueError(f"unknown report {name!r}")
    return subprocess.run(["./reports.sh", name], capture_output=True, text=True).stdout


@mcp.tool()
def read_note(path: str) -> str:
    """Read a note from the notes folder."""
    full = (NOTES_DIR / path).resolve()
    if not full.is_relative_to(NOTES_DIR):
        raise ValueError("path is outside the notes folder")
    return full.read_text(encoding="utf-8")


@mcp.tool()
def fetch_page(url: str) -> str:
    """Fetch a page from an allowed documentation site."""
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    return requests.get(url, timeout=10).text


OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv,
       ast.USub: operator.neg}


def _calc(node: ast.AST) -> float:
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in OPS:
        return OPS[type(node.op)](_calc(node.left), _calc(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in OPS:
        return OPS[type(node.op)](_calc(node.operand))
    raise ValueError("only + - * / and numbers are allowed")


@mcp.tool()
def calc(expression: str) -> str:
    """Evaluate a math expression using + - * / only."""
    return str(_calc(ast.parse(expression, mode="eval").body))


@mcp.tool()
def search(query: str) -> str:
    """Search the notes for a word."""
    return "\n".join(p.name for p in NOTES_DIR.glob("*.md") if query.lower() in p.read_text(encoding="utf-8").lower())


if __name__ == "__main__":
    mcp.run()
