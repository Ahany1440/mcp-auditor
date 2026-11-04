"""Command line entry point: mcp-audit <path|github-url> [--stdio CMD] [--format ...] [--fail-on ...]"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

from . import __version__, live, report
from .detectors import run_all
from .models import SEVERITIES, Target, severity_rank
from .source import open_target


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mcp-audit", description="Scan an MCP server for security problems in the tools it exposes.")
    p.add_argument("target", nargs="?", help="local folder, single file, or https://github.com/owner/repo[/tree/branch/subdir]")
    p.add_argument("--stdio", metavar="CMD", help="also start this stdio server command and audit its live tools/list "
                   "(this runs the server's code)")
    p.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    p.add_argument("-o", "--output", help="write the report to this file instead of stdout")
    p.add_argument("--fail-on", choices=SEVERITIES + ["none"], default="high",
                   help="exit with code 1 if any finding is at or above this severity (default: high)")
    p.add_argument("--timeout", type=float, default=30.0, help="seconds to wait for the --stdio server (default: 30)")
    p.add_argument("--version", action="version", version=f"mcp-audit {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.target and not args.stdio:
        build_parser().error("give a target path/URL, --stdio CMD, or both")
    workdir = None
    try:
        if args.target:
            is_url = args.target.startswith(("https://", "http://"))
            if is_url:
                import tempfile
                workdir = tempfile.mkdtemp(prefix="mcp-audit-")
            target, root = open_target(args.target, workdir)
        else:
            target, root, is_url = Target(args.stdio), None, False
        if args.stdio:
            target.tools += live.list_tools(args.stdio, args.timeout)
        findings = run_all(target)
    except Exception as e:  # report any loader/live failure as a usage error, not a traceback
        print(f"mcp-audit: error: {e}", file=sys.stderr)
        return 2
    finally:
        if workdir:
            shutil.rmtree(workdir, onerror=_force_remove)

    if args.format == "text":
        out = report.to_text(target, findings, color=None if not args.output else False)
    elif args.format == "json":
        out = report.to_json(target, findings)
    else:
        prefix = ""
        if root is not None and not is_url:
            rel = os.path.relpath(Path(root).resolve(), Path.cwd())
            prefix = "" if rel == "." or rel.startswith("..") else Path(rel).as_posix()
        out = report.to_sarif(target, findings, prefix)

    if args.output:
        Path(args.output).write_text(out + "\n", encoding="utf-8")
    else:
        if hasattr(sys.stdout, "reconfigure"):  # Windows consoles default to a legacy code page
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        print(out)

    if args.fail_on != "none" and any(severity_rank(f.severity) >= severity_rank(args.fail_on) for f in findings):
        return 1
    return 0


def _force_remove(func, path, _exc):
    """git marks pack files read-only, which breaks rmtree on Windows."""
    os.chmod(path, 0o700)
    func(path)
