"""Command line entry point: mcp-audit <path|github-url> [--stdio CMD] [--format ...] [--fail-on ...]"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import threading
from pathlib import Path

from . import __version__, live, pin, remote, report
from .detectors import run_all, sort_findings
from .models import SEVERITIES, Target, severity_rank
from .source import open_target

WATCHDOG_GRACE = 10.0  # seconds past --timeout for the checks to finish on what a remote server sent
WATCHDOG_STATIC_GRACE = 600.0  # with a folder or repo in the same run, for scanning that too


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mcp-audit", description="Scan an MCP server for security problems in the tools it exposes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  mcp-audit                                  scan the current folder\n"
               "  mcp-audit path/to/server                   scan a folder or a single file\n"
               "  mcp-audit https://github.com/owner/repo    scan a GitHub repo\n"
               "  mcp-audit --stdio \"python server.py\"       start a server and check its live tools\n"
               "  mcp-audit --url https://example.com/mcp    check a remote server (never calls its tools)\n"
               "  mcp-audit . --pin tools.lock.json          save the tools once, then alert when they change\n"
               "  mcp-audit . --format sarif -o out.sarif    report for GitHub code scanning")
    p.add_argument("target", nargs="?", help="folder, single file, or https://github.com/owner/repo[/tree/branch/subdir] "
                   "(default: the current folder)")
    source = p.add_mutually_exclusive_group()
    source.add_argument("--url", help="also check this remote MCP endpoint (Streamable HTTP): login, HTTPS, OAuth metadata, "
                        "Origin check and its tools/list. Opens and closes a session but never calls a tool")
    p.add_argument("--header", action="append", metavar="'NAME: VALUE'",
                   help="with --url, send this header, e.g. a token, for the tools/list and Origin checks. Repeatable")
    source.add_argument("--stdio", metavar="CMD", help="also start this stdio server command and audit its live tools/list "
                   "(this runs the server's code)")
    p.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    p.add_argument("-o", "--output", help="write the report to this file instead of stdout")
    p.add_argument("--fail-on", choices=SEVERITIES + ["none"], default="high",
                   help="exit with code 1 if any finding is at or above this severity (default: high)")
    p.add_argument("--timeout", type=float, default=30.0, help="seconds to wait for the --stdio server, or for the whole --url scan (default: 30)")
    p.add_argument("--repeat", type=int, default=3, metavar="N",
                   help="with --stdio or --url, ask for tools/list N times and flag tools that change between answers (default: 3)")
    p.add_argument("--pin", metavar="FILE", help="first run: save every tool's definition to FILE. Later runs: report "
                   "tools that were added, changed or removed since. Delete FILE to accept the current tools.")
    p.add_argument("--version", action="version", version=f"mcp-audit {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.url is not None and not args.url.strip():
        parser.error("--url is empty")
    if args.header and not args.url:
        parser.error("--header needs --url")
    if not args.target and not args.stdio and not args.url:
        args.target = "."
    workdir, watchdog = None, None
    try:
        if args.target:
            is_url = args.target.startswith(("https://", "http://"))
            if is_url:
                import tempfile
                workdir = tempfile.mkdtemp(prefix="mcp-audit-")
            target, root = open_target(args.target, workdir)
            if args.target == ".":
                target.label = str(Path.cwd())
        else:
            target, root, is_url = Target(args.stdio or remote.safe_label(args.url)), None, False
        extra, snapshots = [], []
        if args.stdio:
            snapshots = live.list_tools(args.stdio, args.timeout, args.repeat)
        elif args.url:
            watchdog = _start_watchdog(args.timeout + (WATCHDOG_STATIC_GRACE if target.files else WATCHDOG_GRACE), workdir)
            snapshots, extra = remote.scan(args.url, remote.parse_headers(args.header), args.timeout, args.repeat)
            if args.pin and not snapshots:  # pinning nothing would report every tool as new or removed later
                raise RuntimeError("--pin needs the tools, and a login is required: pass --header with a token")
        if snapshots:
            target.tools += snapshots[0]
            for n, later in enumerate(snapshots[1:], 2):
                changes = pin.compare(pin.snapshot(snapshots[0]), later, f"between tools/list call 1 and call {n}")
                if changes:  # report the first flip only, not the same change once per call
                    # also run the detectors on the changed versions, so the new text gets checked too
                    extra += changes
                    first = pin.snapshot(snapshots[0])
                    target.tools += [t for k, t in zip(pin.snapshot(later), later) if first.get(k) != pin.definition(t)]
                    break
        if args.pin and Path(args.pin).exists():
            extra += pin.compare(pin.load(args.pin), target.tools, f"since it was pinned in {args.pin}")
        elif args.pin:
            pin.save(args.pin, target.tools)
            print(f"mcp-audit: pinned {len(target.tools)} tools to {args.pin}. Future runs with --pin "
                  f"{args.pin} will report any change.", file=sys.stderr)
        findings = sort_findings(run_all(target) + extra)
    except Exception as e:  # report any loader/live failure as a usage error, not a traceback
        message = str(e).replace(args.url, remote.safe_label(args.url)) if args.url else str(e)
        print(f"mcp-audit: error: {report.CONTROL.sub('?', message)}", file=sys.stderr)
        return 2
    finally:
        if watchdog:
            watchdog.cancel()
        if workdir:
            shutil.rmtree(workdir, onerror=_force_remove)

    if args.format == "text":
        out = report.to_text(target, findings, color=None if not args.output else False)
    elif args.format == "json":
        out = report.to_json(target, findings)
    else:
        prefix = ""
        if root is not None and not is_url:
            try:
                rel = os.path.relpath(Path(root).resolve(), Path.cwd())
            except ValueError:  # different drive on Windows
                rel = ".."
            prefix = "" if rel == "." or rel.startswith("..") else Path(rel).as_posix()
        out = report.to_sarif(target, findings, prefix)

    if args.output:
        Path(args.output).write_text(out + "\n", encoding="utf-8", errors="replace")
    else:
        if hasattr(sys.stdout, "reconfigure"):  # Windows consoles default to a legacy code page
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        print(out)

    if args.fail_on != "none" and any(severity_rank(f.severity) >= severity_rank(args.fail_on) for f in findings):
        return 1
    return 0


def _start_watchdog(seconds: float, workdir: str | None = None) -> threading.Timer:
    """A remote server is untrusted: socket timeouts reset on every byte, and some checks are slow on
    crafted tool lists. This is the one limit nothing can get around."""
    def give_up():
        print(f"mcp-audit: error: gave up after {seconds:.0f} seconds; the server is too slow or its answers are too costly to check", file=sys.stderr)
        sys.stderr.flush()
        if workdir:
            shutil.rmtree(workdir, onerror=_force_remove)
        os._exit(2)
    timer = threading.Timer(seconds, give_up)
    timer.daemon = True
    timer.start()
    return timer


def _force_remove(func, path, _exc):
    """git marks pack files read-only, which breaks rmtree on Windows."""
    os.chmod(path, 0o700)
    func(path)
