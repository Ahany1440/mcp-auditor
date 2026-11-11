"""Render findings as terminal text, JSON or SARIF 2.1.0."""
from __future__ import annotations

import json
import os
import posixpath
import re
import sys
import textwrap
from collections import Counter

from . import __version__
from .detectors import RULES
from .models import SEVERITIES, Finding, Target

COLORS = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m"}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}  # GitHub's 0-10 scale
HOME = "https://github.com/Ahany1440/mcp-auditor"
# a server must not be able to rewrite the terminal with escape codes, or forge report lines with newlines
CONTROL = re.compile("[\\x00-\\x08\\x0a-\\x1f\\x7f-\\x9f\\u200e\\u200f\\u2028-\\u202e\\u2066-\\u2069]")


def _where(f: Finding) -> str:
    if f.file:
        return f"{f.file}:{f.line}" if f.line else f.file
    return "endpoint" if f.rule.id == "MCP007" else "tools/list (live)"


def warnings(target: Target, findings: list[Finding]) -> list[str]:
    """Reasons a "no findings" result may not mean the server is clean."""
    out = []
    n = sum(x["files"] for x in target.skipped)
    if n:
        out.append(f"{n} code file(s) were NOT scanned, so nothing in them was checked (see the skipped list).")
    if target.from_source and not target.files:
        out.append("0 files were scanned, so this result says nothing about the server.")
    elif not target.tools and not any(f.rule.id == "MCP007" for f in findings):
        out.append("No MCP tools were found, so the tool checks had nothing to look at. Is this the folder of an MCP server?")
    return out


def to_text(target: Target, findings: list[Finding], color: bool | None = None) -> str:
    if color is None:
        color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    paint = (lambda sev, s: f"{COLORS[sev]}{s}\033[0m") if color else (lambda sev, s: s)
    live = sum(t.source == "live" for t in target.tools)
    out = [f"mcp-audit {__version__}: {target.label}",
           f"{len(target.files)} files, {len(target.tools)} tools found ({live} from tools/list)", ""]
    for f in findings:
        tool = f"  [tool: {CONTROL.sub('?', f.tool)}]" if f.tool else ""
        out.append(f"{paint(f.severity, f.severity.upper().ljust(8))} {f.rule.id} {f.rule.name:<22} {_where(f)}{tool}")
        out.append(f"         {CONTROL.sub('?', f.message)}")
        if f.evidence:
            out.append(f"         > {CONTROL.sub('?', f.evidence)}")
        out.append("")
    warned = warnings(target, findings)
    if warned:
        out += [paint("high", "WARNING") + " " + w for w in warned]
        for x in target.skipped:
            count = " (%d files)" % x["files"] if x["files"] > 1 else ""
            out.append(f"  not scanned: {CONTROL.sub('?', x['path'])}{count}: {CONTROL.sub('?', x['reason'])}")
        out.append("")
    if not findings:
        out.append("No findings, but this is NOT a clean result: see the warnings above." if warned else
                   "No findings. That doesn't prove the server is safe, only that none of the known patterns matched.")
        return "\n".join(out)
    seen = {f.rule.id for f in findings}
    out.append("How to fix:")
    for r in RULES:
        if r.id in seen:
            out.append(f"  {r.id} {r.name}")
            out += textwrap.wrap(r.help, 96, initial_indent="    ", subsequent_indent="    ")
    counts = Counter(f.severity for f in findings)
    out += ["", "Summary: " + ", ".join(f"{counts[s]} {s}" for s in reversed(SEVERITIES))]
    return "\n".join(out)


def to_json(target: Target, findings: list[Finding]) -> str:
    return json.dumps({
        "tool": "mcp-audit", "version": __version__, "target": target.label,
        "files_scanned": len(target.files), "skipped": target.skipped, "warnings": warnings(target, findings),
        "tools": [{"name": t.name, "file": t.file, "line": t.line, "source": t.source} for t in target.tools],
        "findings": [{"rule_id": f.rule.id, "rule": f.rule.name, "severity": f.severity, "message": f.message,
                      "file": f.file, "line": f.line, "tool": f.tool, "evidence": f.evidence} for f in findings],
    }, indent=2, ensure_ascii=False)


def to_sarif(target: Target, findings: list[Finding], uri_prefix: str = "") -> str:
    """uri_prefix maps paths relative to the scanned folder onto paths relative to the repo root."""
    rule_index = {r.id: i for i, r in enumerate(RULES)}
    results = []
    for f in findings:
        result = {
            "ruleId": f.rule.id, "ruleIndex": rule_index[f.rule.id], "level": SARIF_LEVEL[f.severity],
            "message": {"text": f.message + (f" Evidence: {f.evidence}" if f.evidence else "")},
            "properties": {"severity": f.severity, **({"mcpTool": f.tool} if f.tool else {})},
        }
        if f.file:
            # normpath: the pin file of a removed tool can sit outside the scanned folder ("../tools.lock.json")
            loc = {"artifactLocation": {"uri": posixpath.normpath(uri_prefix.rstrip("/") + "/" + f.file).lstrip("/")}}
            if f.line:
                loc["region"] = {"startLine": f.line}
            result["locations"] = [{"physicalLocation": loc}]
        results.append(result)
    rules = [{
        "id": r.id, "name": r.name,
        "shortDescription": {"text": r.title}, "fullDescription": {"text": r.help},
        "help": {"text": r.help}, "helpUri": f"{HOME}#detectors",
        "properties": {"tags": ["security", "mcp"],
                       "security-severity": SECURITY_SEVERITY[_default_severity(r.id)]},
    } for r in RULES]
    run: dict = {"tool": {"driver": {"name": "mcp-audit", "version": __version__, "informationUri": HOME, "rules": rules}},
           "results": results}
    warned = warnings(target, findings)
    if warned:  # SARIF 2.1.0 notifications: visible to tools that read them, ignored by the rest
        run["invocations"] = [{"executionSuccessful": True, "toolExecutionNotifications": [
            {"level": "warning", "message": {"text": w}} for w in warned]}]
    if target.skipped:
        run["properties"] = {"skippedFiles": [{**x, "path": (uri_prefix.rstrip("/") + "/" + x["path"]).lstrip("/")}
                                              for x in target.skipped]}
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }, indent=2, ensure_ascii=False)


def _default_severity(rule_id: str) -> str:
    return {"MCP001": "high", "MCP002": "medium", "MCP003": "high", "MCP004": "critical",
            "MCP005": "high", "MCP006": "medium", "MCP007": "high"}[rule_id]
