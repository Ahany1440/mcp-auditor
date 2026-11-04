"""Render findings as terminal text, JSON or SARIF 2.1.0."""
from __future__ import annotations

import json
import os
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


def _where(f: Finding) -> str:
    if f.file:
        return f"{f.file}:{f.line}" if f.line else f.file
    return "tools/list (live)"


def to_text(target: Target, findings: list[Finding], color: bool | None = None) -> str:
    if color is None:
        color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    paint = (lambda sev, s: f"{COLORS[sev]}{s}\033[0m") if color else (lambda sev, s: s)
    live = sum(t.source == "live" for t in target.tools)
    out = [f"mcp-audit {__version__}: {target.label}",
           f"{len(target.files)} files, {len(target.tools)} tools found ({live} from tools/list)", ""]
    for f in findings:
        tool = f"  [tool: {f.tool}]" if f.tool else ""
        out.append(f"{paint(f.severity, f.severity.upper().ljust(8))} {f.rule.id} {f.rule.name:<22} {_where(f)}{tool}")
        out.append(f"         {f.message}")
        if f.evidence:
            out.append(f"         > {f.evidence}")
        out.append("")
    if not target.tools:
        out += ["Note: no MCP tools were found here. Is this the folder of an MCP server?", ""]
    if not findings:
        out.append("No findings. That doesn't prove the server is safe, only that none of the known patterns matched.")
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
        "files_scanned": len(target.files),
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
            loc = {"artifactLocation": {"uri": (uri_prefix.rstrip("/") + "/" + f.file).lstrip("/")}}
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
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "mcp-audit", "version": __version__,
                                      "informationUri": HOME, "rules": rules}},
                  "results": results}],
    }, indent=2, ensure_ascii=False)


def _default_severity(rule_id: str) -> str:
    return {"MCP001": "high", "MCP002": "medium", "MCP003": "high", "MCP004": "critical",
            "MCP005": "high", "MCP006": "medium"}[rule_id]
