"""MCP006: tool descriptions that can change after the user approved the server.

Users (or their client) review a server's tools once. If a description is fetched from
the network, read from the environment or built at runtime, the server can show one
thing at install time and another later: a "rug pull". Servers that announce
tools/list_changed can also swap their tool set at runtime.
"""
from __future__ import annotations

import ast
import re

from ..models import Finding, Rule, SourceFile, Target
from . import _python as py
from ..source import imports_mcp

RULE = Rule("MCP006", "rug-pull-risk", "Tool description is dynamic or fetched remotely",
            "Keep tool names and descriptions as literals in the code that gets reviewed and pinned. If tools "
            "must change at runtime, make sure clients re-ask the user when tools/list changes.")

NETWORK = re.compile(r"\brequests\.|\bhttpx\.|\burlopen\(|\baiohttp\.|\bfetch\(|\baxios\b|\bhttp\.Get\(")
LIST_CHANGED = re.compile(r"sendToolListChanged\s*\(|send_tool_list_changed\s*\(|[\"']notifications/tools/list_changed[\"']"
                          r"|\btools\b[^\n]{0,40}\blist_?[cC]hanged[\"']?\s*[:=]\s*(true|True)\b")
COMMENT = re.compile(r"^\s*(//|#|\*|/\*)")
NEAR_TOOL = 10  # shortcut: a JS/Go tool's own description is assumed to sit within 10 lines of where the tool is declared
ENV = re.compile(r"\bos\.environ|\bgetenv\(|\bprocess\.env\b|\bos\.Getenv\(")
JS_DYNAMIC_DESC = re.compile(r"\bdescription\s*:\s*(`[^`]*\$\{|(?![\"'`\s])[^,\n}]+)")
JS_TOOL_DYNAMIC_DESC = re.compile(r"\.(?:tool|registerTool)\(\s*[\"'`][^\"'`]+[\"'`]\s*,\s*(?![\"'`{\s])([^,\n]+)")
GO_DYNAMIC_DESC = re.compile(r"\bWithDescription\(\s*(?!\")([^)\n]+)")


def _python(f: SourceFile) -> list[Finding]:
    tree = py.parse(f)
    if tree is None:
        return []
    constants = {t.id for node in tree.body if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
                 for t in node.targets if isinstance(t, ast.Name)}
    findings = []
    sdk = imports_mcp(f)

    def check(expr: ast.expr, where: str, line: int) -> None:
        # names used only as the function being called (dedent, textwrap.dedent) are not data
        called = set().union(*(py.names_in(n.func) for n in ast.walk(expr) if isinstance(n, ast.Call)))
        data = set().union(set(), *(py.names_in(a) for n in ast.walk(expr) if isinstance(n, ast.Call)
                                    for a in n.args + [k.value for k in n.keywords]))
        src = f.segment(expr) or ""
        if not (py.names_in(expr) - constants - (called - data)) and not NETWORK.search(src):
            return
        remote = bool(NETWORK.search(f.text))
        env = bool(ENV.search(src))
        sev = "high" if remote else "medium"
        why = ("is built from a value and this file makes network requests (description may be fetched remotely)"
               if remote else "comes from the environment" if env else "is built at runtime")
        findings.append(Finding(RULE, sev, f"{where} description {why}.", f.path, line, evidence=src[:160]))

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and py.is_tool(node):
            dec = next(d for d in node.decorator_list if py._is_tool_decorator(d))
            for kw in getattr(dec, "keywords", []):
                if kw.arg == "description" and not isinstance(kw.value, ast.Constant):
                    check(kw.value, f"Tool '{node.name}'", node.lineno)
        elif sdk and isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", None)) == "Tool":
            for kw in node.keywords:
                if kw.arg == "description" and not isinstance(kw.value, ast.Constant):
                    check(kw.value, "Tool(...)", node.lineno)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Attribute) and (t.attr == "__doc__" or sdk and t.attr == "description") and not isinstance(node.value, ast.Constant):
                    check(node.value, f"Assignment to {f.segment(t)}:", node.lineno)
    return findings


def _text(f: SourceFile, target: Target) -> list[Finding]:
    findings = []
    remote = bool(NETWORK.search(f.text))
    # Only a tool's own description counts: the first "description" within NEAR_TOOL lines of the tool,
    # or a non-literal second argument on the tool line itself.
    own_lines = set()
    for t in target.tools:
        if t.file == f.path and t.line:
            for n in range(t.line, t.line + NEAR_TOOL):
                if re.search(r"\bdescription\s*:|WithDescription\(|Description:", f.line_text(n)) or n == t.line and JS_TOOL_DYNAMIC_DESC.search(f.line_text(n)):
                    own_lines.add(n)
                    break
    rxs = [GO_DYNAMIC_DESC] if f.suffix == ".go" else [JS_DYNAMIC_DESC, JS_TOOL_DYNAMIC_DESC]
    for rx in rxs:
        for m in rx.finditer(f.text):
            value = m.group(1).strip()
            if re.fullmatch(r"[A-Z0-9_.]+|\w+\.(description|DESCRIPTION)|t\(.*\)|i18n.*", value):
                continue  # shortcut: assumes UPPER_CASE names and *.description are constants defined in code
            if value.startswith("`"):  # template literal: static if it only interpolates UPPER_CASE constants
                end = f.text.find("`", m.start(1) + 1)
                parts = re.findall(r"\$\{([^}]*)\}", f.text[m.start(1): end])
                if all(re.fullmatch(r"\s*[A-Z0-9_.]+\s*", p) for p in parts):
                    continue
            line = f.line_of(m.start())
            if line not in own_lines:
                continue
            env = bool(ENV.search(value))
            sev = "high" if remote and re.search(r"await|fetch|response|res\.|data\b|json", value) else "medium" if env else "low"
            findings.append(Finding(RULE, sev, "Tool description is not a string literal"
                                    + (" and comes from the environment" if env else "")
                                    + (" (file also makes network requests)" if sev == "high" else "") + ".",
                                    f.path, line, evidence=f.line_text(line)))
    return findings


def detect(target: Target) -> list[Finding]:
    findings = []
    for f in target.files:
        if not f.is_code:
            continue
        findings += _python(f) if f.is_python else _text(f, target)
        m = next((m for m in LIST_CHANGED.finditer(f.text) if not COMMENT.match(f.line_text(f.line_of(m.start())))), None)
        if m:
            line = f.line_of(m.start())
            findings.append(Finding(RULE, "low", "Server can change its tool list at runtime (tools/list_changed). "
                                    "Clients that do not re-review changed tools will use the new definitions silently.",
                                    f.path, line, evidence=f.line_text(line)))
    return findings
