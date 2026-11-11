"""MCP002: tools that run commands, touch arbitrary paths or reach arbitrary URLs with no allow-list.

A tool is flagged when its handler passes tool input into a shell/file/network call and the
handler contains nothing that looks like an allow-list or path check. Python handlers are
checked with the AST (input must actually reach the call); JS/TS/Go handlers with regexes
over the handler text. Tools with no visible handler (live tools/list, low-level SDK servers)
fall back to wording in the description.
"""
from __future__ import annotations

import ast
import re

from ..models import Finding, Rule, SourceFile, Target, Tool
from . import _python as py
from ._code import code_view

RULE = Rule("MCP002", "over-broad-capability", "Tool has shell, file or network access without an allow-list",
            "Give the tool only what it needs: a fixed list of commands (no shell), a root directory that "
            "resolved paths must stay inside, or a list of allowed hosts. An agent that gets prompt-injected "
            "will use whatever the tool allows.")

# category -> (severity, what it does, python call-name regex, js/go text regex, guard regex, description wording)
CATEGORIES = {
    "shell": ("high", "runs OS commands",
              r"^(subprocess\.\w+|os\.(system|popen|exec\w*|spawn\w*)|asyncio\.create_subprocess_\w+)$",
              r"(?:(?<![.\w$])|\b(?:child_process|cp|childProcess)\.)(execSync|execFileSync|spawnSync|execa|exec|execFile|spawn)\(|\bexec\.Command(Context)?\(|\bDeno\.Command\(",
              r"allow(ed)?_?(list|commands?|programs?)|whitelist|ALLOWED_|\bin\s+(SAFE|ALLOW)\w*",
              r"\b(run|execute|exec)s?\b.{0,20}\b(shell|terminal|system|bash|arbitrary)?\s*commands?\b|\bshell\b"),
    "filesystem": ("medium", "reads or writes files at a path taken from tool input",
                   r"^(open|io\.open|os\.(remove|unlink|rmdir|rename|listdir|scandir|walk|makedirs)|shutil\.\w+)$|\.(read_text|write_text|read_bytes|write_bytes|unlink|rmdir|iterdir|rglob|glob|open)$",
                   r"\bfs(Promises)?\.(readFile|writeFile|appendFile|unlink|rm|rmdir|readdir|createReadStream|createWriteStream|rename)\w*\(|\b(readFile|writeFile|readdir|unlink)(Sync)?\(|\bos\.(ReadFile|WriteFile|Open|OpenFile|Create|Remove|RemoveAll|ReadDir)\(",
                   r"allow(ed)?_?(dirs?|directories|paths?|roots?|list)|is_relative_to|commonpath|realpath|\.resolve\(|(?:startswith|startsWith)\((?!\s*[\"'](?:[^\"'/\\]*|/)[\"'])|path\.relative|ALLOWED_|validatePath|safe_?path|filepath\.Rel|HasPrefix",
                   r"\b(read|write|delete|edit|move|create|list)s?\b.{0,25}\b(any|arbitrary)?\s*(files?|director(y|ies))\b"),
    "network": ("medium", "makes requests to URLs taken from tool input",
                r"^(requests|httpx)\.(get|post|put|patch|delete|head|request|stream)$|(^|\.)urlopen$|^aiohttp\.request$",
                r"\bfetch\(|\baxios(\.\w+)?\(|\bgot(\.\w+)?\(|\bhttps?\.(get|request)\(|\bhttp\.(Get|Post|NewRequest(WithContext)?)\(",
                r"allow(ed)?_?(hosts?|domains?|urls?|origins?|list)|ALLOWED_|whitelist|\.hostname\b|\.netloc\b|\bhostname\s+(not\s+)?in\b",
                r"\b(fetch|download|retrieve|request|get)s?\b.{0,25}\b(any|arbitrary)?\s*(urls?|web ?pages?|websites?)\b"),
}


def _checks(fn: ast.AST) -> list[ast.AST]:
    """The parts of a function that can hold a check: conditions, loop heads and plain statements, not whole blocks."""
    out = []
    for node in ast.walk(fn):
        if isinstance(node, (ast.If, ast.While, ast.Assert)):
            out.append(node.test)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            out.append(node.iter)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            out += [item.context_expr for item in node.items]
        elif isinstance(node, ast.stmt) and not hasattr(node, "body"):
            out.append(node)
    return out


def _python(f: SourceFile, target: Target) -> list[Finding]:
    tree = py.parse(f)
    if tree is None:
        return []
    code = code_view(f)  # no comments, no string contents: a guard word there is not a guard
    findings = []
    for fn in py.functions(tree):
        if not py.is_tool(fn):
            continue
        tool = target.tool_at(f.path, fn.lineno)
        name = tool.name if tool else fn.name
        tainted = py.tainted_names(fn)
        checks = [(code.segment(c) or "", py.names_in(c)) for c in _checks(fn)]
        for cat, (sev, what, call_rx, _, guard_rx, _) in CATEGORIES.items():
            # a real guard is code that uses the tool's input (or something made from it)
            if any(re.search(guard_rx, text) and names & tainted for text, names in checks):
                continue
            for call in (n for n in ast.walk(fn) if isinstance(n, ast.Call)):
                if re.search(call_rx, py.dotted(call.func)) and py.call_inputs(call) & tainted:
                    findings.append(Finding(RULE, sev, f"Tool '{name}' {what} with no allow-list or path check.",
                                            f.path, call.lineno, name, f.line_text(call.lineno)))
                    break
    return findings


def _windowed(f: SourceFile, tool: Tool) -> list[Finding]:
    lines = code_view(f).lines[tool.line - 1: tool.end_line]
    body = "\n".join(lines)
    findings = []
    for cat, (sev, what, _, text_rx, guard_rx, _) in CATEGORIES.items():
        m = re.search(text_rx, body)
        if m and not re.search(guard_rx, body):
            line = tool.line + body.count("\n", 0, m.start())
            findings.append(Finding(RULE, sev, f"Tool '{tool.name}' {what.replace(' taken from tool input', '')} "
                                    "and its handler shows no allow-list or path check.", f.path, line, tool.name,
                                    f.line_text(line)))
    return findings


def _by_description(tool: Tool) -> list[Finding]:
    findings = []
    text = f"{tool.name.replace('_', ' ')} {tool.description}"
    for cat, (sev, what, _, _, guard_rx, words_rx) in CATEGORIES.items():
        if re.search(words_rx, text, re.I) and not re.search(r"allow(ed)?|restricted|only within|sandbox", text, re.I):
            lower = {"high": "medium", "medium": "low"}[sev]
            findings.append(Finding(RULE, lower, f"Tool '{tool.name}' description suggests it {what.split(' at ')[0].split(' to ')[0]} "
                                    "and does not mention any restriction (handler code not available to check).",
                                    tool.file, tool.line, tool.name, tool.description[:160]))
    return findings


def detect(target: Target) -> list[Finding]:
    findings = []
    for f in target.files:
        if f.is_python:
            findings += _python(f, target)
    for tool in target.tools:
        f = target.file(tool.file) if tool.file else None
        if f is not None and f.is_python and tool.end_line:
            continue  # handled by the AST pass above
        if f is not None and tool.end_line:
            findings += _windowed(f, tool)
        else:
            findings += _by_description(tool)
    return findings
