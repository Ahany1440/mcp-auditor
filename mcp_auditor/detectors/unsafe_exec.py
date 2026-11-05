"""MCP004: eval/exec/shell execution with tool input flowing in.

Python: AST. Flags eval/exec, os.system/os.popen, subprocess.*(shell=True) and
create_subprocess_shell whose arguments are not constants. "critical" when a tool
parameter reaches the call inside a tool handler, "high" when any function parameter
does, "medium" when the argument is dynamic but its source is unclear.
JS/TS/Go: regexes for eval, new Function, child_process exec with a non-literal
command, spawn(..., {shell: true}) and exec.Command("sh", "-c", ...). "critical" when
the call sits inside a tool handler, "medium" elsewhere (no data-flow trace).
"""
from __future__ import annotations

import ast
import re

from ..models import Finding, Rule, SourceFile, Target
from . import _python as py

RULE = Rule("MCP004", "unsafe-execution", "Code or shell execution with dynamic input",
            "Never pass tool input to eval/exec or a shell. Call the program directly with an argument list "
            "(shell=False / execFile), validate input against an allow-list, and use a real parser instead of "
            "eval for expressions.")

PY_ALWAYS = re.compile(r"^(eval|exec|os\.system|os\.popen|subprocess\.getoutput|subprocess\.getstatusoutput|asyncio\.create_subprocess_shell|commands\.getoutput)$")
PY_SHELL_KW = re.compile(r"^subprocess\.(run|call|check_call|check_output|Popen)$")

JS_PATTERNS = [
    (r"(?<![.\w$\"'`])eval\(\s*(?![\"'`][^\"'`$]*[\"'`]\s*\))", "eval() on a dynamic string"),
    (r"\bnew\s+Function\(", "new Function() builds code from a string"),
    (r"(?:(?<![.\w$])(?<!function )|\b(?:child_process|cp|childProcess)\.)(?:exec|execSync)\(\s*(?:`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+|[A-Za-z_$][\w$.]*\s*[,)+])",
     "child_process exec() with a command built from variables (runs through a shell)"),
    (r"\bspawn(?:Sync)?\([^;]{0,200}shell\s*:\s*true", "spawn() with shell: true"),
    (r"\bvm\.(runInNewContext|runInThisContext|runInContext)\(", "vm.run*() executes a string as code"),
    (r"\bexec\.Command(?:Context)?\([^)]*\"(?:sh|bash|zsh|cmd|cmd\.exe|powershell|pwsh)\"\s*,\s*\"(?:-c|/c|-Command)\"",
     "exec.Command runs a shell with -c"),
]
JS_PATTERNS = [(re.compile(rx), why) for rx, why in JS_PATTERNS]


def _python(f: SourceFile) -> list[Finding]:
    tree = py.parse(f)
    if tree is None:
        return []
    findings, seen = [], set()
    scopes = [(fn, py.tainted_names(fn), py.is_tool(fn)) for fn in py.functions(tree)]
    # innermost function first so a call is judged by its own handler
    scopes.sort(key=lambda s: s[0].end_lineno - s[0].lineno)
    for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)):
        name = py.dotted(call.func)
        shell_kw = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                       for kw in call.keywords)
        if not (PY_ALWAYS.match(name) or (PY_SHELL_KW.match(name) and shell_kw)):
            continue
        args = call.args[:1] or [kw.value for kw in call.keywords if kw.arg in ("args", "cmd", "source")]
        if not args or all(py.is_literal(a) for a in args):
            continue
        scope = next((s for s in scopes if s[0].lineno <= call.lineno <= s[0].end_lineno), None)
        used = set().union(*(py.names_in(a) for a in args))
        if scope and used & scope[1]:
            sev = "critical" if scope[2] else "high"
            who = f"tool parameter(s) {sorted(used & scope[1])}" if scope[2] else f"parameter(s) {sorted(used & scope[1])} of {scope[0].name}()"
            msg = f"{name}() {'with shell=True ' if shell_kw else ''}receives input from {who}."
        else:
            sev, msg = "medium", f"{name}() {'with shell=True ' if shell_kw else ''}is called with a dynamic argument."
        if (call.lineno, name) not in seen:
            seen.add((call.lineno, name))
            findings.append(Finding(RULE, sev, msg, f.path, call.lineno,
                                    scope[0].name if scope and scope[2] else None, f.line_text(call.lineno)))
    return findings


def _text(f: SourceFile, target: Target) -> list[Finding]:
    findings = []
    for rx, why in JS_PATTERNS:
        if "child_process" in why and "child_process" not in f.text:
            continue  # avoids regex.exec(...) and similar look-alikes
        for m in rx.finditer(f.text):
            line = f.line_of(m.start())
            tool = target.tool_at(f.path, line)
            # without a data-flow trace we only know tool input can reach it when it sits inside a tool handler
            findings.append(Finding(RULE, "critical" if tool else "medium",
                                    f"{why}{f' inside tool {tool.name!r}' if tool else ''}.", f.path, line,
                                    tool.name if tool else None, f.line_text(line)))
    return findings


def detect(target: Target) -> list[Finding]:
    findings = []
    for f in target.files:
        if f.is_python:
            findings += _python(f)
        elif f.is_code:
            findings += _text(f, target)
    return findings
