"""MCP004: eval/exec/shell execution with tool input flowing in.

Python: AST. Flags eval/exec, os.system/os.popen, subprocess.*(shell=True) and
create_subprocess_shell whose arguments are not constants. "critical" when a tool
parameter reaches the call inside a tool handler, "high" when any function parameter
does, "medium" when the argument is dynamic but its source is unclear. When exec/eval runs only
after a check of its input and with __builtins__ replaced (a sandboxed expression evaluator), the
severity stays and the message notes the mitigation for the reviewer to confirm.
JS/TS/Go: regexes for eval, new Function, child_process exec with a non-literal
command, spawn(..., {shell: true}) and exec.Command("sh", "-c", ...). "critical" when
the call sits inside a tool handler, "medium" elsewhere (no data-flow trace).
"""
from __future__ import annotations

import ast
import re

from bisect import bisect_left

from ..models import Finding, Rule, SourceFile, Target
from ..source import py_defs
from . import _python as py

RULE = Rule("MCP004", "unsafe-execution", "Code or shell execution with dynamic input",
            "Never pass tool input to eval/exec or a shell. Call the program directly with an argument list "
            "(shell=False / execFile), validate input against an allow-list, and use a real parser instead of "
            "eval for expressions.")

# The dangerous calls. Python names are matched after import aliases are resolved (`import subprocess as sp`).
PY_ALWAYS = re.compile(r"^((__builtins__|builtins)\.)?(eval|exec)$|^(os\.system|os\.popen|subprocess\.getoutput|subprocess\.getstatusoutput|asyncio\.create_subprocess_shell|commands\.getoutput)$")
PY_SHELL_KW = re.compile(r"^subprocess\.(run|call|check_call|check_output|Popen)$")  # a sink with shell=True or a `sh -c` list
PY_DESERIALIZE = re.compile(r"^(pickle|_pickle|cPickle|cloudpickle|dill|marshal)\.loads?$|^jsonpickle\.decode$|^yaml\.unsafe_load(_all)?$")
PY_YAML_LOAD = re.compile(r"^yaml\.load(_all)?$")  # a sink unless it is given a safe Loader
YAML_UNSAFE_LOADERS = {"Loader", "UnsafeLoader", "FullLoader", "CLoader", "CUnsafeLoader", "CFullLoader"}
SHELL_PROGRAM = re.compile(r"(?i)^(.*[/\\])?(sh|bash|zsh|dash|ksh|cmd|powershell|pwsh)(\.exe)?$")
SHELL_FLAG = re.compile(r"(?i)^(-[a-z]*c|/c|-command)$")
JS_MODULES = "child_process|vm"

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


def _py_sink(call: ast.Call, name: str, shell_kw: bool) -> str | None:
    """None when the call is not one of the dangerous ones; else the phrase for the message ("" if its name says it all)."""
    if PY_ALWAYS.match(name):
        return "with shell=True " if shell_kw else ""
    if PY_SHELL_KW.match(name):
        first = call.args[0] if call.args else None
        if shell_kw:
            return "with shell=True "
        if (isinstance(first, (ast.List, ast.Tuple)) and len(first.elts) > 2
                and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in first.elts[:2])
                and SHELL_PROGRAM.match(first.elts[0].value) and SHELL_FLAG.match(first.elts[1].value)):
            return "running a shell with -c "
    if PY_DESERIALIZE.match(name):
        return "(can run code while loading) "
    if PY_YAML_LOAD.match(name):
        loader = call.args[1] if len(call.args) > 1 else next((k.value for k in call.keywords if k.arg == "Loader"), None)
        if loader is None or py.dotted(loader).split(".")[-1] in YAML_UNSAFE_LOADERS:
            return "(can run code while loading) "
    return None



NOT_A_CHECK = {"len", "isinstance", "str", "bool", "type", "hasattr", "callable", "print"}


def _runs_before(fn: ast.AST, call: ast.Call) -> list[ast.stmt]:
    """Statements of fn that always run before the statement holding call, in order: its earlier siblings,
    then those of each enclosing block. A statement inside an earlier if/loop/with is not one of them."""
    parent, todo = {}, [fn]
    while todo:
        node = todo.pop()
        for child in ast.iter_child_nodes(node):
            if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                parent[child] = node
                todo.append(child)
    chain, node = [], call
    while node in parent:
        up = parent[node]
        for field in ("body", "orelse", "finalbody"):  # an earlier except handler may not have run
            block = getattr(up, field, None)
            if isinstance(block, list) and node in block:
                chain = block[:block.index(node)] + chain
        node = up
    return chain


def _stops(stmt: ast.If) -> bool:
    return bool(stmt.body) and isinstance(stmt.body[-1], (ast.Raise, ast.Return))


def _checked_call(test: ast.expr, results: dict[str, str], arg: str) -> str | None:
    """The check named by `not ok`, `not check(arg)` or `not check(arg)[0]`, or None."""
    if not (isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not)):
        return None
    inner = test.operand.value if isinstance(test.operand, ast.Subscript) else test.operand
    if isinstance(inner, ast.Name):
        return results.get(inner.id)
    if isinstance(inner, ast.Call) and any(isinstance(a, ast.Name) and a.id == arg for a in inner.args[:1]):
        return py.dotted(inner.func)
    return None


def _validator(fn: ast.AST, call: ast.Call) -> str | None:
    """Name of the check that gates exec/eval, or None.

    Matches `ok, err = check(src)` or `ok = check(src)` then `if not ok: raise/return`, and
    `if not check(src): raise/return`, where src is the very name exec/eval runs. The check must run on
    every path to the call (not inside an earlier branch or loop), and neither src nor the check's result
    may be assigned again anywhere else in the function.
    """
    if not (call.args and isinstance(call.args[0], ast.Name)):
        return None
    arg = call.args[0].id
    stores = [n for n in ast.walk(fn) if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del))]
    if any(n.id == arg for n in stores):
        return None  # src is reassigned somewhere: what is checked may not be what runs
    results = {}
    for stmt in _runs_before(fn, call):
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.value, ast.Call) \
                and any(isinstance(a, ast.Name) and a.id == arg for a in stmt.value.args[:1]):
            target = stmt.targets[0]
            first = target.elts[0] if isinstance(target, ast.Tuple) and target.elts else target
            if isinstance(first, ast.Name) and sum(n.id == first.id for n in stores) == 1:
                results[first.id] = py.dotted(stmt.value.func)
        elif isinstance(stmt, ast.If) and _stops(stmt):
            check = _checked_call(stmt.test, results, arg)
            if check and check.rsplit(".", 1)[-1] not in NOT_A_CHECK:
                return check
    return None


def _replaces_builtins(call: ast.Call, fn: ast.AST) -> bool:
    """True when exec/eval gets a globals dict whose __builtins__ is not the real builtins."""
    g = call.args[1] if len(call.args) > 1 else next((k.value for k in call.keywords if k.arg == "globals"), None)
    if isinstance(g, ast.Name):
        name = g.id
        # one plain assignment that runs before the call, and the dict is not changed afterwards
        g = next((n.value for n in _runs_before(fn, call) if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None
                  and name in py.names_in(n.targets[0] if isinstance(n, ast.Assign) else n.target)), None)
        writes = sum(isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, (ast.Store, ast.Del)) for n in ast.walk(fn))
        changed = any(isinstance(n, (ast.Subscript, ast.Attribute)) and isinstance(n.value, ast.Name) and n.value.id == name
                      and (isinstance(n.ctx, (ast.Store, ast.Del)) or isinstance(n, ast.Attribute)) for n in ast.walk(fn))
        if writes != 1 or changed:
            return False
    if not isinstance(g, ast.Dict):
        return False
    value = next((v for k, v in zip(g.keys, g.values) if isinstance(k, ast.Constant) and k.value == "__builtins__"), None)
    return value is not None and not (isinstance(value, ast.Name) and value.id in ("__builtins__", "builtins"))


def _python(f: SourceFile) -> list[Finding]:
    tree = py.parse(f)
    if tree is None:
        return []
    aliases, defs = py.import_aliases(tree), py_defs(tree)
    findings, seen = [], set()
    scopes = [(fn, py.tainted_names(fn), py.is_tool(fn)) for fn in py.functions(tree)]
    # innermost function first so a call is judged by its own handler
    scopes.sort(key=lambda s: s[0].end_lineno - s[0].lineno)
    for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)):
        name = py.resolved(call.func, aliases, defs)
        shell_kw = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                       for kw in call.keywords)
        how = _py_sink(call, name, shell_kw)
        if how is None:
            continue
        args = call.args[:1] or [kw.value for kw in call.keywords if kw.arg in ("args", "cmd", "source")]
        if not args or all(py.is_literal(a) for a in args):
            continue
        scope = next((s for s in scopes if s[0].lineno <= call.lineno <= s[0].end_lineno), None)
        used = set().union(*(py.names_in(a) for a in args))
        if scope and used & scope[1]:
            sev = "critical" if scope[2] else "high"
            who = f"tool parameter(s) {sorted(used & scope[1])}" if scope[2] else f"parameter(s) {sorted(used & scope[1])} of {scope[0].name}()"
            msg = f"{name}() {how}receives input from {who}."
        else:
            sev, msg = "medium", f"{name}() {how}is called with a dynamic argument."
        # a sandboxed expression evaluator: the input is checked first and the builtins are swapped out.
        # Code shape can't show that the check really validates (def check(x): return True passes),
        # so the severity stays and the message names the check for the reviewer to confirm.
        check = _validator(scope[0], call) if scope and name.rsplit(".", 1)[-1] in ("exec", "eval") and sev != "medium" else None
        if check and _replaces_builtins(call, scope[0]):
            msg += (f" It runs only after {check}() accepts the input, with __builtins__ replaced; check that "
                    f"{check}() is an allow-list that also rejects dunder attribute access.")
        if (call.lineno, name) not in seen:
            seen.add((call.lineno, name))
            findings.append(Finding(RULE, sev, msg, f.path, call.lineno,
                                    scope[0].name if scope and scope[2] else None, f.line_text(call.lineno)))
    return findings


def _js_aliases(text: str) -> dict[str, str]:
    """Local name -> "child_process", "child_process.exec", "vm.runInNewContext"... from require() and import."""
    out = {"cp": "child_process", "childProcess": "child_process"}
    require = r"""require\(\s*["'](?:node:)?(""" + JS_MODULES + r""")["']\s*\)"""
    for m in re.finditer(r"(?:const|let|var)\s+([\w$]+)\s*=\s*" + require + r"(?:\.([\w$]+))?", text):
        out[m.group(1)] = m.group(2) + ("." + m.group(3) if m.group(3) else "")
    for m in re.finditer(r"(?:const|let|var)\s*\{([^}]*)\}\s*=\s*" + require, text):
        for item in m.group(1).split(","):  # `exec: run` or just `exec`
            real, _, local = item.partition(":")
            if real.strip():
                out[local.strip() or real.strip()] = m.group(2) + "." + real.strip()
    for m in re.finditer(r"""\bimport\s+([^;'"]*?)\s*from\s*["'](?:node:)?(""" + JS_MODULES + r""")["']""", text):
        clause, module = m.group(1), m.group(2)
        for item in re.findall(r"\{([^}]*)\}", clause):  # `{ exec as run, execSync }`
            for part in item.split(","):
                real, _, local = part.partition(" as ")
                if real.strip():
                    out[local.strip() or real.strip()] = module + "." + real.strip()
        for local in re.findall(r"(?:\*\s*as\s+)?([\w$]+)\s*(?:,|$)", re.sub(r"\{[^}]*\}", "", clause)):
            out[local] = module
    return out


def _canonical_js(text: str) -> str:
    """The same text with the other spellings of a dangerous call turned into the plain ones the patterns look for:
    `require("child_process").execSync(x)`, `cp2.exec(x)` / `run(x)` through an alias, `cp["exec"](x)`,
    `globalThis.eval(x)` and `(0, eval)(x)`. Newlines are never touched, so line numbers stay the same."""
    aliases = _js_aliases(text)
    text = re.sub(r"""require\([ \t]*["'](?:node:)?(""" + JS_MODULES + r""")["'][ \t]*\)""", r"\1", text)
    for local, real in aliases.items():
        if "." in real:  # `run(x)` is child_process.exec(x)
            text = re.sub(rf"(?<![\w$.])(?<!function ){re.escape(local)}(?=[ \t]*\()", real, text)
        else:  # `cp2.exec(x)` and `cp2["exec"](x)`
            text = re.sub(rf"(?<![\w$.]){re.escape(local)}(?=[ \t]*[.\[])", real, text)
    text = re.sub(r"""\b(""" + JS_MODULES + r""")[ \t]*\[[ \t]*["'](\w+)["'][ \t]*\]""", r"\1.\2", text)
    text = re.sub(r"\([ \t]*0[ \t]*,[ \t]*(?:(?:globalThis|window|global|self)[ \t]*\.[ \t]*)?eval[ \t]*\)(?=[ \t]*\()", "eval", text)
    return re.sub(r"(?<![\w$.])(?:globalThis|window|global|self)[ \t]*\.[ \t]*eval(?=[ \t]*\()", "eval", text)


def _text(f: SourceFile, target: Target) -> list[Finding]:
    findings = []
    text = f.text if f.suffix == ".go" else _canonical_js(f.text)
    newlines = [m.start() for m in re.finditer("\\n", text)]
    for rx, why in JS_PATTERNS:
        if "child_process" in why and "child_process" not in text:
            continue  # avoids regex.exec(...) and similar look-alikes
        for m in rx.finditer(text):
            line = bisect_left(newlines, m.start()) + 1
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
