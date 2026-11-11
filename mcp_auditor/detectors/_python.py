"""Small AST helpers shared by the Python parts of the detectors."""
from __future__ import annotations

import ast
from typing import Iterator

from ..models import SourceFile
from ..source import _is_tool_decorator, fold_str, py_defs


def parse(f: SourceFile) -> ast.Module | None:
    try:
        return ast.parse(f.text)
    except SyntaxError:
        return None


def dotted(func: ast.expr) -> str:
    """`subprocess.run` -> "subprocess.run"; `Path(p).read_text` -> "?.read_text"."""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return dotted(func.value) + "." + func.attr
    return "?"


def import_aliases(tree: ast.Module) -> dict[str, str]:
    """Local name -> real dotted name: `import subprocess as sp` -> sp: subprocess, `from os import system as s` -> s: os.system.
    shortcut: every scope is read as one, and relative imports are skipped; upgrade if shadowing shows up in practice."""
    out = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.update({a.asname: a.name for a in node.names if a.asname})
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            out.update({a.asname or a.name: f"{node.module}.{a.name}" for a in node.names if a.name != "*"})
    return out


def resolved(func: ast.expr, aliases: dict[str, str], defs: dict) -> str:
    """Like dotted(), but through import aliases, `__import__("os")` and `getattr(os, "sys" + "tem")`."""
    if isinstance(func, ast.Name):
        return aliases.get(func.id, func.id)
    if isinstance(func, ast.Attribute):
        return resolved(func.value, aliases, defs) + "." + func.attr
    if isinstance(func, ast.Call) and func.args:
        target = dotted(func.func)
        if target in ("__import__", "importlib.import_module"):
            text, known = fold_str(func.args[0], defs)
            return text if known else "?"
        if target == "getattr" and len(func.args) >= 2:
            text, known = fold_str(func.args[1], defs)
            return resolved(func.args[0], aliases, defs) + "." + text if known else "?"
    return "?"


def names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def is_tool(fn: ast.AST) -> bool:
    return any(_is_tool_decorator(d) for d in getattr(fn, "decorator_list", []))


def functions(tree: ast.Module) -> Iterator[ast.FunctionDef | ast.AsyncFunctionDef]:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def tainted_names(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Parameters of fn plus local names assigned from them (two rounds of propagation).

    shortcut: no inter-procedural flow; a value passed through a helper function is lost.
    """
    tainted = {a.arg for a in fn.args.args + fn.args.kwonlyargs + fn.args.posonlyargs} - {"self", "cls", "ctx"}
    if fn.args.vararg:
        tainted.add(fn.args.vararg.arg)
    for _ in range(2):
        for node in ast.walk(fn):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)) and node.value is not None:
                if names_in(node.value) & tainted:
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for t in targets:
                        tainted |= names_in(t)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is not None and names_in(item.context_expr) & tainted:
                        tainted |= names_in(item.optional_vars)
    return tainted


def call_inputs(call: ast.Call) -> set[str]:
    """Names that feed a call: its arguments plus the object a method is called on."""
    used = set()
    for a in call.args:
        used |= names_in(a)
    for kw in call.keywords:
        if kw.arg != "shell":
            used |= names_in(kw.value)
    if isinstance(call.func, ast.Attribute):
        used |= names_in(call.func.value)
    return used


def is_literal(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) or (
        isinstance(node, (ast.List, ast.Tuple)) and all(isinstance(e, ast.Constant) for e in node.elts))
