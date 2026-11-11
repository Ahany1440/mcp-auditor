"""Load a server's files (local folder or GitHub URL) and find the tools it defines.

Tool discovery is static: Python is parsed with `ast`, JavaScript/TypeScript and Go
are matched with regular expressions for the common SDK call shapes. See DESIGN.md
for what this misses.
"""
from __future__ import annotations

import ast
import os
import re
import subprocess
import tempfile
from pathlib import Path

from .models import CODE_SUFFIXES, SourceFile, Target, Tool, schema_texts

SCAN_SUFFIXES = {".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".tsx", ".jsx", ".go",
                 ".json", ".yaml", ".yml", ".toml", ".env", ".ini", ".cfg"}
SKIP_DIRS = {".git", "node_modules", "dist", "build", "out", ".venv", "venv", "env", "__pycache__",
             "vendor", "site-packages", ".next", "coverage", ".tox", ".mypy_cache"}
TEST_DIRS = {"test", "tests", "__tests__", "testdata", "fixtures", "e2e"}
TEST_FILE = re.compile(r"(^test_.*\.py$|_test\.(py|go)$|\.(test|spec)\.[cm]?[jt]sx?$)")
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock", "go.sum"}
MAX_BYTES = 1_000_000

GITHUB_URL = re.compile(r"^https://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?(?:/tree/([^/]+)(?:/(.*))?)?/?$")


# ---------------------------------------------------------------- loading

def _count_code(folder: Path) -> int:
    return sum(Path(n).suffix.lower() in CODE_SUFFIXES for _, _, names in os.walk(folder) for n in names)


def load_files(root: Path, skipped: list[dict] | None = None) -> list[SourceFile]:
    """Read the scannable files. Everything code-like that is left out is appended to `skipped`
    (a folder counts as one entry with the number of code files inside), so a scan never hides it."""
    skipped = [] if skipped is None else skipped
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        keep = []
        for d in sorted(dirnames):
            if d in SKIP_DIRS or d.lower() in TEST_DIRS:
                n = _count_code(Path(dirpath, d))
                if n:
                    skipped.append({"path": Path(dirpath, d).relative_to(root).as_posix() + "/", "files": n,
                                    "reason": "test folder" if d.lower() in TEST_DIRS else "dependency or build folder"})
            else:
                keep.append(d)
        dirnames[:] = keep
        for name in sorted(filenames):
            p = Path(dirpath, name)
            rel = p.relative_to(root).as_posix()
            is_code = p.suffix.lower() in CODE_SUFFIXES

            def skip(reason: str) -> None:
                skipped.append({"path": rel, "files": 1, "reason": reason})
            if name in SKIP_FILES:
                continue
            if TEST_FILE.search(name):
                if is_code:
                    skip("test file")
                continue
            if p.suffix.lower() not in SCAN_SUFFIXES and not name.startswith(".env"):
                continue
            if is_code and name.endswith((".min.js", ".d.ts")):
                skip("minified file" if name.endswith(".min.js") else "type declarations")
                continue
            try:
                if p.stat().st_size > MAX_BYTES:
                    skip(f"larger than {MAX_BYTES // 1_000_000} MB")
                    continue
                text = p.read_text(encoding="utf-8", errors="replace")  # one bad byte must not drop the file
            except OSError as e:
                skip(f"unreadable ({e.strerror or 'I/O error'})")
                continue
            files.append(SourceFile(rel, text))
    return files


def clone_github(url: str, into: str) -> Path:
    """Shallow-clone a GitHub URL (optionally .../tree/<branch>/<subdir>) and return the folder to scan."""
    m = GITHUB_URL.match(url)
    if not m:
        raise ValueError(f"not a GitHub repository URL: {url}")
    owner, repo, branch, sub = m.groups()
    cmd = ["git", "clone", "--quiet", "--depth", "1"]
    if branch:
        cmd += ["--branch", branch]
    cmd += [f"https://github.com/{owner}/{repo}.git", into]
    subprocess.run(cmd, check=True, timeout=300)
    root = Path(into, sub) if sub else Path(into)
    if not root.is_dir():
        raise ValueError(f"path '{sub}' not found in {owner}/{repo}")
    return root


def load_target(label: str, root: Path) -> Target:
    skipped: list[dict] = []
    files = load_files(root, skipped)
    tools = []
    for f in files:
        if f.is_python:
            tools += python_tools(f)
        elif f.suffix in {".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".tsx", ".jsx"}:
            tools += js_tools(f)
        elif f.suffix == ".go":
            tools += go_tools(f)
    return Target(label, files, tools, skipped, True)


def open_target(path_or_url: str, workdir: str | None = None) -> tuple[Target, Path]:
    """Return the loaded target and the folder it was read from."""
    if path_or_url.startswith(("https://", "http://")):
        workdir = workdir or tempfile.mkdtemp(prefix="mcp-audit-")
        root = clone_github(path_or_url, workdir)
    else:
        root = Path(path_or_url)
        if not root.exists():
            raise FileNotFoundError(f"no such file or folder: {path_or_url}")
        if root.is_file():  # a single server file: scan just that
            return load_target_single(path_or_url, root), root.parent
    return load_target(path_or_url, root), root


def load_target_single(label: str, path: Path) -> Target:
    sf = SourceFile(path.name, path.read_text(encoding="utf-8", errors="replace"))
    tools = python_tools(sf) if sf.is_python else go_tools(sf) if sf.suffix == ".go" else js_tools(sf)
    return Target(label, [sf], tools, from_source=True)


# ---------------------------------------------------------------- Python

def _is_tool_decorator(dec: ast.expr) -> bool:
    func = dec.func if isinstance(dec, ast.Call) else dec
    return (isinstance(func, ast.Attribute) and func.attr == "tool") or (isinstance(func, ast.Name) and func.id == "tool")


def py_defs(tree: ast.Module) -> dict[str, ast.expr | None]:
    """Module-level `NAME = expr`. A name assigned more than once (or augmented) maps to None: its value isn't known."""
    defs: dict[str, ast.expr | None] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets, value = [t for t in node.targets if isinstance(t, ast.Name)], node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            targets, value = [node.target], node.value
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            targets, value = [node.target], None
        else:
            continue
        for t in targets:
            defs[t.id] = None if t.id in defs or value is None else value
    return defs


def fold_str(node: ast.AST, defs: dict, _seen: tuple = ()) -> tuple[str, bool]:
    """The text of a string expression (literals, module constants, `+`, f-strings of those) and whether all of it
    was known. Parts that are not known become a space, so the known parts can still be checked."""
    if isinstance(node, ast.Constant):
        return (node.value, True) if isinstance(node.value, str) else ("", True)
    if isinstance(node, ast.Name):
        value = defs.get(node.id)
        if value is None or node.id in _seen:
            return " ", False
        return fold_str(value, defs, _seen + (node.id,))
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        (a, known_a), (b, known_b) = fold_str(node.left, defs, _seen), fold_str(node.right, defs, _seen)
        return a + b, known_a and known_b
    if isinstance(node, ast.JoinedStr):
        parts = [fold_str(v.value if isinstance(v, ast.FormattedValue) else v, defs, _seen) for v in node.values]
        plain = all(not isinstance(v, ast.FormattedValue) or (v.conversion == -1 and v.format_spec is None) for v in node.values)
        return "".join(p for p, _ in parts), plain and all(known for _, known in parts)
    if isinstance(node, ast.Call):  # dedent("""..."""), cleandoc(...), "...".strip(): only whitespace changes
        name = getattr(node.func, "id", getattr(node.func, "attr", None))
        if name in ("dedent", "cleandoc") and len(node.args) == 1 and not node.keywords:
            return fold_str(node.args[0], defs, _seen)
        if name in ("strip", "lstrip", "rstrip") and isinstance(node.func, ast.Attribute) and not node.args:
            return fold_str(node.func.value, defs, _seen)
    return " ", False


def _kw_text(call: ast.AST, name: str, defs: dict) -> tuple[str | None, bool]:
    """(text, fully known) of the keyword argument `name`; (None, True) when it is not there."""
    if isinstance(call, ast.Call):
        for kw in call.keywords:
            if kw.arg == name:
                return fold_str(kw.value, defs)
    return None, True


def _str_of(value: ast.AST | None, defs: dict, any_constant: bool = False) -> str | None:
    """A string constant, or a constant expression that folds to text; None for anything else."""
    if isinstance(value, ast.Constant):
        return str(value.value) if any_constant or isinstance(value.value, str) else None
    if isinstance(value, (ast.Name, ast.BinOp, ast.JoinedStr)):
        text = fold_str(value, defs)[0]
        return text if text.strip() else None
    return None


def _literal(node: ast.AST, defs: dict, _seen: tuple = ()):
    """Like ast.literal_eval, but names that hold module-level constants and `"a" + "b"` are followed."""
    if isinstance(node, ast.Name):
        value = defs.get(node.id)
        if value is None or node.id in _seen:
            raise ValueError(node.id)
        return _literal(value, defs, _seen + (node.id,))
    if isinstance(node, (ast.BinOp, ast.JoinedStr)):
        text, known = fold_str(node, defs, _seen)
        if known:
            return text
        raise ValueError("not a constant")
    if isinstance(node, ast.Dict):
        if any(k is None for k in node.keys):
            raise ValueError("dict unpacking")
        return {_literal(k, defs, _seen): _literal(v, defs, _seen) for k, v in zip(node.keys, node.values)}
    if isinstance(node, (ast.List, ast.Tuple)):
        return [_literal(e, defs, _seen) for e in node.elts]
    return ast.literal_eval(node)


def _descriptions_in(node: ast.AST, defs: dict) -> list[str]:
    """Every string passed as `description=...` or under a "description" dict key inside node."""
    out = []
    for n in ast.walk(node):
        if isinstance(n, ast.keyword) and n.arg == "description":
            text = _str_of(n.value, defs, any_constant=True)
            if text is not None:
                out.append(text)
        elif isinstance(n, ast.Dict):
            for k, v in zip(n.keys, n.values):
                if isinstance(k, ast.Constant) and k.value == "description":
                    text = _str_of(v, defs, any_constant=True)
                    if text is not None:
                        out.append(text)
    return out


def imports_mcp(f: SourceFile) -> bool:
    """Only treat Tool(...) calls as MCP tools in files that import the MCP SDK (other libraries have a Tool too)."""
    return bool(re.search(r"^\s*(from\s+mcp[\s.]|import\s+mcp\b)", f.text, re.M))


def _field_strings(node: ast.AST | None, defs: dict) -> list[tuple[str, str]]:
    """title=, default= and examples= strings inside a parameter annotation such as Field(...)."""
    out = []
    for n in ast.walk(node) if node is not None else []:
        if isinstance(n, ast.keyword) and n.arg in ("title", "default", "examples"):
            if isinstance(n.value, (ast.Name, ast.BinOp, ast.JoinedStr)):
                text = _str_of(n.value, defs)
                if text is not None:
                    out.append((n.arg, text))
                continue
            for c in ast.walk(n.value):
                if isinstance(c, ast.Constant) and isinstance(c.value, str):
                    out.append((n.arg, c.value))
    return out


def python_tools(f: SourceFile) -> list[Tool]:
    try:
        tree = ast.parse(f.text)
    except SyntaxError:
        return []
    defs = py_defs(tree)
    tools = []
    sdk = imports_mcp(f)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            dec = next((d for d in node.decorator_list if _is_tool_decorator(d)), None)
            if dec is None:
                continue
            params, extra = {}, []
            args = node.args.args + node.args.kwonlyargs
            # positional defaults line up with the last positional args; kw-only defaults are listed per arg
            defaults = dict(zip([a.arg for a in node.args.args][::-1], node.args.defaults[::-1]))
            defaults.update({a.arg: d for a, d in zip(node.args.kwonlyargs, node.args.kw_defaults) if d is not None})
            for a in args:
                if a.arg in ("self", "ctx", "context"):
                    continue
                descs = _descriptions_in(a.annotation, defs) if a.annotation else []
                params[a.arg] = " ".join(descs)
                extra.append(("parameter name", a.arg))
                extra += [(f"parameter '{a.arg}' {k}", v) for k, v in _field_strings(a.annotation, defs)]
                default = _str_of(defaults.get(a.arg), defs)
                if default is not None:
                    extra.append((f"parameter '{a.arg}' default", default))
            name, _ = _kw_text(dec, "name", defs)
            desc, known = _kw_text(dec, "description", defs)
            tools.append(Tool(
                name=name if name and name.strip() else node.name,
                description=desc if desc and desc.strip() else ast.get_docstring(node, clean=False) or "",
                params=params, file=f.path, line=node.lineno, end_line=node.end_lineno, extra=extra,
                unresolved=["description"] if desc is not None and not known else []))
        elif sdk and isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", None)) == "Tool":
            name_expr = next((kw.value for kw in node.keywords if kw.arg == "name"), None)
            if name_expr is None:
                continue
            text, known = fold_str(name_expr, defs)
            name = text if known and text else ast.unparse(name_expr)  # e.g. "self.name" when set at runtime
            schema = next((kw.value for kw in node.keywords if kw.arg in ("inputSchema", "input_schema")), None)
            params = {f"param{i}": d for i, d in enumerate(_descriptions_in(schema, defs))} if schema else {}
            try:  # a literal schema can be walked in full; one built from variables only partly
                extra = schema_texts(_literal(schema, defs)) if schema else []
            except (ValueError, TypeError):
                extra = []
            desc, known = _kw_text(node, "description", defs)
            tools.append(Tool(name, desc if desc and desc.strip() else "", params, f.path, node.lineno, extra=extra,
                              unresolved=["description"] if desc is not None and not known else []))
    return tools


# ---------------------------------------------------------------- JavaScript / TypeScript / Go

_STR = r"""(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|`((?:\\.|[^`\\])*)`)"""  # one string literal, 3 groups
JS_TOOL_CALL = re.compile(r"\.(?:tool|registerTool|addTool)\(\s*" + _STR, re.S)
_STR_RE = re.compile(_STR, re.S)
JS_TOOL_OBJ = re.compile(r"\bname\s*:\s*" + _STR + r"\s*,\s*(?:title\s*:\s*" + _STR + r"\s*,\s*)?description\s*:\s*", re.S)
JS_COMMA = re.compile(r"\s*,\s*")
JS_DESC_KEY = re.compile(r"\bdescription\s*:\s*|\.describe\(\s*")
JS_CONST = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;\n]+)?=\s*")  # `const d = ...` (a TS type is ok)
JS_CHAIN = re.compile(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*")
JS_PLUS = re.compile(r"\s*\+\s*")
JS_NOT_OVER = re.compile(r"\s*[.(\[+*/%?&|<>=!:-]")  # the expression goes on: `.repeat(3)`, `? a : b`, `== x`
JS_PLACEHOLDER = re.compile(r"\$\{\s*([A-Za-z_$][\w$]*)\s*\}")
# mark3labs/mcp-go: mcp.NewTool("name", mcp.WithDescription("..."))
# official go-sdk:  mcp.Tool{Name: "name", Description: "..."}  (or Description: t("KEY", "default text"))
JS_PARAM_NAME = re.compile(r"\b([A-Za-z_$][\w$]*)\s*:\s*z\.")  # zod: { city: z.string() }
GO_TOOL = re.compile(r"\bNewTool\(\s*\"((?:\\.|[^\"\\])*)\"|\bmcp\.Tool\{\s*Name:\s*\"((?:\\.|[^\"\\])*)\"")
GO_DESC = re.compile(r"\b(?:(?:WithDescription|Description)\(\s*|Description:\s*(?:\w+\(\s*\"[^\"]*\"\s*,\s*)?)\"((?:\\.|[^\"\\])*)\"")
WINDOW_LINES = 80  # shortcut: a JS/Go tool's handler is assumed to sit within the next 80 lines or before the next tool


def _unescape(s: str) -> str:
    s = re.sub(r"\\u\{([0-9a-fA-F]+)\}", lambda m: chr(int(m.group(1), 16)), s)
    s = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), s)
    s = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), s)
    return s.replace("\\n", "\n").replace("\\t", "\t").replace('\\"', '"').replace("\\'", "'").replace("\\`", "`")


def _first(groups) -> str:
    return _unescape(next((g for g in groups if g is not None), ""))


def _skip_group(text: str, pos: int) -> int | None:
    """Index after the bracket group that opens at pos, or None. Strings inside are skipped."""
    depth, i = 0, pos
    while i < len(text):
        c = text[i]
        if c in "\"'`":
            m = _STR_RE.match(text, i)
            if not m:
                return None
            i = m.end()
            continue
        depth += (c in "([{") - (c in ")]}")
        i += 1
        if depth == 0:
            return i
    return None


def _js_operand(text: str, pos: int, env: dict) -> tuple[str, bool, bool, int] | None:
    """One operand of a `+` chain at pos: (text, fully known, is a string literal, end). Known constants are
    replaced by their value; calls, members and other names count as unknown (a space)."""
    m = _STR_RE.match(text, pos)
    if m:
        s = _first(m.groups())
        if m.group(3) is not None and "${" in s:  # template literal: `${NAME}` of a known constant is filled in
            s = JS_PLACEHOLDER.sub(lambda p: env[p.group(1)] if env.get(p.group(1)) is not None else p.group(0), s)
        return s, "${" not in s, True, m.end()
    m = JS_CHAIN.match(text, pos)
    if not m:
        return None
    end, plain = m.end(), True
    while True:
        if text[end:end + 1] in ("(", "["):
            end, plain = _skip_group(text, end) or len(text), False
        elif text[end:end + 1] == "." and re.match(r"\.[A-Za-z_$]", text[end:end + 2]):  # `.then(...)` after a call
            end, plain = JS_CHAIN.match(text, end + 1).end(), False
        else:
            break
    value = env.get(m.group(0)) if plain and "." not in m.group(0) else None
    return (value, True, False, end) if value is not None else (" ", False, False, end)


def _js_expr(text: str, pos: int, env: dict, lone_name: bool = False, strict: bool = False) -> tuple[str, bool] | None:
    """Read `"a" + CONST + "b"` at pos. Returns (text, fully known), or None when it is not a string expression.
    A single unknown name is skipped unless lone_name (after `description:` it is a description; in a call it
    may just as well be a handler or a schema). strict also rejects `"a".repeat(3)` and `"a" ? b : c`."""
    parts, known, literal, n = [], True, False, 0
    while (op := _js_operand(text, pos, env)) is not None:
        s, ok, is_literal, pos = op
        parts.append(s)
        known, literal, n = known and ok, literal or is_literal, n + 1
        plus = JS_PLUS.match(text, pos)
        if not plus:
            break
        pos = plus.end()
    if n == 0 or (n == 1 and not literal and not known and not lone_name):
        return None
    if strict and JS_NOT_OVER.match(text, pos):
        return None
    return "".join(parts), known


def js_constants(text: str) -> dict[str, str | None]:
    """`const NAME = "..." + "..."` in the file. A name defined more than once with different values maps to None."""
    env: dict[str, str | None] = {}
    for m in JS_CONST.finditer(text):
        found = _js_expr(text, m.end(), env, lone_name=True, strict=True)
        value = found[0] if found and found[1] else None
        env[m.group(1)] = value if m.group(1) not in env or env[m.group(1)] == value else None
    return env


def _js_descriptions(f: SourceFile, start: int, end: int, env: dict) -> list[tuple[str, bool]]:
    """(text, fully known) for every `description: ...` and `.describe(...)` between start and end."""
    found = (_js_expr(f.text, m.end(), env, lone_name=True) for m in JS_DESC_KEY.finditer(f.text, start, max(end, start)))
    return [r for r in found if r is not None]


def _go_descriptions(f: SourceFile, start: int, end: int, env: dict) -> list[tuple[str, bool]]:
    return [(_first(m.groups()), True) for m in GO_DESC.finditer(f.text, start, max(end, start))]


def _windowed(f: SourceFile, hits: list[tuple[int, str]], describe, first_desc_is_tool: bool, env: dict) -> list[Tool]:
    """Turn (offset, name) hits into tools whose descriptions come from the text up to the next hit."""
    tools = []
    hits.sort()
    for i, (start, name) in enumerate(hits):
        end = hits[i + 1][0] if i + 1 < len(hits) else len(f.text)
        line = f.line_of(start)
        ends = f.line_ends
        end = min(end, ends[min(line - 1 + WINDOW_LINES, len(ends) - 1)])
        descs = describe(f, start, end, env)
        unresolved = ["description"] if descs and not descs[0][1] else []
        desc = descs.pop(0)[0] if descs and first_desc_is_tool else ""
        # a description that was not text at all (`description: fn()`) is a space: not worth listing as a parameter
        texts = [d for d, _ in descs if d.strip()]
        names = [("parameter name", n) for n in JS_PARAM_NAME.findall(f.text, start, max(end, start))] if describe is _js_descriptions else []
        tools.append(Tool(name, desc, {f"param{j}": d for j, d in enumerate(texts)}, f.path, line,
                          f.line_of(max(end - 1, start)), extra=names, unresolved=unresolved))
    return tools


def js_tools(f: SourceFile) -> list[Tool]:
    tools = []
    env = js_constants(f.text)
    # `.tool("name", "description", ...)`: the description is the next argument, a string or a constant expression.
    call_tools = []
    for m in JS_TOOL_CALL.finditer(f.text):
        comma = JS_COMMA.match(f.text, m.end())
        call_tools.append((m.start(), _first(m.groups()), _js_expr(f.text, comma.end(), env) if comma else None))
    own_desc: dict[tuple[int, str], tuple[str, bool] | None] = {}
    for s, n, d in call_tools:
        own_desc.setdefault((f.line_of(s), n), d)
    for t in _windowed(f, [(s, n) for s, n, _ in call_tools], _js_descriptions, False, env):
        own = own_desc[(t.line, t.name)]
        if own is not None:
            t.description, t.unresolved = own[0], [] if own[1] else ["description"]
        else:  # registerTool("name", { description: "..." }) style
            first = next(iter(t.params.values()), "")
            t.description, t.params = first, dict(list(t.params.items())[1:])
        tools.append(t)
    # `{ name: "x", description: "y", inputSchema: {...} }` style (low-level SDK)
    taken = {t.line for t in tools}
    hits = [(m.start(), _first(m.groups()[0:3])) for m in JS_TOOL_OBJ.finditer(f.text)
            if f.line_of(m.start()) not in taken and _js_expr(f.text, m.end(), env) is not None]
    for t in _windowed(f, hits, _js_descriptions, True, env):
        t.end_line = None  # the handler of a low-level tool lives elsewhere
        tools.append(t)
    return tools


def go_tools(f: SourceFile) -> list[Tool]:
    return _windowed(f, [(m.start(), _unescape(m.group(1) or m.group(2))) for m in GO_TOOL.finditer(f.text)],
                     _go_descriptions, True, {})
