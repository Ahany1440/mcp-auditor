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


def _const_kwarg(call: ast.AST, name: str) -> str | None:
    if isinstance(call, ast.Call):
        for kw in call.keywords:
            if kw.arg == name and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                return kw.value.value
    return None


def _descriptions_in(node: ast.AST) -> list[str]:
    """Every string passed as `description=...` or under a "description" dict key inside node."""
    out = []
    for n in ast.walk(node):
        if isinstance(n, ast.keyword) and n.arg == "description" and isinstance(n.value, ast.Constant):
            out.append(str(n.value.value))
        elif isinstance(n, ast.Dict):
            for k, v in zip(n.keys, n.values):
                if isinstance(k, ast.Constant) and k.value == "description" and isinstance(v, ast.Constant):
                    out.append(str(v.value))
    return out


def imports_mcp(f: SourceFile) -> bool:
    """Only treat Tool(...) calls as MCP tools in files that import the MCP SDK (other libraries have a Tool too)."""
    return bool(re.search(r"^\s*(from\s+mcp[\s.]|import\s+mcp\b)", f.text, re.M))


def _field_strings(node: ast.AST | None) -> list[tuple[str, str]]:
    """title=, default= and examples= strings inside a parameter annotation such as Field(...)."""
    out = []
    for n in ast.walk(node) if node is not None else []:
        if isinstance(n, ast.keyword) and n.arg in ("title", "default", "examples"):
            for c in ast.walk(n.value):
                if isinstance(c, ast.Constant) and isinstance(c.value, str):
                    out.append((n.arg, c.value))
    return out


def python_tools(f: SourceFile) -> list[Tool]:
    try:
        tree = ast.parse(f.text)
    except SyntaxError:
        return []
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
                descs = _descriptions_in(a.annotation) if a.annotation else []
                params[a.arg] = " ".join(descs)
                extra.append(("parameter name", a.arg))
                extra += [(f"parameter '{a.arg}' {k}", v) for k, v in _field_strings(a.annotation)]
                d = defaults.get(a.arg)
                if isinstance(d, ast.Constant) and isinstance(d.value, str):
                    extra.append((f"parameter '{a.arg}' default", d.value))
            tools.append(Tool(
                name=_const_kwarg(dec, "name") or node.name,
                description=_const_kwarg(dec, "description") or ast.get_docstring(node, clean=False) or "",
                params=params, file=f.path, line=node.lineno, end_line=node.end_lineno, extra=extra))
        elif sdk and isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", None)) == "Tool":
            name_expr = next((kw.value for kw in node.keywords if kw.arg == "name"), None)
            if name_expr is None:
                continue
            name = _const_kwarg(node, "name") or ast.unparse(name_expr)  # e.g. "self.name" when set at runtime
            schema = next((kw.value for kw in node.keywords if kw.arg in ("inputSchema", "input_schema")), None)
            params = {f"param{i}": d for i, d in enumerate(_descriptions_in(schema))} if schema else {}
            try:  # a literal schema can be walked in full; one built from variables only partly
                extra = schema_texts(ast.literal_eval(schema)) if schema else []
            except ValueError:
                extra = []
            tools.append(Tool(name, _const_kwarg(node, "description") or "", params, f.path, node.lineno, extra=extra))
    return tools


# ---------------------------------------------------------------- JavaScript / TypeScript / Go

_STR = r"""(?:"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)'|`((?:\\.|[^`\\])*)`)"""  # one string literal, 3 groups
JS_TOOL_CALL = re.compile(r"\.(?:tool|registerTool|addTool)\(\s*" + _STR, re.S)
JS_TOOL_OBJ = re.compile(r"\bname\s*:\s*" + _STR + r"\s*,\s*(?:title\s*:\s*" + _STR + r"\s*,\s*)?description\s*:\s*" + _STR, re.S)
JS_SECOND_STR = re.compile(r"\s*,\s*" + _STR, re.S)  # the description argument right after a tool name
JS_DESC = re.compile(r"(?:\bdescription\s*:\s*|\.describe\(\s*)" + _STR, re.S)
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


def _windowed(f: SourceFile, hits: list[tuple[int, str]], desc_re: re.Pattern, first_desc_is_tool: bool) -> list[Tool]:
    """Turn (offset, name) hits into tools whose descriptions come from the text up to the next hit."""
    tools = []
    hits.sort()
    for i, (start, name) in enumerate(hits):
        end = hits[i + 1][0] if i + 1 < len(hits) else len(f.text)
        line = f.line_of(start)
        ends = f.line_ends
        end = min(end, ends[min(line - 1 + WINDOW_LINES, len(ends) - 1)])
        descs = [_first(m.groups()) for m in desc_re.finditer(f.text, start, max(end, start))]
        desc = descs.pop(0) if descs and first_desc_is_tool else ""
        names = [("parameter name", n) for n in JS_PARAM_NAME.findall(f.text, start, max(end, start))] if desc_re is JS_DESC else []
        tools.append(Tool(name, desc, {f"param{j}": d for j, d in enumerate(descs)}, f.path, line,
                          f.line_of(max(end - 1, start)), extra=names))
    return tools


def js_tools(f: SourceFile) -> list[Tool]:
    tools = []
    # `.tool("name", "description", ...)`: the description is the next string argument.
    call_tools = []
    for m in JS_TOOL_CALL.finditer(f.text):
        dm = JS_SECOND_STR.match(f.text, m.end())
        call_tools.append((m.start(), _first(m.groups()), _first(dm.groups()) if dm else None))
    own_desc: dict[tuple[int, str], str | None] = {}
    for s, n, d in call_tools:
        own_desc.setdefault((f.line_of(s), n), d)
    for t in _windowed(f, [(s, n) for s, n, _ in call_tools], JS_DESC, False):
        own = own_desc[(t.line, t.name)]
        if own is not None:
            t.description = own
        else:  # registerTool("name", { description: "..." }) style
            first = next(iter(t.params.values()), "")
            t.description, t.params = first, dict(list(t.params.items())[1:])
        tools.append(t)
    # `{ name: "x", description: "y", inputSchema: {...} }` style (low-level SDK)
    taken = {t.line for t in tools}
    hits = [(m.start(), _first(m.groups()[0:3])) for m in JS_TOOL_OBJ.finditer(f.text) if f.line_of(m.start()) not in taken]
    for t in _windowed(f, hits, JS_DESC, True):
        t.end_line = None  # the handler of a low-level tool lives elsewhere
        tools.append(t)
    return tools


def go_tools(f: SourceFile) -> list[Tool]:
    return _windowed(f, [(m.start(), _unescape(m.group(1) or m.group(2))) for m in GO_TOOL.finditer(f.text)], GO_DESC, True)
