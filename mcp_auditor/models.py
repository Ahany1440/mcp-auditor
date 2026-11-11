"""Plain data types shared by the loader, the detectors and the reporters."""
from __future__ import annotations

import re
from bisect import bisect_left
from dataclasses import dataclass, field
from functools import cached_property
from itertools import accumulate
from pathlib import PurePosixPath

SEVERITIES = ["low", "medium", "high", "critical"]  # ordered, lowest first

CODE_SUFFIXES = {".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".tsx", ".jsx", ".go"}


def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity)


@dataclass
class Rule:
    id: str          # e.g. "MCP001"
    name: str        # e.g. "tool-poisoning"
    title: str       # one line
    help: str        # what it means and how to fix it


@dataclass
class Finding:
    rule: Rule
    severity: str
    message: str
    file: str | None = None      # path relative to the scanned root, forward slashes
    line: int | None = None
    tool: str | None = None      # name of the MCP tool involved, if any
    evidence: str | None = None  # short snippet; secrets are masked before they get here


@dataclass
class Tool:
    """One tool the server exposes, as found in source code or returned by tools/list."""
    name: str
    description: str = ""
    params: dict[str, str] = field(default_factory=dict)  # parameter name -> description
    file: str | None = None
    line: int | None = None
    end_line: int | None = None  # last line of the handler, when the handler is known
    source: str = "static"       # "static" or "live"
    extra: list[tuple[str, str]] = field(default_factory=list)  # (where, text): parameter names, titles, enums, defaults...
    raw: dict | None = None      # the full definition as returned by tools/list (live tools only)
    unresolved: list[str] = field(default_factory=list)  # text the scanner could not work out, e.g. ["description"]


def schema_texts(schema, where: str = "input schema") -> list[tuple[str, str]]:
    """Every string in a JSON schema that ends up in the model's context, labelled with where it sits."""
    out: list[tuple[str, str]] = []
    if not isinstance(schema, dict):
        return out
    for key in ("title", "description", "default"):
        if isinstance(schema.get(key), str):
            out.append((f"{where} {key}", schema[key]))
    for key in ("enum", "examples"):
        for v in schema.get(key) or []:
            if isinstance(v, str):
                out.append((f"{where} {key} value", v))
    props = schema.get("properties")
    for name, sub in (props.items() if isinstance(props, dict) else []):
        out.append(("parameter name", str(name)))
        out += schema_texts(sub, f"parameter '{name}'")
    for key in ("items", "additionalProperties"):
        out += schema_texts(schema.get(key), f"{where} items")
    for key in ("anyOf", "oneOf", "allOf"):
        for sub in schema.get(key) or []:
            out += schema_texts(sub, where)
    for key in ("$defs", "definitions"):
        defs = schema.get(key)
        for name, sub in (defs.items() if isinstance(defs, dict) else []):
            out += schema_texts(sub, f"schema definition '{name}'")
    return out


@dataclass
class SourceFile:
    path: str  # relative, forward slashes
    text: str

    @property
    def suffix(self) -> str:
        return PurePosixPath(self.path).suffix.lower()

    @property
    def is_code(self) -> bool:
        return self.suffix in CODE_SUFFIXES

    @property
    def is_python(self) -> bool:
        return self.suffix == ".py"

    # Line tables are built once per file: detectors ask for a line number or line text once per tool, and
    # re-counting or re-splitting the whole file each time made big files take quadratic time.
    @cached_property
    def _newlines(self) -> list[int]:
        return [m.start() for m in re.finditer(r"\n", self.text)]

    @cached_property
    def lines(self) -> list[str]:
        return self.text.splitlines()

    @cached_property
    def line_ends(self) -> list[int]:
        """line_ends[k] is the offset where line k+1 starts, by splitlines() rules (which can differ from newline counting)."""
        return [0, *accumulate(len(l) for l in self.text.splitlines(True))]

    def line_of(self, offset: int) -> int:
        return bisect_left(self._newlines, offset) + 1

    def line_text(self, line: int) -> str:
        return self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""

    @cached_property
    def _ast_lines(self) -> list[str]:
        return re.findall(r"[^\r\n]*(?:\r\n|[\r\n])|[^\r\n]+", self.text)  # how ast splits source: not on form feeds

    def segment(self, node) -> str | None:
        """ast.get_source_segment(self.text, node), without re-splitting the whole file for every node."""
        if getattr(node, "end_lineno", None) is None or getattr(node, "end_col_offset", None) is None:
            return None
        lines, a, b = self._ast_lines, node.lineno - 1, node.end_lineno - 1
        if a == b:
            return lines[a].encode()[node.col_offset:node.end_col_offset].decode()
        return lines[a].encode()[node.col_offset:].decode() + "".join(lines[a + 1:b]) + lines[b].encode()[:node.end_col_offset].decode()


@dataclass
class Target:
    label: str                      # what the user passed (path or URL)
    files: list[SourceFile] = field(default_factory=list)
    tools: list[Tool] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)  # {"path", "reason", "files"}: code that was not scanned
    from_source: bool = False  # loaded from a folder/file/repo (not only from a live tools/list)

    def file(self, path: str) -> SourceFile | None:
        return next((f for f in self.files if f.path == path), None)

    def tool_at(self, path: str, line: int) -> Tool | None:
        """The static tool whose handler contains this line, if any."""
        for t in self.tools:
            if t.file == path and t.line and t.end_line and t.line <= line <= t.end_line:
                return t
        return None
