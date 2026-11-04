"""Plain data types shared by the loader, the detectors and the reporters."""
from __future__ import annotations

from dataclasses import dataclass, field
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

    def line_of(self, offset: int) -> int:
        return self.text.count("\n", 0, offset) + 1

    def line_text(self, line: int) -> str:
        lines = self.text.splitlines()
        return lines[line - 1].strip() if 0 < line <= len(lines) else ""


@dataclass
class Target:
    label: str                      # what the user passed (path or URL)
    files: list[SourceFile] = field(default_factory=list)
    tools: list[Tool] = field(default_factory=list)

    def file(self, path: str) -> SourceFile | None:
        return next((f for f in self.files if f.path == path), None)

    def tool_at(self, path: str, line: int) -> Tool | None:
        """The static tool whose handler contains this line, if any."""
        for t in self.tools:
            if t.file == path and t.line and t.end_line and t.line <= line <= t.end_line:
                return t
        return None
