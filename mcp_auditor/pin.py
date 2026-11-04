"""Pin a server's tool definitions and report what changed since (rug-pull protection).

A static scan says whether a description *can* change. A pin catches it when it *does*:
the first run with --pin saves every tool's definition, later runs compare against it.
The same comparison is used between repeated tools/list calls in one live session.
"""
from __future__ import annotations

import difflib
import json
from pathlib import Path

from . import __version__
from .detectors.rug_pull import RULE
from .models import Finding, Tool


def definition(tool: Tool) -> dict:
    """What the model sees for this tool, without source positions (so moving code isn't a change)."""
    if tool.raw is not None:
        return tool.raw
    return {"name": tool.name, "description": tool.description, "params": tool.params,
            "schema_text": [list(x) for x in tool.extra]}


def snapshot(tools: list[Tool]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for t in tools:
        key, n = f"{t.source}:{t.name}", 2
        while key in out:  # two tools with the same name (e.g. names set at runtime)
            key, n = f"{t.source}:{t.name}#{n}", n + 1
        out[key] = definition(t)
    return out


def save(path: str, tools: list[Tool]) -> None:
    data = {"pinned_by": f"mcp-audit {__version__}", "tools": snapshot(tools)}
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def load(path: str) -> dict[str, dict]:
    return json.loads(Path(path).read_text(encoding="utf-8"))["tools"]


def compare(old: dict[str, dict], tools: list[Tool], since: str) -> list[Finding]:
    """Findings for tools added, changed or removed relative to `old`. `since` finishes the sentence."""
    new = snapshot(tools)
    by_key = dict(zip(new, tools))
    sources = {k.split(":", 1)[0] for k in new}
    findings = []
    for key, d in new.items():
        t = by_key[key]
        if key not in old:
            findings.append(Finding(RULE, "medium", f"Tool '{t.name}' is new {since}. Review it before trusting it.",
                                    t.file, t.line, t.name, t.description[:120]))
        elif old[key] != d:
            fields = sorted(k for k in set(old[key]) | set(d) if old[key].get(k) != d.get(k))
            findings.append(Finding(RULE, "high", f"Tool '{t.name}' changed {since} ({', '.join(fields)}).",
                                    t.file, t.line, t.name, _first_difference(old[key], d)))
    for key in old:
        # only report removals for the kind of scan that ran this time (static vs live)
        if key not in new and key.split(":", 1)[0] in sources:
            name = key.split(":", 1)[1]
            findings.append(Finding(RULE, "low", f"Tool '{name}' was removed {since}.", tool=name))
    return findings


def _first_difference(old: dict, new: dict) -> str:
    for k in sorted(set(old) | set(new)):  # a changed text field reads best as plain before/after
        if old.get(k) != new.get(k) and isinstance(old.get(k), str) and isinstance(new.get(k), str):
            return f"{k} was: {old[k][:100]!r} now: {new[k][:140]!r}"
    a = json.dumps(old, sort_keys=True, ensure_ascii=False)
    b = json.dumps(new, sort_keys=True, ensure_ascii=False)
    for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if op != "equal":
            return f"was: {a[max(i1 - 20, 0):i2 + 20]!r} now: {b[max(j1 - 20, 0):j2 + 60]!r}"[:240]
    return ""
