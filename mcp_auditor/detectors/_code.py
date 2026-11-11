"""Copies of source files with the comments (and optionally the string contents) blanked out.

Detectors look for guard words such as `check_auth` or `allowlist`. A comment ("# TODO: add check_auth later"),
a docstring or a string must not count as a guard, so they search these copies instead of the raw text.
Blanked characters become spaces and line breaks stay, so line numbers and byte columns are the same as in the file.
"""
from __future__ import annotations

import io
import re
import tokenize

from ..models import SourceFile

LINE_BREAKS = set("\r\n\x0b\x0c\x1c\x1d\x1e\x85  ")  # what str.splitlines() splits on: keep them all
SEPARATORS = set("/\\")  # kept inside strings so a `startswith("/data/")` can be told from `startswith("#")`
# The few strings that are the guard: request.headers.get("authorization"), Header.Get("Origin")
HEADER_NAMES = re.compile(r"(?i)^\s*(authorization|x-api-key|origin)\s*$")
STRING_PARTS = re.compile(r"""(?s)^([A-Za-z]*)(\"\"\"|\'\'\'|"|')(.*)\2$""")


def _blank(text: str, keep=LINE_BREAKS) -> str:
    # one space per UTF-8 byte, so the byte columns the ast module reports still point at the same code
    return "".join(c if c in keep else " " * len(c.encode()) for c in text)


def _blank_string(token: str) -> str:
    m = STRING_PARTS.match(token)
    if not m:  # an f-string piece without quotes
        return _blank(token, LINE_BREAKS | SEPARATORS)
    prefix, quote, inner = m.groups()
    if HEADER_NAMES.match(inner):
        return token
    return prefix + quote + _blank(inner, LINE_BREAKS | SEPARATORS) + quote


def _python_spans(text: str) -> list[tuple[int, int, bool]]:
    starts = [0]
    for line in text.split("\n"):
        starts.append(starts[-1] + len(line) + 1)
    fstring_text = getattr(tokenize, "FSTRING_MIDDLE", None)  # Python 3.12+ splits f-strings into pieces
    spans = []
    for tok in tokenize.generate_tokens(io.StringIO(text).readline):
        if tok.type in (tokenize.COMMENT, tokenize.STRING) or tok.type == fstring_text:
            (r1, c1), (r2, c2) = tok.start, tok.end
            spans.append((starts[r1 - 1] + c1, starts[r2 - 1] + c2, tok.type != tokenize.COMMENT))
    return spans


def _c_like_spans(text: str) -> list[tuple[int, int, bool]]:
    """JavaScript, TypeScript and Go: // and /* */ comments, "..." '...' `...` strings.
    shortcut: regular-expression literals are not recognised; one containing a quote or // can blank a little too much."""
    spans, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end < 0 else end
            spans.append((i, end, False))
            i = end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = n if end < 0 else end + 2
            spans.append((i, end, False))
            i = end
        elif c in "\"'`":
            j = i + 1
            while j < n and text[j] != c and not (c != "`" and text[j] == "\n"):
                j += 2 if text[j] == "\\" else 1
            spans.append((i, min(j + 1, n), True))
            i = min(j + 1, n)
        else:
            i += 1
    return spans


def code_view(f: SourceFile, keep_strings: bool = False) -> SourceFile:
    """f with its comments blanked, and the inside of its strings too unless keep_strings."""
    cache = f.__dict__.setdefault("_code_views", {})
    if keep_strings not in cache:
        try:
            spans = _python_spans(f.text) if f.is_python else _c_like_spans(f.text)
        except (tokenize.TokenError, IndentationError, SyntaxError):  # not tokenizable: drop `#` comments only
            spans = [(m.start(), m.end(), False) for m in re.finditer(r"#[^\n]*", f.text)] if f.is_python else []
        out, pos = [], 0
        for start, end, is_string in sorted(spans):
            if start < pos:
                continue
            out.append(f.text[pos:start])
            out.append(f.text[start:end] if is_string and keep_strings else _blank_string(f.text[start:end]) if is_string
                       else _blank(f.text[start:end]))
            pos = end
        out.append(f.text[pos:])
        cache[keep_strings] = SourceFile(f.path, "".join(out))
    return cache[keep_strings]
