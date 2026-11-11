"""MCP001: hidden instructions in tool names, descriptions and parameter descriptions.

The model reads every tool description, the user usually does not. Text in there that
gives the model orders, hides things from the user, points at credential files or is
invisible/encoded is the "tool poisoning" attack.
"""
from __future__ import annotations

import base64
import binascii
import re

from ..models import Finding, Rule, Target

RULE = Rule("MCP001", "tool-poisoning", "Hidden instructions in tool metadata",
            "Tool names and descriptions are sent to the model as trusted context. Remove instructions aimed at "
            "the model, references to secrets or other tools, invisible characters and encoded blobs. A tool "
            "description should only say what the tool does.")

# (pattern, severity, explanation). Patterns are matched case-insensitively against one text field.
PHRASES = [
    (r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|any|other|system)\b.{0,25}\b(instructions?|prompts?|rules|guidelines|context)\b",
     "critical", "tells the model to ignore its other instructions"),
    (r"\b(do not|don't|never|must not)\b.{0,30}\b(tell|inform|mention|reveal|show|notify|alert)\b.{0,40}\buser\b",
     "critical", "tells the model to hide something from the user"),
    (r"\bwithout\b.{0,20}\b(telling|informing|notifying|asking|alerting)\b.{0,25}\buser\b",
     "critical", "tells the model to act without the user's knowledge"),
    (r"<\s*/?\s*(important|system|instructions?|secret|hidden|admin)\s*>",
     "high", "contains a pseudo system/IMPORTANT tag"),
    (r"(~/\.ssh|\bid_(rsa|ed25519)\b|\.aws/credentials|/etc/(passwd|shadow)|\.netrc\b|\.git-credentials)",
     "high", "mentions a credential file"),
    # MCP config files hold API keys, but tools that set up MCP clients name them for honest reasons
    (r"(\bmcp\.json\b|claude_desktop_config|\.cursor/)",
     "medium", "mentions an MCP client config file (these often hold API keys)"),
    (r"\b(read|send|pass|include|copy|append|forward|leak|upload)\b.{0,50}\b(api[ _-]?keys?|access tokens?|passwords?|credentials?|secrets?|private keys?|ssh keys?)\b",
     "medium", "asks for secrets to be read or passed along"),
    (r"\b(instead of|rather than)\s+(using|calling|the)\b.{0,40}\btool\b|\b(other|another|every|all)\s+(mcp\s+)?tools?\b.{0,60}\b(must|should|always|never)\b",
     "high", "tries to change how other tools are used (tool shadowing)"),
]
PHRASES = [(re.compile(p, re.I | re.S), s, why) for p, s, why in PHRASES]

INVISIBLE = re.compile("[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]")
BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
TAG_CHARS = re.compile("[\U000e0020-\U000e007e]+")
BASE64 = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")
LONG_DESCRIPTION = 1500


SENTENCE_END = re.compile(r"[.!?](?=\s|$)|\n")
DEFENSIVE_OK = {"mentions a credential file", "mentions an MCP client config file (these often hold API keys)",
                "asks for secrets to be read or passed along"}
EXFIL_VERB = re.compile(r"(?i)\b(read|send|pass|include|copy|append|forward|upload|cat)\b")
NEGATION = re.compile(r"(?i)\b(never|not|no|n't|refused|rejected|blocked|denied|forbidden|excluded|redact\w*|without)\b")


# England/Scotland/Wales flags are emoji tag sequences: U+1F3F4, tag letters, U+E007F
EMOJI_FLAG = re.compile("\U0001f3f4[\U000e0020-\U000e007e]+\U000e007f")
BIDI_OVERRIDE = re.compile("[\u202a-\u202e]")
SANITIZER = re.compile("\\[[^\\]]*[\u202a-\u202e\u2066-\u2069]|['\"][\u202a-\u202e\u2066-\u2069]['\"]")


def _isolates_balanced(line: str) -> bool:
    return sum(line.count(c) for c in "\u2066\u2067\u2068") == line.count("\u2069")


def _sentence(text: str, m: re.Match) -> str:
    """The sentence around a match; a dot inside "mcp.json" or "~/.ssh" does not end a sentence."""
    bounds = [b.end() for b in SENTENCE_END.finditer(text)]
    start = max([b for b in bounds if b <= m.start()], default=0)
    end = min([b for b in bounds if b >= m.end()], default=len(text))
    return text[start:end]


def humanize(name: str) -> str:
    """ignore_previousInstructions -> "ignore previous Instructions", so phrase patterns match identifiers too."""
    return re.sub(r"[_\-.]+", " ", re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name))


def check_text(text: str) -> list[tuple[str, str, str]]:
    """Return (severity, reason, evidence) for one metadata string. Used for tools and by tests."""
    out = []
    for rx, sev, why in PHRASES:
        m = rx.search(text)
        if m:
            if why in DEFENSIVE_OK and NEGATION.search(_sentence(text, m)):
                # "credentials are NOT exposed", "never send secrets", "id_rsa is refused": usually a safety note,
                # but negation is cheap to fake, so keep it visible at medium instead of dropping it
                sev, why = "medium", why + " (in a sentence with a negation; likely a safety note)"
            elif why.startswith("mentions an MCP client config") and EXFIL_VERB.search(_sentence(text, m)):
                sev, why = "high", "asks for an MCP client config file (these hold API keys) to be read or passed along"
            out.append((sev, why, m.group(0)))
    hidden = INVISIBLE.findall(text)
    if hidden:
        codes = ", ".join(sorted({f"U+{ord(c):04X}" for c in hidden}))
        smuggled = "".join(chr(ord(c) - 0xE0000) for run in TAG_CHARS.findall(text) for c in run)
        evidence = f"hidden text decodes to: {smuggled!r}" if smuggled else codes
        out.append(("high", f"contains {len(hidden)} invisible Unicode character(s) ({codes})", evidence))
    for m in BASE64.finditer(text):
        if m.group(0).count("/") > len(m.group(0)) / 15:
            continue  # a URL or file path ("com/Documentation/Splunk/..."); base64 has a '/' about once in 64
        try:
            decoded = base64.b64decode(m.group(0) + "=" * (-len(m.group(0)) % 4)).decode("utf-8")
            readable = sum(c.isprintable() or c.isspace() for c in decoded) / max(len(decoded), 1) > 0.9
        except (binascii.Error, UnicodeDecodeError):
            readable = False
        out.append(("high", "contains base64 that decodes to readable text", decoded[:120]) if readable
                   else ("medium", "contains a long base64-like blob", m.group(0)[:60] + "..."))
    if len(text) > LONG_DESCRIPTION:
        out.append(("low", f"is unusually long ({len(text)} characters); long text is an easy place to hide instructions", text[:80] + "..."))
    return out


def detect(target: Target) -> list[Finding]:
    findings = []
    flagged_invisible: set[tuple[str, int]] = set()
    named = sorted({t.name for t in target.tools if len(t.name) >= 4 and "_" in t.name})
    named = [(name, name.lower()) for name in named]
    for tool in target.tools:
        if "description" in tool.unresolved:  # built from something the scanner can't evaluate: say so, don't pass it
            findings.append(Finding(RULE, "medium", f"Tool '{tool.name}' description could not be resolved to text, "
                                    "so it was not fully checked for hidden instructions.", tool.file, tool.line, tool.name))
        fields = [("name", tool.name), ("description", tool.description)]
        fields += [(f"parameter '{p}' description" if not p.startswith("param") else "a parameter description", d)
                   for p, d in tool.params.items()]
        fields += tool.extra  # parameter names, titles, enum values, defaults, nested schema text
        seen = set()
        for field, text in fields:
            if not text or text in seen:
                continue  # the same string can be reached twice (e.g. a description via params and via the schema)
            seen.add(text)
            if field in ("name", "parameter name"):
                text = humanize(text)
            for sev, why, evidence in check_text(text):
                findings.append(Finding(RULE, sev, f"Tool '{tool.name}' {field} {why}.", tool.file, tool.line,
                                        tool.name, evidence.strip()[:200]))
                if "invisible" in why and tool.file:
                    flagged_invisible.update((tool.file, n) for n in range(tool.line or 0, (tool.end_line or tool.line or 0) + 1))
        # A description that tells the model to call some other tool is how cross-tool hijacking starts.
        lowered = tool.description.lower()
        for other, low in named:
            if low not in lowered or other == tool.name:  # the plain check first: servers can list thousands of tools
                continue
            m = re.search(rf"\b(call|use|run|invoke|send|pass)\b.{{0,40}}\b{re.escape(other)}\b.{{0,40}}", tool.description, re.I | re.S)
            if m:
                # "Use read_text_file instead" is normal cross-referencing; ordering the model around is less so
                pushy = re.search(r"\b(always|first|before|must|every time)\b", m.group(0), re.I)
                findings.append(Finding(RULE, "medium" if pushy else "low",
                                        f"Tool '{tool.name}' description tells the model to use another tool ('{other}')"
                                        + ("; check the instruction is intended." if pushy else "."),
                                        tool.file, tool.line, tool.name, m.group(0).strip()))
    # Bidi controls and tag characters anywhere in source can hide code from review ("Trojan Source",
    # CVE-2021-42574). Zero-width joiners, LRM/RLM and BOMs are normal in emoji and RTL text, so skip them here.
    for f in target.files:
        for n, line in enumerate(f.text.splitlines(), 1):
            bidi, tags = BIDI.search(line), TAG_CHARS.search(EMOJI_FLAG.sub("", line))
            if (bidi or tags) and (f.path, n) not in flagged_invisible:
                codes = ", ".join(sorted({f"U+{ord(c):04X}" for c in INVISIBLE.findall(line)}))
                # code that strips these characters lists them in a regex class or as literals; paired
                # isolates (FSI ... PDI) are how localized text is wrapped. Neither reorders the code around it.
                defensive = bool(SANITIZER.search(line)) or (not BIDI_OVERRIDE.search(line) and _isolates_balanced(line))
                findings.append(Finding(RULE, "medium" if defensive else "high",
                                        f"Source line contains {'bidirectional control' if bidi else 'Unicode tag'} characters ({codes}).",
                                        f.path, n, evidence=INVISIBLE.sub("\ufffd", line.strip())[:200]))
    return findings
