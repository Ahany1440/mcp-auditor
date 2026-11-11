"""MCP003: hard-coded secrets in server code or config.

Provider patterns are adapted from the gitleaks default rule set (MIT). A generic
`key = "value"` rule catches the rest, filtered by placeholder words and entropy.
Three more shapes are checked: unquoted `KEY=value` / `key: value` in .env, YAML and INI
files, `Bearer <token>`, and passwords inside connection URLs (`postgres://user:pw@host`).
Matched values are masked before they reach any report.
"""
from __future__ import annotations

import math
import re
from collections import Counter

from ..models import Finding, Rule, Target

RULE = Rule("MCP003", "hardcoded-secret", "Hard-coded secret in server code or config",
            "Move the value to an environment variable or a secret manager, and rotate it: anything that was "
            "committed should be treated as leaked.")

PROVIDERS = [
    ("AWS access key ID", r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    ("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    ("GitHub fine-grained token", r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    ("Anthropic API key", r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}"),
    ("OpenAI API key", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}"),
    ("Slack token", r"\bxox[abposr]-[0-9A-Za-z-]{10,}"),
    ("Slack webhook", r"https://hooks\.slack\.com/services/[A-Za-z0-9/_+-]{40,}"),
    ("Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ("Stripe secret key", r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b"),
    ("Private key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
    ("JSON Web Token", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("Hugging Face token", r"\bhf_[A-Za-z]{34}\b"),
    ("npm token", r"\bnpm_[A-Za-z0-9]{36}\b"),
]
PROVIDERS = [(name, re.compile(rx)) for name, rx in PROVIDERS]

GENERIC = re.compile(
    r"""(?i)\b([\w-]*(?:api[_-]?key|secret|token|passw(?:or)?d|access[_-]?key|auth[_-]?key)[\w-]*)["']?\s*[:=]\s*["']([^"'\s]{16,})["']""")
PLACEHOLDER = re.compile(r"(?i)your|example|xxx|changeme|placeholder|dummy|sample|redacted|<|>|\$\{|\{\{|process\.env|environ|getenv|\*\*\*")

KEY_BODY = re.compile(r"\A(?:\s|\\n|\\r)*(?:[A-Za-z0-9+/=]|\\n){64,}")
UUID = re.compile(r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

CONFIG_FILE = re.compile(r"(?i)(?:^|/)\.env[^/]*$|\.(?:env|ya?ml|ini|cfg)$")
# Unquoted values only in config files (in code, `key = name` is a variable). The key must END with the secret
# word, so `tokenizer`, `token_url` and `password_regex` are not read as secrets.
UNQUOTED = re.compile(
    r"""(?i)^\s*(?:-\s+)?(?:export\s+)?([\w.-]*(?:api[_-]?key|access[_-]?key|auth[_-]?key|secret(?:[_-]?key)?|token|passw(?:or)?d))"""
    r"""\s*[:=]\s*([^\s"'#]\S*)(?:\s+#.*)?\s*$""")
NOT_A_VALUE = re.compile(r"^[$%*&!{]|://|^(?:[./~\\]|[A-Za-z]:[\\/])")  # references, anchors, URLs and file paths
BEARER = re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{20,})")
URL_CREDS = re.compile(r"""\b([a-z][a-z0-9+.-]*)://([^\s:/@"'<>]+):([^\s@/"'<>]+)@([^\s/"'<>?#]+)""", re.I)
DOC_PASSWORDS = {"password", "passwd", "pass", "pwd", "secret", "changeme", "token", "user", "username"}
LOCAL_HOST = re.compile(r"(?i)(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?::\d+)?")


def entropy(s: str) -> float:
    return -sum(c / len(s) * math.log2(c / len(s)) for c in Counter(s).values())


def mask(value: str) -> str:
    shown = value[:4] if len(value) >= 12 else ""  # a short secret must not be printed in full
    return shown + "*" * min(len(value) - len(shown), 12) + f" ({len(value)} chars)"


def looks_secret(value: str) -> bool:
    """Not a placeholder, a list of names, a digit-free word or a UUID, and random enough."""
    # a list of secret *names* ("GITHUB_TOKEN,NPM_TOKEN", "api_key|password") is not a secret
    names_only = re.fullmatch(r"[A-Z0-9_,|. -]+", value) or re.fullmatch(r"(?i)\w+(\s*[,|]\s*\w+)+", value)
    # random secrets almost always contain a digit; theme scopes ("keyword.control.ts") and words don't.
    # UUIDs are request/record ids far more often than credentials.
    not_secret = not re.search(r"\d", value) or UUID.fullmatch(value)
    return not (PLACEHOLDER.search(value) or names_only or not_secret) and entropy(value) >= 3.5


def url_password(m: re.Match) -> str | None:
    """The password of a `scheme://user:password@host` match, unless it is a template or a docs placeholder."""
    user, pw = m.group(2), m.group(3)
    if PLACEHOLDER.search(user) or PLACEHOLDER.search(pw) or pw.lower() in DOC_PASSWORDS:
        return None
    if re.match(r"[$%{*]", pw) or re.fullmatch(r"[A-Z][A-Z0-9_]+", pw):  # ${PW}, %s, {pw}, DB_PASSWORD
        return None
    return pw


def extra_secret(f, line: str):
    """(severity, message, value) for the shapes the provider and generic rules do not see, or None."""
    m = URL_CREDS.search(line)
    pw = url_password(m) if m else None
    if pw:
        severity = "medium" if LOCAL_HOST.fullmatch(m.group(4)) else "high"  # dev databases on localhost
        return severity, f"Password embedded in a {m.group(1)}:// connection URL.", pw
    m = BEARER.search(line)
    if m and looks_secret(m.group(1)):
        return "medium", "Bearer token committed in source.", m.group(1)
    m = UNQUOTED.match(line) if CONFIG_FILE.search(f.path) else None
    if m and len(m.group(2)) >= 16 and not NOT_A_VALUE.search(m.group(2)) and looks_secret(m.group(2)):
        return "medium", f"Possible secret assigned to '{m.group(1)}'.", m.group(2)
    return None


def detect(target: Target) -> list[Finding]:
    findings = []
    for f in target.files:
        lines = f.text.splitlines()
        for n, line in enumerate(lines, 1):
            if len(line) > 2000:  # minified or generated
                continue
            hit = False
            for name, rx in PROVIDERS:
                m = rx.search(line)
                if m and PLACEHOLDER.search(m.group(0)):  # AKIAIOSFODNN7EXAMPLE, xoxb-your-token
                    m = None
                if m and name == "Private key" and not KEY_BODY.search(" ".join([line[m.end():]] + lines[n:n + 2])):
                    m = None  # only the header: a label, placeholder or code that formats keys
                if m:
                    findings.append(Finding(RULE, "high" if name != "JSON Web Token" else "medium",
                                            f"{name} committed in source.", f.path, n, evidence=mask(m.group(0))))
                    hit = True
                    break
            if hit:
                continue
            m = GENERIC.search(line)
            if m and looks_secret(m.group(2)):
                findings.append(Finding(RULE, "medium", f"Possible secret assigned to '{m.group(1)}'.", f.path, n,
                                        evidence=mask(m.group(2))))
                continue
            extra = extra_secret(f, line)
            if extra:
                findings.append(Finding(RULE, extra[0], extra[1], f.path, n, evidence=mask(extra[2])))
    return findings
