"""MCP005: HTTP/SSE transport with no sign of inbound authentication.

A stdio server is only reachable by the process that started it. An SSE or
streamable-HTTP server is reachable by anything that can open a socket to it,
including web pages via DNS rebinding when it listens on localhost. If the codebase
starts such a transport and nothing in it checks an incoming credential, flag it.
"""
from __future__ import annotations

import re

from ..models import Finding, Rule, Target

RULE = Rule("MCP005", "missing-auth", "HTTP/SSE transport without authentication",
            "Require a credential on every request (the MCP authorization spec uses OAuth 2.1 bearer tokens; "
            "an API-key header is the minimum), check the Origin header, and bind to 127.0.0.1 unless the "
            "server must be remote.")

TRANSPORT = re.compile(
    r"""transport\s*[=:]\s*["'](sse|streamable-http|streamable_http|http)["']"""
    r"|\b(SseServerTransport|SSEServerTransport|StreamableHTTPServerTransport)\b"
    r"|\.(sse_app|streamable_http_app|http_app)\("
    r"|\b(NewSSEServer|NewStreamableHTTPServer)\(")
INBOUND_AUTH = re.compile(
    r"(?i)AuthSettings|TokenVerifier|auth_?(server_)?provider|requireBearerAuth|bearerAuth|BearerAuthBackend"
    r"|(req|request)\.headers(\.get\(\s*|\[\s*)[\"'](authorization|x-api-key)"
    r"|headers\.authorization|Header\.Get\(\s*\"(Authorization|X-API-Key)\""
    r"|auth_?middleware|AuthenticationMiddleware|passport\.|verify_?(token|api_?key|jwt)|check_?auth|WithAuth\w*\("
    # raw ASGI header lookups and constant-time token comparison are inbound checks too
    r"|\.get\(\s*b[\"']authorization|Bearer\w*Middleware|Token\w*Middleware|compare_digest\(|timingSafeEqual\(")
ORIGIN_CHECK = re.compile(r"(?i)origin_?validation|allowed_?origins|validate_?origin|headers\.origin|Header\.Get\(\s*\"Origin\"|TrustedOrigins")
ALL_INTERFACES =re.compile(r"""["']0\.0\.0\.0["']|["']::["']|host\s*[=:]\s*["']["']""")


def detect(target: Target) -> list[Finding]:
    code = [f for f in target.files if f.is_code]
    if any(INBOUND_AUTH.search(f.text) for f in code):
        return []
    findings = []
    for f in code:
        # point at where the transport is used, not where it is imported
        lines = [f.line_of(m.start()) for m in TRANSPORT.finditer(f.text)]
        used = [n for n in lines if not re.match(r"(import|from)\b", f.line_text(n))]
        line = next((n for n in used if re.search(r"(Transport|_app|Server)\(|\.run\(", f.line_text(n))), used[0] if used else None)
        if line is None:
            continue
        exposed = bool(ALL_INTERFACES.search(f.text))
        origin_checked = any(ORIGIN_CHECK.search(c.text) for c in code)
        sev = "critical" if exposed else "medium" if origin_checked else "high"
        findings.append(Finding(
            RULE, sev,
            "Server starts an HTTP/SSE transport and no inbound authentication was found in the codebase"
            + (", and it binds to all network interfaces." if exposed else
               " (an Origin check limits browser-based attacks, but any local process can still connect)."
               if origin_checked else "."),
            f.path, line, evidence=f.line_text(line)))
    return findings
