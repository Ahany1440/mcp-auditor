"""Check a remote MCP server over Streamable HTTP, where there is no code to read.

Only sends initialize, notifications/initialized, tools/list, GETs for OAuth metadata and a
DELETE that ends the session it opened. It never calls a tool.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import re
import time
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlsplit, urlunsplit

from . import __version__
from .live import PROTOCOL_VERSION, _to_tool
from .models import Finding, Rule, Tool

RULE = Rule("MCP007", "remote-endpoint", "Remote MCP endpoint is exposed or misconfigured",
            "Require a token on any MCP endpoint that is not meant to be public, serve it over HTTPS, reject "
            "requests with an unexpected Origin header (this stops DNS rebinding), and on 401 send a WWW-Authenticate "
            "header pointing at RFC 9728 metadata whose 'resource' matches the endpoint URL.")

FAKE_ORIGIN = "https://mcp-audit.invalid"
MAX_BODY = 10 * 1024 * 1024
MAX_TOOLS = 5000  # some checks are quadratic in tools; a hostile server must not be able to stall them
NETWORK_ERRORS = (OSError, http.client.HTTPException)
# whole phrases in the message only: "Unexpected token <" or "author table missing" are not login errors
AUTH_ERROR = re.compile(r"(?i)\b(unauthori[sz]ed|unauthenticated|forbidden|access denied|(authentication|authorization|login) required"
                        r"|not (authenticated|authori[sz]ed|logged in)|(invalid|missing|expired) (api[ _-]?)?(token|key|credentials?))\b")
STANDARD_ERRORS = range(-32700, -32599)  # JSON-RPC parse, method and internal errors


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # a redirect could carry the user's token to another host


# A plain-HTTP proxy would read the token, and could answer in the server's place. HTTPS proxies only tunnel.
_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({k: v for k, v in urllib.request.getproxies().items() if k == "https"}), _NoRedirect)


class _BadTools(RuntimeError):
    """The server answered tools/list, but with something that can't be audited."""


class _Denied(Exception):
    """The server refused a request: this HTTP status, or 200 with a login-related JSON-RPC error."""
    def __init__(self, status: int, www: str):
        self.status, self.www = status, www


def safe_label(url: str) -> str:
    """The URL without its query or fragment, which can hold tokens; this text goes into reports."""
    try:
        u = urlsplit(url)
    except ValueError:
        return "(invalid URL)"
    return urlunsplit((u.scheme, u.netloc, u.path, "", ""))


def parse_headers(raw: list[str] | None) -> dict[str, str]:
    """'Name: value' strings to a dict. Error messages never repeat the value, it is usually a token."""
    out = {}
    for item in raw or []:
        name, sep, value = item.partition(":")
        name, value = name.strip(), value.strip()
        if not sep or not re.fullmatch(r"[A-Za-z0-9-]+", name) or not value or re.search(r"[\r\n]", value):
            raise ValueError("--header must look like 'Name: value', on one line")
        try:
            value.encode("latin-1")
        except UnicodeEncodeError:
            raise ValueError(f"--header {name}: the value has characters HTTP headers can't carry") from None
        out[name] = value
    return out


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _open(req: urllib.request.Request, timeout: float):
    try:
        return _OPENER.open(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        return e  # an HTTP error is an answer we want to look at, not a failure


def _is_reply(msg: dict | None, msg_id: int) -> bool:
    return bool(msg) and msg.get("id") == msg_id and "method" not in msg  # with "method" it's a request from the server


def _read_reply(resp, msg_id: int, deadline: float) -> dict:
    """The JSON-RPC reply with this id, from a JSON body or an SSE stream (which may never end by itself)."""
    is_sse = resp.headers.get("Content-Type", "").lower().startswith("text/event-stream")
    buf = b""
    while True:
        if time.monotonic() > deadline:
            raise TimeoutError(f"no reply to request {msg_id} within the timeout")
        chunk = resp.read1(65536)
        if chunk:
            buf += chunk
        if len(buf) > MAX_BODY:
            raise RuntimeError("the server's reply is too large")
        if is_sse:
            # the last piece is an unfinished event, unless the stream has ended
            events = buf.replace(b"\r\n", b"\n").replace(b"\r", b"\n").split(b"\n\n")
            for event in events if not chunk else events[:-1]:
                data = b"\n".join(line[5:].lstrip() for line in event.split(b"\n") if line.startswith(b"data:"))
                msg = _parse(data)
                if _is_reply(msg, msg_id):
                    return msg
        if not chunk:
            break
    msg = None if is_sse else _parse(buf)
    if _is_reply(msg, msg_id):
        return msg
    raise RuntimeError("the URL did not answer like an MCP server (no JSON-RPC reply). Is it the MCP endpoint?")


def _parse(data: bytes) -> dict | None:
    try:
        msg = json.loads(data)
    except (ValueError, RecursionError):
        return None
    return msg if isinstance(msg, dict) else None


class _Session:
    def __init__(self, url: str, headers: dict[str, str], deadline: float):
        self.url, self.headers, self.deadline = url, dict(headers), deadline
        self.next_id = 1

    def _post(self, msg: dict):
        req = urllib.request.Request(self.url, json.dumps({"jsonrpc": "2.0", **msg}).encode(), method="POST", headers={
            "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
            "User-Agent": f"mcp-audit/{__version__}", **self.headers})
        return _open(req, _remaining(self.deadline))

    def call(self, method: str, params: dict) -> dict:
        msg_id, self.next_id = self.next_id, self.next_id + 1
        with self._post({"id": msg_id, "method": method, "params": params}) as resp:
            if not 200 <= resp.status < 300:
                raise _Denied(resp.status, resp.headers.get("WWW-Authenticate", ""))
            session_id = resp.headers.get("Mcp-Session-Id")
            if session_id:
                self.headers["Mcp-Session-Id"] = session_id
            reply = _read_reply(resp, msg_id, self.deadline)
        error = reply.get("error")
        if error:
            code = error.get("code") if isinstance(error, dict) else None
            code = code if isinstance(code, int) else "?"
            text = error.get("message") if isinstance(error, dict) else None
            if code not in STANDARD_ERRORS and isinstance(text, str) and AUTH_ERROR.search(text):
                raise _Denied(200, f"JSON-RPC error {code}")
            raise RuntimeError(f"the server answered {method} with JSON-RPC error {code}")
        if not isinstance(reply.get("result"), dict):
            raise RuntimeError(f"the server's answer to {method} has no result. Is it an MCP endpoint?")
        return reply["result"]

    def initialize(self) -> None:
        result = self.call("initialize", {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                                          "clientInfo": {"name": "mcp-audit", "version": __version__}})
        version = result.get("protocolVersion")
        if not isinstance(version, str) or not re.fullmatch(r"[\w.-]+", version):
            raise RuntimeError("the URL did not answer initialize like an MCP server. Is it the MCP endpoint?")
        self.headers["MCP-Protocol-Version"] = version
        self._post({"method": "notifications/initialized"}).close()

    def list_tools(self, times: int) -> list[list[Tool]]:
        snapshots = []
        for _ in range(max(times, 1)):
            tools, cursor = [], None
            while True:  # an endless cursor loop is stopped by the session deadline in _read_reply
                result = self.call("tools/list", {"cursor": cursor} if cursor else {})
                raw = result.get("tools")
                if not isinstance(raw, list) or not all(isinstance(t, dict) for t in raw):
                    raise _BadTools("the server's tools/list answer is malformed, so its tools can't be checked")
                if len(tools) + len(raw) > MAX_TOOLS:
                    raise _BadTools(f"the server lists more than {MAX_TOOLS} tools; not scanning that")
                try:
                    tools += [_to_tool(t) for t in raw]
                except (AttributeError, TypeError):
                    raise _BadTools("a tool definition from the server is malformed, so it can't be checked") from None
                cursor = result.get("nextCursor")
                if not cursor:
                    break
            snapshots.append(tools)
        return snapshots

    def close(self) -> None:
        """End the session we opened, so the scan leaves nothing behind. Best effort."""
        if "Mcp-Session-Id" not in self.headers:
            return
        try:
            _open(urllib.request.Request(self.url, method="DELETE", headers=self.headers), min(_remaining(self.deadline), 5)).close()
        except NETWORK_ERRORS:
            pass


def _remaining(deadline: float) -> float:
    return max(deadline - time.monotonic(), 0.1)


def _explain(e: _Denied, url: str) -> RuntimeError:
    if e.status == 200:
        return RuntimeError(f"the server refused the request ({e.www})")
    if e.status == 405:
        # shortcut: the old HTTP+SSE transport is not spoken, add it if people need those servers scanned
        return RuntimeError("the server refused POST (HTTP 405). It may use the old HTTP+SSE transport, "
                            "which --url doesn't support, or this isn't the MCP endpoint")
    if 300 <= e.status < 400:
        return RuntimeError(f"HTTP {e.status} redirect, which is not followed so a token can't leak. "
                            f"Point --url at the final address")
    return RuntimeError(f"{safe_label(url)} answered HTTP {e.status} to an MCP initialize. Is it the MCP endpoint?")


def _get_json(url: str, deadline: float) -> dict | None:
    """Fetch public metadata (never with the user's headers). None if there's nothing usable there."""
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": f"mcp-audit/{__version__}"})
        with _open(req, _remaining(deadline)) as resp:
            return _parse(resp.read(MAX_BODY)) if resp.status == 200 else None
    except NETWORK_ERRORS:
        return None


def _norm_url(url: str) -> str:
    u = urlsplit(url)
    return urlunsplit((u.scheme.lower(), u.netloc.lower(), u.path.rstrip("/"), u.query, ""))


def _oauth_findings(url: str, www: str, deadline: float) -> list[Finding]:
    """What a client can learn about logging in after a 401 (RFC 9728)."""
    u = urlsplit(url)
    root = urlunsplit((u.scheme, u.netloc, "", "", ""))
    declared = re.search(r'resource_metadata="([^"]+)"', www)
    findings = []
    if not www:
        findings.append(Finding(RULE, "low", "The 401 reply has no WWW-Authenticate header, so clients can't tell how to log in."))
    if declared:
        where = urljoin(url, declared.group(1))
        target = urlsplit(where)
        if target.netloc != u.netloc or target.scheme not in ("http", "https"):
            # never fetch a URL on another host just because the server named it
            return findings + [Finding(RULE, "low", "The OAuth metadata is on another host or not on HTTP(S), so it was not checked.",
                                       evidence=safe_label(where)[:200])]
        candidates = [where]
    else:
        path = u.path.rstrip("/")
        candidates = [root + "/.well-known/oauth-protected-resource" + path] * bool(path)
        candidates.append(root + "/.well-known/oauth-protected-resource")
    meta = next(filter(None, (_get_json(c, deadline) for c in candidates)), None)
    if meta is None:
        return findings + [Finding(RULE, "low", "No usable RFC 9728 OAuth metadata found, so OAuth clients can't discover "
                                                "how to log in. Fine if this server uses API keys instead.")]
    resource = meta.get("resource")
    if not isinstance(resource, str):
        findings.append(Finding(RULE, "medium", "OAuth metadata has no 'resource', which RFC 9728 requires."))
    elif _norm_url(resource) != _norm_url(safe_label(url)):
        findings.append(Finding(RULE, "medium", "OAuth metadata names a different resource than this endpoint, which RFC 9728 "
                                                "says clients must reject.", evidence=resource[:200]))
    servers = meta.get("authorization_servers")
    if not isinstance(servers, list) or not servers:
        findings.append(Finding(RULE, "low", "OAuth metadata lists no authorization_servers, so clients don't know where to get a token."))
    return findings


def _origin_finding(url: str, headers: dict[str, str], deadline: float, is_open: bool, local: bool) -> Finding | None:
    unknown = Finding(RULE, "low", "Could not tell whether the server checks the Origin header: the test request failed.")
    probe = _Session(url, {**headers, "Origin": FAKE_ORIGIN}, deadline)
    try:
        probe.initialize()
    except _Denied as e:
        # a 500 or a rate limit says nothing about Origin, and must not pass as "rejected"
        return None if e.status in (200, 400, 401, 403) else unknown
    except TimeoutError:
        return Finding(RULE, "low", "Could not tell whether the server checks the Origin header: the scan ran out of time. Try a higher --timeout.")
    except (RuntimeError, *NETWORK_ERRORS):
        return unknown
    finally:
        probe.close()
    severity = "low" if not is_open else "high" if local else "medium"
    why = ("any web page you open could reach this local server through DNS rebinding" if is_open and local else
           "any web page could call it from a visitor's browser if its CORS rules allow that" if is_open else
           "a login is still needed, so the risk is small, but the MCP spec requires this check")
    return Finding(RULE, severity, f"The server accepted a request with a foreign Origin header: {why}.",
                   evidence=f"Origin: {FAKE_ORIGIN}")


def _merge_anonymous(snapshots: list[list[Tool]], anonymous: list[Tool]) -> None:
    """Tools shown only to anonymous callers still reach clients, so they get audited too."""
    key = lambda t: json.dumps(t.raw, sort_keys=True)
    known = {key(t) for t in snapshots[0]}
    only_anon = [t for t in anonymous if key(t) not in known]
    for snapshot in snapshots:
        snapshot += only_anon


def scan(url: str, headers: dict[str, str], timeout: float, times: int) -> tuple[list[list[Tool]], list[Finding]]:
    """Return one tools/list snapshot per repeat (empty if a login is needed and no token given), and the findings."""
    if re.search(r"[^\x21-\x7e]", url):
        raise ValueError("--url has spaces, control or non-ASCII characters; percent-encode them")
    u = urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("--url needs a full http:// or https:// address")
    if u.username or u.password:
        raise ValueError("don't put credentials in the --url address, use --header")
    has_credentials = bool(headers or u.query)  # the query string may be how this server takes its key
    local = _is_loopback(u.hostname)
    deadline = time.monotonic() + timeout
    findings = []
    if u.scheme == "http" and not local:
        if has_credentials:
            raise ValueError("refusing to send --header or a query string over plain HTTP to another machine; use https://")
        findings.append(Finding(RULE, "high", "The endpoint uses plain HTTP, so anyone on the network path can read or change its traffic."))

    try:
        # always try with no credentials first: this is the question "is it open to anyone?"
        anon, anonymous, denied, inconclusive = _Session(safe_label(url), {}, deadline), None, None, False
        try:
            try:
                anon.initialize()
                anonymous = anon.list_tools(1)
            except _Denied as e:
                denied = e
            except _BadTools:
                raise  # it answered, so it is open, and tools we can't read must not pass as checked
            except RuntimeError:
                if not has_credentials:
                    raise
                inconclusive = True  # with credentials, a login page here says nothing about the real answer
            if denied and denied.status not in (200, 401, 403):
                if not has_credentials:
                    raise _explain(denied, url)
                inconclusive = True
            is_open = anonymous is not None
            if is_open:
                findings.append(Finding(RULE, "medium" if local else "high",
                                        f"Anyone who can reach this endpoint can list its {len(anonymous[0])} tool(s) without logging in. "
                                        "Only fine for a public, read-only server, and calling tools may be open too (not tested)."))
            elif inconclusive:
                findings.append(Finding(RULE, "low", "Could not tell whether the endpoint is open without credentials: "
                                                     "the attempt without them failed in a way that isn't a login refusal."))
            elif denied.status == 401:
                findings += _oauth_findings(url, denied.www, deadline)

            # before the repeated calls: a slow server running out of budget must not cost a high finding
            if has_credentials or is_open:
                origin = _origin_finding(url, headers, deadline, is_open, local)
                if origin:
                    findings.append(origin)

            if has_credentials:
                session = _Session(url, headers, deadline)
                try:
                    session.initialize()
                    snapshots = session.list_tools(times)
                except _Denied as e:
                    if e.status in (200, 401, 403):
                        raise RuntimeError("the server rejected the credentials") from None
                    raise _explain(e, url) from None
                finally:
                    session.close()
                if is_open:
                    _merge_anonymous(snapshots, anonymous[0])
            elif is_open:
                snapshots = anonymous + (anon.list_tools(times - 1) if times > 1 else [])
            else:
                snapshots = None
                how = "with a login error" if denied.status == 200 else f"with HTTP {denied.status}"
                findings.append(Finding(RULE, "low", f"The endpoint refused the request {how}, so it needs a login or "
                                                     "isn't an MCP server. Its tools and Origin check were not tested. Pass "
                                                     "--header \"Authorization: Bearer ...\" to include them."))
        finally:
            anon.close()
    except TimeoutError:
        raise TimeoutError(f"{safe_label(url)} did not answer within --timeout") from None
    return snapshots or [], findings
