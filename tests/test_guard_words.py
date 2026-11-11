"""Words in comments and strings must not switch off MCP002 / MCP005; real checks still must."""
import tempfile
import unittest
from pathlib import Path

from mcp_auditor.detectors import broad_capabilities, missing_auth
from mcp_auditor.detectors._code import code_view
from mcp_auditor.models import SourceFile
from mcp_auditor.source import load_target

PY_HEAD = "import os\nfrom pathlib import Path\nfrom mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n"
JS_HEAD = 'import fs from "fs";\nimport { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\nconst server = new McpServer({ name: "x" });\n'


def run(detector, name: str, text: str, extra: dict | None = None) -> list:
    with tempfile.TemporaryDirectory() as d:
        for n, t in {name: text, **(extra or {})}.items():
            Path(d, n).write_text(t, encoding="utf-8")
        return detector.detect(load_target("tmp", Path(d)))


def py_tool(body: str, imports: str = "") -> str:
    return f"{PY_HEAD}{imports}\nROOT = Path('data').resolve()\n\n@mcp.tool()\ndef read(path: str) -> str:\n    \"\"\"Read a file.\"\"\"\n{body}\n"


def js_tool(body: str) -> str:
    return f'{JS_HEAD}server.tool("read", "Read a file", {{}}, async ({{ path }}) => {{\n{body}\n}});\n'


class CodeViewTest(unittest.TestCase):
    def test_comments_and_strings_are_blanked_but_positions_stay(self):
        text = 'x = "é allow_list"  # check_auth\nprint(x)  # é\ny = "Authorization"\n'
        view = code_view(SourceFile("a.py", text))
        self.assertNotIn("check_auth", view.text)
        self.assertNotIn("allow_list", view.text)
        self.assertIn('"Authorization"', view.text)  # header names stay: they are the guard
        self.assertEqual(view.text.count("\n"), text.count("\n"))
        self.assertEqual(len(view.text.encode()), len(text.encode()))  # byte columns are unchanged

    def test_js_comments_and_strings(self):
        view = code_view(SourceFile("a.js", 'a("verify_token"); // verify_token\n/* verify_token\n */ b(`verify_token`);\n'))
        self.assertNotIn("verify_token", view.text)

    def test_unparseable_python_still_loses_its_comments(self):
        self.assertNotIn("check_auth", code_view(SourceFile("a.py", "def (:\n  # check_auth\n")).text)


class MissingAuthTest(unittest.TestCase):
    SERVER = 'from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("x")\n{extra}\nif __name__ == "__main__":\n    mcp.run(transport="sse")\n'

    def findings(self, extra: str, name: str = "server.py") -> list:
        return run(missing_auth, name, self.SERVER.format(extra=extra))

    def test_todo_comment_does_not_count(self):
        self.assertEqual(len(self.findings("# TODO: add check_auth later")), 1)

    def test_docstring_and_string_do_not_count(self):
        self.assertEqual(len(self.findings('"""Needs verify_token and BearerAuthBackend one day."""\nNOTE = "AuthSettings"')), 1)

    def test_block_comment_in_javascript_does_not_count(self):
        js = 'import { SSEServerTransport } from "sdk";\n// TODO requireBearerAuth\n/* verify_token(req) */\nconst t = new SSEServerTransport("/m", res);\n'
        self.assertEqual(len(run(missing_auth, "server.js", js)), 1)

    def test_real_auth_code_suppresses(self):
        for extra in ("settings = AuthSettings(issuer_url='https://x')", "def verify_token(t):\n    return t == 'a'\n",
                      "def mw(request):\n    return request.headers.get('authorization')"):
            self.assertEqual(self.findings(extra), [], extra)
        js = 'import { SSEServerTransport } from "sdk";\napp.use((req, res) => { if (!req.headers["authorization"]) throw 1; });\nnew SSEServerTransport("/m", res);\n'
        self.assertEqual(run(missing_auth, "server.js", js), [])

    def test_a_commented_out_transport_is_not_a_transport(self):
        code = 'from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("x")\n# mcp.run(transport="sse", host="0.0.0.0")\nmcp.run()\n'
        self.assertEqual(run(missing_auth, "server.py", code), [])

    def test_a_comment_does_not_make_it_critical(self):
        findings = self.findings("# bind 0.0.0.0 only in docker")
        self.assertEqual(findings[0].severity, "high")


class BroadCapabilitiesTest(unittest.TestCase):
    def flagged(self, findings, count=1):
        self.assertEqual(len(findings), count, [f.message for f in findings])

    def test_comment_does_not_count(self):
        self.flagged(run(broad_capabilities, "s.py", py_tool("    # TODO: add an allowlist\n    return open(path).read()")))

    def test_docstring_and_string_do_not_count(self):
        body = '    """Only paths in ALLOWED_PATHS, checked with is_relative_to."""\n    note = "allowed_paths realpath"\n    return open(path).read()'
        self.flagged(run(broad_capabilities, "s.py", py_tool(body)))

    def test_startswith_of_a_non_path_literal_is_not_a_check(self):
        self.flagged(run(broad_capabilities, "s.py", py_tool('    if path.startswith("#"):\n        path = path[1:]\n    return open(path).read()')))

    def test_a_guard_that_does_not_use_the_input_is_not_a_check(self):
        self.flagged(run(broad_capabilities, "s.py", py_tool("    allowed = ALLOWED_PATHS = ['a']\n    return open(path).read()")))

    def test_comment_before_shell_and_network_calls(self):
        shell = "    # whitelist of commands lives elsewhere\n    return os.popen(path).read()"
        net = "    # ALLOWED_HOSTS is checked upstream\n    return requests.get(path).text"
        self.flagged(run(broad_capabilities, "s.py", py_tool(shell)))
        self.flagged(run(broad_capabilities, "s.py", py_tool(net, "import requests")))

    def test_real_checks_still_suppress(self):
        for body in ("    full = (ROOT / path).resolve()\n    if not full.is_relative_to(ROOT):\n        raise ValueError(path)\n    return full.read_text()",
                     "    if path not in ALLOWED_PATHS:\n        raise ValueError(path)\n    return open(path).read()",
                     "    if not os.path.realpath(path).startswith(str(ROOT)):\n        raise ValueError(path)\n    return open(path).read()",
                     '    if not path.startswith("/srv/data/"):\n        raise ValueError(path)\n    return open(path).read()'):
            self.assertEqual(run(broad_capabilities, "s.py", py_tool(body)), [], body)

    def test_javascript_comment_and_string_do_not_count(self):
        self.flagged(run(broad_capabilities, "s.js", js_tool("  // TODO: add an allowlist\n  return fs.readFileSync(path);")))
        self.flagged(run(broad_capabilities, "s.js", js_tool('  /* ALLOWED_PATHS, validatePath */\n  const n = "isRelativeTo";\n  return fs.readFileSync(path);')))

    def test_javascript_startswith_of_a_non_path_literal(self):
        self.flagged(run(broad_capabilities, "s.js", js_tool('  if (path.startsWith("#")) path = path.slice(1);\n  return fs.readFileSync(path);')))

    def test_javascript_real_checks_still_suppress(self):
        for body in ("  const full = path.resolve(ROOT, p);\n  return fs.readFileSync(full);",
                     "  if (!full.startsWith(root)) throw new Error('no');\n  return fs.readFileSync(full);",
                     '  if (!full.startsWith("/srv/data/")) throw 1;\n  return fs.readFileSync(full);',
                     "  const full = validatePath(path);\n  return fs.readFileSync(full);"):
            self.assertEqual(run(broad_capabilities, "s.js", js_tool(body)), [], body)


if __name__ == "__main__":
    unittest.main()
