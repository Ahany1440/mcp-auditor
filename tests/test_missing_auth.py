import tempfile
import unittest
from pathlib import Path

from mcp_auditor.detectors import missing_auth
from mcp_auditor.source import load_target
from tests.helpers import scan


class MissingAuthTest(unittest.TestCase):
    def test_bad_server(self):
        findings = scan(missing_auth, "missing_auth/bad")
        self.assertEqual([(f.file, f.line, f.severity) for f in findings], [("index.ts", 6, "critical")])

    def test_good_server(self):
        self.assertEqual(scan(missing_auth, "missing_auth/good"), [])

    def test_asgi_bearer_middleware_counts_as_auth(self):
        code = (
            "import hmac\n"
            "class BearerTokenMiddleware:\n"
            "    async def __call__(self, scope, receive, send):\n"
            "        header = dict(scope['headers']).get(b'authorization', b'')\n"
            "        if not hmac.compare_digest(header, self.token): return\n"
            "app = server.streamable_http_app(host=host)\n"
        )
        with tempfile.TemporaryDirectory() as d:
            Path(d, "http.py").write_text(code, encoding="utf-8")
            self.assertEqual(missing_auth.detect(load_target("tmp", Path(d))), [])


if __name__ == "__main__":
    unittest.main()
