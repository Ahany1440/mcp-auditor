import unittest

from mcp_auditor.detectors import rug_pull
from tests.helpers import scan


class RugPullTest(unittest.TestCase):
    def test_bad_server(self):
        findings = {(f.file, f.severity) for f in scan(rug_pull, "rug_pull/bad")}
        self.assertEqual(findings, {
            ("server.py", "high"),     # description downloaded with httpx
            ("server.ts", "medium"),   # description from process.env
            ("server.ts", "low"),      # sendToolListChanged
        })

    def test_constructor_argument(self):
        # self.description = description in __init__ only stores the caller's value; a fetch there is still high
        findings = {(f.line, f.severity) for f in scan(rug_pull, "rug_pull/stored_arg")}
        self.assertEqual(findings, {(8, "low"), (13, "high")})

    def test_good_server(self):
        # module-level string constant and dedent("...") are static
        self.assertEqual(scan(rug_pull, "rug_pull/good"), [])


if __name__ == "__main__":
    unittest.main()
