import unittest

from mcp_auditor.detectors import missing_auth
from tests.helpers import scan


class MissingAuthTest(unittest.TestCase):
    def test_bad_server(self):
        findings = scan(missing_auth, "missing_auth/bad")
        self.assertEqual([(f.file, f.line, f.severity) for f in findings], [("index.ts", 6, "critical")])

    def test_good_server(self):
        self.assertEqual(scan(missing_auth, "missing_auth/good"), [])


if __name__ == "__main__":
    unittest.main()
