import unittest

from mcp_auditor.detectors import broad_capabilities
from mcp_auditor.models import Target, Tool
from tests.helpers import scan


class BroadCapabilitiesTest(unittest.TestCase):
    def test_bad_server(self):
        findings = scan(broad_capabilities, "broad_capabilities/bad")
        got = {(f.tool, f.severity) for f in findings}
        self.assertEqual(got, {("run_command", "high"), ("read_file", "medium"),
                               ("http_get", "medium"), ("write_file", "medium")})

    def test_good_server(self):
        # read_config opens a fixed path, read_file checks is_relative_to / startsWith
        self.assertEqual(scan(broad_capabilities, "broad_capabilities/good"), [])

    def test_live_tool_uses_description(self):
        tool = Tool("exec", "Execute any shell command on the host.", source="live")
        findings = broad_capabilities.detect(Target("live", [], [tool]))
        self.assertEqual([f.severity for f in findings], ["medium"])


if __name__ == "__main__":
    unittest.main()
