import unittest

from mcp_auditor.detectors import unsafe_exec
from tests.helpers import scan


class UnsafeExecTest(unittest.TestCase):
    def test_bad_server(self):
        findings = {(f.file, f.line, f.severity) for f in scan(unsafe_exec, "unsafe_exec/bad")}
        self.assertEqual(findings, {
            ("server.py", 7, "high"),        # os.system(cmd), cmd built from a parameter
            ("server.py", 13, "critical"),   # shell=True with a tool parameter
            ("server.js", 4, "critical"),    # exec(`...${host}`) inside a tool
            ("main.go", 6, "medium"),        # sh -c, outside any tool handler
        })

    def test_good_server(self):
        # list-form subprocess, constant shell command, execFile, and regex .exec() are all fine
        self.assertEqual(scan(unsafe_exec, "unsafe_exec/good"), [])


if __name__ == "__main__":
    unittest.main()
