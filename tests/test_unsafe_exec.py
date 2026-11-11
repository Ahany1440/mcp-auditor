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

    def test_sandboxed_evaluator(self):
        # exec/eval stays high; the message notes the mitigation only when a check of the input stops the
        # function first AND __builtins__ is swapped
        findings = {(f.line, f.severity, "It runs only after" in f.message)
                    for f in scan(unsafe_exec, "unsafe_exec/sandboxed")}
        self.assertEqual(findings, {
            (18, "high", True),     # validate() first, then exec with replaced builtins
            (22, "high", False),    # builtins replaced, but nothing checks the input
            (28, "high", False),    # input checked, but the real builtins are passed
            (34, "high", False),    # a length limit is not a check
            (43, "high", True),     # checked, then exec inside try with a builtins dict built before it
            (52, "high", False),    # the check is on a different variable
            (56, "high", False),    # the check runs after exec
            (65, "high", False),    # the check sits in a branch that may not run
            (72, "high", False),    # the checked value is replaced before exec
            (80, "high", False),    # the check's result is overwritten
            (86, "high", False),    # a failed check does not stop the function
            (93, "high", False),    # the check is in a nested function that is never called
            (101, "high", False),   # the real builtins are put back into the dict
            (110, "high", False),   # the check is in an except handler that may not run
        })

    def test_good_server(self):
        # list-form subprocess, constant shell command, execFile, and regex .exec() are all fine
        self.assertEqual(scan(unsafe_exec, "unsafe_exec/good"), [])


if __name__ == "__main__":
    unittest.main()
