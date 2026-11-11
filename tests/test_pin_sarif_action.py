"""SARIF results from --pin always have a location, and the GitHub Action definition is sane."""
import io
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from mcp_auditor.cli import main
from tests.helpers import ROOT

SERVER = '''from mcp.server.fastmcp import FastMCP
mcp = FastMCP("x")

@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b
'''
SECOND_TOOL = '''
@mcp.tool()
def sub(a: int, b: int) -> int:
    """Subtract two numbers."""
    return a - b
'''


def run(*argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(list(argv))
    return code, buf.getvalue()


class PinSarifTest(unittest.TestCase):
    def setUp(self):
        self.repo = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, ignore_errors=True)
        cwd = os.getcwd()
        os.chdir(self.repo)
        self.addCleanup(os.chdir, cwd)  # runs before the rmtree above
        (self.repo / "server").mkdir()
        self.server = self.repo / "server" / "server.py"

    def removed_tool_sarif(self, scan_path):
        self.server.write_text(SERVER + SECOND_TOOL, encoding="utf-8")
        run(scan_path, "--pin", "tools.lock.json")  # the first run saves the pin
        self.server.write_text(SERVER, encoding="utf-8")  # now `sub` is gone
        return json.loads(run(scan_path, "--pin", "tools.lock.json", "--format", "sarif", "--fail-on", "none")[1])

    def check(self, sarif, uri):
        results = sarif["runs"][0]["results"]
        removed = [r for r in results if "was removed" in r["message"]["text"]]
        self.assertEqual(len(removed), 1)
        self.assertTrue(all(r.get("locations") for r in results), "every result needs a location")
        loc = removed[0]["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], uri)
        self.assertEqual(loc["region"]["startLine"], 1)
        try:
            import jsonschema
        except ImportError:
            return
        schema = json.loads((ROOT / "tests" / "data" / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))
        jsonschema.validate(sarif, schema)

    def test_removed_tool_points_at_the_pin_file(self):
        self.check(self.removed_tool_sarif("server"), "tools.lock.json")  # pin at the repo root, scan of a subfolder

    def test_pin_file_next_to_the_scanned_folder_root(self):
        self.check(self.removed_tool_sarif("."), "tools.lock.json")

    def test_text_output_names_the_pin_file(self):
        self.removed_tool_sarif("server")
        out = run("server", "--pin", "tools.lock.json", "--fail-on", "none")[1]
        self.assertIn("tools.lock.json:1", out.replace("\\", "/").replace("../", ""))


class ActionTest(unittest.TestCase):
    text = (ROOT / "action.yml").read_text(encoding="utf-8")

    def test_scans_once(self):
        self.assertEqual(self.text.count("-m mcp_auditor"), 1)

    def test_sets_up_python_without_changing_the_callers_environment(self):
        self.assertIn("uses: actions/setup-python@v7", self.text)
        self.assertIn("update-environment: false", self.text)
        self.assertIn('"$PYTHON" -m mcp_auditor', self.text)
        self.assertNotIn("python3", self.text)

    def test_uses_the_current_upload_sarif(self):
        self.assertIn("github/codeql-action/upload-sarif@v4", self.text)
        self.assertNotIn("upload-sarif@v3", self.text)


if __name__ == "__main__":
    unittest.main()
