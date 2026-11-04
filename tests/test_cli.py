"""End-to-end: CLI on the example servers, output formats, exit codes and live mode."""
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from mcp_auditor.cli import main
from tests.helpers import FIXTURES, ROOT

VULNERABLE = str(ROOT / "examples" / "vulnerable-server")
CLEAN = str(ROOT / "examples" / "clean-server")


def run(*argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(list(argv))
    return code, buf.getvalue()


class CliTest(unittest.TestCase):
    def test_vulnerable_example_hits_every_detector(self):
        code, out = run(VULNERABLE, "--format", "json")
        self.assertEqual(code, 1)
        rules = {f["rule_id"] for f in json.loads(out)["findings"]}
        self.assertEqual(rules, {"MCP001", "MCP002", "MCP003", "MCP004", "MCP005", "MCP006"})

    def test_clean_example_has_no_findings(self):
        code, out = run(CLEAN, "--format", "json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["findings"], [])

    def test_fail_on_threshold(self):
        self.assertEqual(run(VULNERABLE, "--fail-on", "none")[0], 0)
        self.assertEqual(run(VULNERABLE, "--fail-on", "critical")[0], 1)

    def test_text_output(self):
        code, out = run(VULNERABLE)
        self.assertIn("CRITICAL MCP004 unsafe-execution", out)
        self.assertIn("Summary:", out)

    def test_sarif_validates_against_schema(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("pip install jsonschema to run the SARIF schema check")
        schema = json.loads((ROOT / "tests" / "data" / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as d:
            out = Path(d, "r.sarif")
            run(VULNERABLE, "--format", "sarif", "-o", str(out))
            sarif = json.loads(out.read_text(encoding="utf-8"))
        jsonschema.validate(sarif, schema)
        results = sarif["runs"][0]["results"]
        self.assertTrue(results)
        self.assertTrue(all(r["locations"][0]["physicalLocation"]["region"]["startLine"] > 0 for r in results))

    def test_live_stdio(self):
        cmd = f'"{sys.executable}" "{FIXTURES / "live_server.py"}"'
        code, out = run("--stdio", cmd, "--format", "json")
        report = json.loads(out)
        self.assertEqual([t["name"] for t in report["tools"]], ["echo", "helper"])
        self.assertEqual({f["tool"] for f in report["findings"]}, {"helper"})
        self.assertEqual(code, 1)

    def test_bad_target_is_an_error(self):
        self.assertEqual(run("does/not/exist")[0], 2)


if __name__ == "__main__":
    unittest.main()
