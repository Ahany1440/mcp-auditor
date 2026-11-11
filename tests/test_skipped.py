"""A scan must never look clean just because files were left out."""
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from mcp_auditor.cli import main
from tests.helpers import ROOT

BAD = (ROOT / "examples" / "vulnerable-server" / "server.py").read_bytes()


def run(*argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(list(argv))
    return code, buf.getvalue()


def make(place: str, data: bytes = BAD) -> str:
    d = tempfile.mkdtemp()
    target = Path(d, place)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return d


class SkippedFilesTest(unittest.TestCase):
    def assert_flagged(self, folder, reason):
        code, out = run(folder, "--format", "json")
        report = json.loads(out)
        self.assertEqual(report["findings"], [])
        self.assertTrue(any(reason in s["reason"] for s in report["skipped"]), report["skipped"])
        self.assertTrue(report["warnings"])
        self.assertEqual(code, 0)  # exit code behaviour is unchanged
        text = run(folder)[1]
        self.assertIn("WARNING", text)
        self.assertIn("not scanned", text)
        self.assertIn("NOT a clean result", text)
        return folder

    def test_dist_folder(self):
        self.assert_flagged(make("dist/server.py"), "dependency or build folder")

    def test_tests_folder(self):
        self.assert_flagged(make("tests/server.py"), "test folder")

    def test_test_file_name(self):
        self.assert_flagged(make("server_test.py"), "test file")

    def test_over_one_megabyte(self):
        self.assert_flagged(make("server.py", BAD + b"\n#" + b"x" * 1_000_001), "larger than")

    def test_non_utf8_byte_no_longer_drops_the_file(self):
        folder = make("server.py", b"# caf\xe9\n" + BAD)
        report = json.loads(run(folder, "--format", "json")[1])
        self.assertTrue(report["findings"])
        self.assertEqual(report["skipped"], [])
        self.assertEqual(run(folder, "--format", "json")[0], 1)

    def test_single_file_with_bad_byte(self):
        folder = make("server.py", b"# caf\xe9\n" + BAD)
        code, out = run(str(Path(folder, "server.py")), "--format", "json")
        self.assertTrue(json.loads(out)["findings"])

    def test_zero_files_is_not_presented_as_clean(self):
        folder = tempfile.mkdtemp()
        report = json.loads(run(folder, "--format", "json")[1])
        self.assertEqual(report["files_scanned"], 0)
        self.assertTrue(any("0 files were scanned" in w for w in report["warnings"]))
        self.assertIn("NOT a clean result", run(folder)[1])

    def test_normal_scan_has_no_warning(self):
        code, out = run(str(ROOT / "examples" / "clean-server"))
        self.assertNotIn("WARNING", out)
        self.assertIn("No findings.", out)

    def test_file_names_cannot_inject_terminal_codes(self):
        from mcp_auditor.models import Target
        from mcp_auditor.report import to_text
        esc = chr(27)
        t = Target("x", skipped=[{"path": f"dist/evil{esc}[31m.py", "files": 1, "reason": "test file\n"}], from_source=True)
        self.assertNotIn(esc, to_text(t, []))

    def test_sarif_carries_the_skipped_info_and_stays_valid(self):
        folder = make("dist/server.py")
        out = Path(tempfile.mkdtemp(), "r.sarif")
        run(folder, "--format", "sarif", "-o", str(out))
        sarif = json.loads(out.read_text(encoding="utf-8"))
        sarif_run = sarif["runs"][0]
        self.assertEqual(sarif_run["properties"]["skippedFiles"][0]["path"], "dist/")
        notes = sarif_run["invocations"][0]["toolExecutionNotifications"]
        self.assertEqual(notes[0]["level"], "warning")
        try:
            import jsonschema
        except ImportError:
            return
        schema = json.loads((ROOT / "tests" / "data" / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))
        jsonschema.validate(sarif, schema)


if __name__ == "__main__":
    unittest.main()
