"""Scan time must grow roughly linearly with the tool count, and the findings must not change."""
import json
import tempfile
import time
import unittest
from pathlib import Path

from mcp_auditor.detectors import run_all, sort_findings
from mcp_auditor.source import load_target
from tests.helpers import FIXTURES, ROOT

GOLDEN = ROOT / "tests" / "data" / "scan_golden.json"

JS_BLOCK = '''
server.tool("tool_%(i)d", "Reads the thing number %(i)d", { id: z.string().describe("the id") }, async ({ id }) => {
  const data = await fs.promises.readFile(id);
  return { content: [] };
});
server.registerTool("reg_%(i)d", { title: "Reg", description: "Registered %(i)d <IMPORTANT>x</IMPORTANT>", inputSchema: { q: z.string() } }, async ({ q }) => {
  require("child_process").exec(`ls ${q}`);
});
server.tool("dyn_%(i)d", `Dynamic ${process.env.X} %(i)d`, {}, async () => fetch(url));
const low_%(i)d = { name: "low_%(i)d", description: "Low level %(i)d", inputSchema: { type: "object", properties: { a: { description: "p" } } } };
'''
GO_BLOCK = '''
	s.AddTool(mcp.NewTool("go_tool_%(i)d", mcp.WithDescription("Go tool %(i)d"), mcp.WithString("p", mcp.Description("param"))), h)
	exec.Command("sh", "-c", arg)
'''


def synthetic(folder: Path) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "a.js").write_text("".join(JS_BLOCK % {"i": i} for i in range(25)), encoding="utf-8")
    # CRLF and a form feed: splitlines() and "\n" disagree about where lines end, and findings must not move
    (folder / "b.js").write_text("".join(JS_BLOCK % {"i": i} for i in range(5)).replace("\n", "\r\n").replace("{ id", "\x0c{ id"),
                                 encoding="utf-8", newline="")
    (folder / "c.go").write_text("package main\nfunc f() {\n" + "".join(GO_BLOCK % {"i": i} for i in range(10)) + "}\n", encoding="utf-8")


def snapshot(label: str, root: Path) -> dict:
    target = load_target(label, root)
    findings = sort_findings(run_all(target))
    return {
        "tools": [[t.name, t.description, t.params, t.file, t.line, t.end_line, t.extra] for t in target.tools],
        "findings": [[f.rule.id, f.severity, f.message, f.file, f.line, f.tool, f.evidence] for f in findings],
    }


def snapshot_all() -> dict:
    out = {}
    roots = sorted(p for p in FIXTURES.glob("*/*") if p.is_dir()) + sorted(p for p in (ROOT / "examples").iterdir() if p.is_dir())
    for p in roots:
        out[p.relative_to(ROOT).as_posix()] = snapshot(p.name, p)
    with tempfile.TemporaryDirectory() as d:
        synthetic(Path(d))
        out["synthetic"] = snapshot("synthetic", Path(d))
    return json.loads(json.dumps(out))  # tuples -> lists, like the stored file


class ScanSpeedTest(unittest.TestCase):
    def test_findings_are_unchanged(self):
        golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
        self.assertEqual(snapshot_all(), golden)

    def test_3000_tools_scan_in_seconds(self):
        with tempfile.TemporaryDirectory() as d:
            lines = [f'server.tool("t{i}", "d", {{}}, async () => {{}});' for i in range(3000)]
            Path(d, "big.js").write_text("\n".join(lines), encoding="utf-8")
            start = time.monotonic()
            target = load_target("big", Path(d))
            run_all(target)
            elapsed = time.monotonic() - start
        self.assertEqual(len(target.tools), 3000)
        self.assertLess(elapsed, 5, f"scan took {elapsed:.1f}s")

    def test_3000_realistic_tools_scan_in_seconds(self):
        """Handlers with fs/exec/fetch calls and underscore names exercise every detector, not just discovery."""
        with tempfile.TemporaryDirectory() as d:
            Path(d, "big.js").write_text("".join(JS_BLOCK % {"i": i} for i in range(750)), encoding="utf-8")
            start = time.monotonic()
            run_all(load_target("big", Path(d)))
            elapsed = time.monotonic() - start
        self.assertLess(elapsed, 5, f"scan took {elapsed:.1f}s")


    def test_3000_python_tools_scan_in_seconds(self):
        code = "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n" + "".join(
            f'@mcp.tool()\ndef tool_{i}(p: str) -> str:\n    """Does thing {i}."""\n    return open(p).read()\n' for i in range(3000))
        with tempfile.TemporaryDirectory() as d:
            Path(d, "big.py").write_text(code, encoding="utf-8")
            start = time.monotonic()
            findings = run_all(load_target("big", Path(d)))
            elapsed = time.monotonic() - start
        self.assertEqual(len(findings), 3000)
        self.assertLess(elapsed, 5, f"scan took {elapsed:.1f}s")


if __name__ == "__main__":
    unittest.main()
