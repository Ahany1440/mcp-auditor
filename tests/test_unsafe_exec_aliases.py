"""MCP004 must still see dangerous calls that are renamed, imported with `as`, or reached through __import__."""
import tempfile
import unittest
from pathlib import Path

from mcp_auditor.detectors import unsafe_exec
from mcp_auditor.source import load_target

PY_HEAD = "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n"
JS_HEAD = 'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\nconst server = new McpServer({ name: "x" });\n'


def scan(name: str, text: str) -> list:
    with tempfile.TemporaryDirectory() as d:
        Path(d, name).write_text(text, encoding="utf-8")
        return unsafe_exec.detect(load_target("tmp", Path(d)))


def py_tool(imports: str, body: str) -> str:
    return f"{PY_HEAD}{imports}\n@mcp.tool()\ndef run(cmd: str) -> str:\n    {body}\n"


def js_tool(prelude: str, body: str) -> str:
    return f'{JS_HEAD}{prelude}\nserver.tool("run", "Runs it", {{}}, async ({{ cmd }}) => {{\n  {body}\n}});\n'


class PythonAliasesTest(unittest.TestCase):
    def assert_flagged(self, code, word=None):
        findings = scan("s.py", code)
        self.assertEqual([f.severity for f in findings], ["critical"], [f.message for f in findings])
        if word:
            self.assertIn(word, findings[0].message)

    def test_import_as(self):
        self.assert_flagged(py_tool("import subprocess as sp", "return sp.run(cmd, shell=True)"), "subprocess.run()")

    def test_from_import(self):
        self.assert_flagged(py_tool("from os import system", "return system(cmd)"), "os.system()")

    def test_from_import_as(self):
        self.assert_flagged(py_tool("from os import system as launch", "return launch(cmd)"), "os.system()")

    def test_dunder_import(self):
        self.assert_flagged(py_tool("", 'return __import__("os").system(cmd)'), "os.system()")

    def test_getattr_with_a_split_name(self):
        self.assert_flagged(py_tool("import os", 'return getattr(os, "sys" + "tem")(cmd)'), "os.system()")

    def test_shell_dash_c_list(self):
        self.assert_flagged(py_tool("import subprocess as sp", 'return sp.run(["sh", "-c", cmd])'), "running a shell with -c")
        self.assert_flagged(py_tool("import subprocess", 'return subprocess.Popen(("/bin/bash", "-lc", cmd))'))
        self.assert_flagged(py_tool("import subprocess", 'return subprocess.check_output(["cmd.exe", "/c", cmd])'))

    def test_pickle_and_marshal(self):
        self.assert_flagged(py_tool("import pickle", "return pickle.loads(cmd)"), "pickle.loads()")
        self.assert_flagged(py_tool("import pickle as p", "return p.loads(cmd)"), "pickle.loads()")
        self.assert_flagged(py_tool("from pickle import loads", "return loads(cmd)"), "pickle.loads()")
        self.assert_flagged(py_tool("import marshal", "return marshal.loads(cmd)"), "marshal.loads()")

    def test_unsafe_yaml(self):
        self.assert_flagged(py_tool("import yaml", "return yaml.load(cmd)"), "yaml.load()")
        self.assert_flagged(py_tool("import yaml", "return yaml.load(cmd, Loader=yaml.Loader)"))
        self.assert_flagged(py_tool("import yaml as y", "return y.unsafe_load(cmd)"), "yaml.unsafe_load()")
        self.assert_flagged(py_tool("from yaml import load, FullLoader", "return load(cmd, FullLoader)"))

    def test_builtins_spelling(self):
        self.assert_flagged(py_tool("", "return __builtins__.eval(cmd)"))

    def assert_quiet(self, code):
        self.assertEqual(scan("s.py", code), [], code)

    def test_look_alikes_are_not_flagged(self):
        self.assert_quiet(py_tool("def system(c):\n    return c", "return system(cmd)"))  # a local function
        self.assert_quiet(py_tool("from mylib import system", "return system(cmd)"))
        self.assert_quiet(py_tool("import subprocess", 'return subprocess.run(["ls", "-l", cmd], shell=False)'))
        self.assert_quiet(py_tool("import subprocess as sp", 'return sp.run(["git", "status"])'))
        self.assert_quiet(py_tool("import subprocess", 'return subprocess.run(["sh", "-c", "echo hi"])'))  # fixed command
        self.assert_quiet(py_tool("import subprocess", 'return subprocess.run(["sh", cmd])'))  # no -c: runs a script file
        self.assert_quiet(py_tool("import yaml", "return yaml.safe_load(cmd)"))
        self.assert_quiet(py_tool("import yaml", "return yaml.load(cmd, Loader=yaml.SafeLoader)"))
        self.assert_quiet(py_tool("import pickle", 'return pickle.loads(b"fixed")'))
        self.assert_quiet(py_tool("import pickle", "return pickle.dumps(cmd)"))


class JavaScriptAliasesTest(unittest.TestCase):
    def assert_flagged(self, code, ext="s.js"):
        findings = scan(ext, code)
        self.assertEqual([f.severity for f in findings], ["critical"], [f.message for f in findings])

    def test_global_eval(self):
        self.assert_flagged(js_tool("", "return globalThis.eval(cmd);"))
        self.assert_flagged(js_tool("", "return window.eval(cmd);"))

    def test_indirect_eval(self):
        self.assert_flagged(js_tool("", "return (0, eval)(cmd);"))
        self.assert_flagged(js_tool("", "return (0,globalThis.eval)(cmd);"))

    def test_inline_require(self):
        self.assert_flagged(js_tool("", 'return require("child_process").execSync(cmd);'))
        self.assert_flagged(js_tool("", 'return require("node:child_process").exec(`ls ${cmd}`);'))

    def test_module_alias(self):
        self.assert_flagged(js_tool('const proc = require("child_process");', "return proc.exec(cmd);"))
        self.assert_flagged(js_tool('import * as proc from "node:child_process";', "return proc.execSync(cmd);"), "s.ts")
        self.assert_flagged(js_tool('import sys from "child_process";', 'return sys["exec"](cmd);'))

    def test_destructured_and_renamed_functions(self):
        self.assert_flagged(js_tool('const { exec: run } = require("child_process");', "return run(cmd);"))
        self.assert_flagged(js_tool('import { execSync as sh } from "child_process";', "return sh(cmd);"), "s.ts")
        self.assert_flagged(js_tool('const launch = require("child_process").execSync;', "return launch(cmd);"))

    def test_vm_alias(self):
        self.assert_flagged(js_tool('const v = require("node:vm");', "return v.runInNewContext(cmd);"))

    def test_line_numbers_are_those_of_the_original(self):
        code = js_tool('const { exec: run } = require("child_process");', "return run(cmd);")
        line = scan("s.js", code)[0].line
        self.assertIn("run(cmd)", code.splitlines()[line - 1])

    def assert_quiet(self, code):
        self.assertEqual(scan("s.js", code), [], code)

    def test_look_alikes_are_not_flagged(self):
        self.assert_quiet(js_tool("function run(c) { return c; }", "return run(cmd);"))  # a local function
        self.assert_quiet(js_tool('const { exec: run } = require("not_child_process");', "return run(cmd);"))
        self.assert_quiet(js_tool('const proc = require("child_process");', 'return proc.execSync("ls -l");'))  # fixed command
        self.assert_quiet(js_tool("", 'return eval("1 + 1");'))
        self.assert_quiet(js_tool('const re = /a/;', "return re.exec(cmd);"))
        self.assert_quiet(js_tool('const proc = require("child_process");', 'return proc.execFile("ls", [cmd]);'))
        self.assert_quiet(js_tool('const other = { eval: (x) => x };', "return other.eval(cmd);"))


if __name__ == "__main__":
    unittest.main()
