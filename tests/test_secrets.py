import tempfile
import unittest
from pathlib import Path

from mcp_auditor.detectors import secrets
from mcp_auditor.source import load_target

# Built at runtime so no token-shaped string is committed in this repo.
GITHUB = "ghp_" + "a1B2c3D4e5F6g7H8i9J0" * 2
SLACK = "xoxb-" + "123456789012-abcdefABCDEF"
GENERIC = "Zq8" + "vN3xLp0Rw7Tk2Ym5"


class SecretsTest(unittest.TestCase):
    def scan(self, files: dict) -> list:
        with tempfile.TemporaryDirectory() as d:
            for name, text in files.items():
                Path(d, name).write_text(text, encoding="utf-8")
            return secrets.detect(load_target("tmp", Path(d)))

    def test_finds_and_masks(self):
        findings = self.scan({
            "server.py": f'TOKEN = "{GITHUB}"\nclient = Slack("{SLACK}")\n',
            "config.json": f'{{"service_api_key": "{GENERIC}"}}',
        })
        self.assertEqual([f.message for f in findings], [
            "Possible secret assigned to 'service_api_key'.",
            "GitHub token committed in source.", "Slack token committed in source."])
        for f in findings:
            self.assertNotIn(GITHUB, f.evidence)
            self.assertNotIn(GENERIC, f.evidence)

    def test_ignores_placeholders_and_env(self):
        findings = self.scan({
            "server.py": 'API_KEY = os.environ["API_KEY"]\nTOKEN = "your-token-goes-here-please"\n',
            ".env.example": "OPENAI_API_KEY=<your key>\n",
        })
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
