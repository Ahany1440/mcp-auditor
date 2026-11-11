"""MCP003: secrets that are not in quotes (.env, YAML, INI), Bearer tokens and passwords inside URLs."""
import tempfile
import unittest
from pathlib import Path

from mcp_auditor.detectors import secrets
from mcp_auditor.source import load_target

HEX = "9f8a7b6c5d4e3f2a" + "1b0c9d8e7f6a5b4c"  # built at runtime so no key-shaped string is committed
PW = "Tr0ub4dor" + "Xyz99aaQQ12"
PW2 = "Tr0ub4dor" + "&3xYz99aa"
SECRETS = [HEX, PW, PW2, "pw", "Sup3rS3cret" + "Pw99"]


class SecretShapesTest(unittest.TestCase):
    def scan(self, files: dict) -> list:
        with tempfile.TemporaryDirectory() as d:
            for name, text in files.items():
                Path(d, name).write_text(text, encoding="utf-8")
            return secrets.detect(load_target("tmp", Path(d)))

    def assert_found(self, files, expected):
        findings = self.scan(files)
        self.assertEqual([(f.file, f.line) for f in findings], expected, [f.message for f in findings])
        for f in findings:  # masked: the value itself never reaches a report
            for secret in SECRETS:
                self.assertNotIn(secret, f.evidence + f.message)
        return findings

    def test_unquoted_env_values(self):
        findings = self.assert_found({".env": f"API_KEY={HEX}\nexport DB_PASSWORD={PW2}\nDEBUG=true\n"},
                                     [(".env", 1), (".env", 2)])
        self.assertEqual(findings[0].message, "Possible secret assigned to 'API_KEY'.")

    def test_unquoted_yaml_values(self):
        self.assert_found({"config.yaml": f"db:\n  password: {PW}\n  api_key: {HEX}  # prod\n  name: main\n"},
                          [("config.yaml", 2), ("config.yaml", 3)])

    def test_unquoted_ini_values(self):
        self.assert_found({"settings.ini": f"[auth]\nclient_secret = {HEX}\n"}, [("settings.ini", 2)])

    def test_env_file_with_a_suffix(self):
        self.assert_found({".env.production": f"AUTH_TOKEN={HEX}\n"}, [(".env.production", 1)])

    def test_unquoted_values_are_not_read_in_code_files(self):
        self.assertEqual(self.scan({"server.py": f"api_key = get_key_{HEX}\nTOKEN: str = load_{PW}\n"}), [])

    def test_bearer_token(self):
        findings = self.assert_found({"client.py": f'headers = {{"Authorization": "Bearer {HEX}9f8a"}}\n'}, [("client.py", 1)])
        self.assertEqual(findings[0].message, "Bearer token committed in source.")

    def test_password_in_connection_url(self):
        findings = self.assert_found({"db.py": 'conn = "postgres://admin:pw@host"\n',
                                      "mongo.ts": f"const u = 'mongodb+srv://app:{SECRETS[4]}@cluster0.example.net/db';\n"},
                                     [("db.py", 1), ("mongo.ts", 1)])
        self.assertEqual({f.severity for f in findings}, {"high"})
        self.assertEqual(findings[0].message, "Password embedded in a postgres:// connection URL.")

    def test_url_password_on_localhost_is_medium(self):
        findings = self.assert_found({"db.py": 'conn = "postgres://dev:hunter2@localhost:5432/app"\n'}, [("db.py", 1)])
        self.assertEqual(findings[0].severity, "medium")

    def test_placeholders_and_templates_are_ignored(self):
        self.assertEqual(self.scan({
            ".env": "API_KEY=changeme\nSECRET=your_key_here\nTOKEN=<token>\nPASSWORD=${DB_PASSWORD}\n"
                    "API_KEY=example-key-1234567890abcdef\nAPI_TOKEN=\n",
            "ci.yml": "token: ${{ secrets.GITHUB_TOKEN }}\npassword: \"{{ vault_password }}\"\napi_key: *shared_key\n",
            "t.py": 'a = "postgres://user:password@localhost/db"\nb = "postgres://user:${PW}@host/db"\n'
                    'c = "postgres://user:<password>@host/db"\nd = "postgres://user:DB_PASSWORD@host/db"\n'
                    'e = "Bearer <token>"\nf = f"Bearer {token}"\ng = "Bearer your-token-here-1234567890"\n',
        }), [])

    def test_harmless_values_are_ignored(self):
        self.assertEqual(self.scan({
            "config.yaml": "token_url: https://login.example.com/oauth2/v2.0/token\n"
                           "secret_file: /run/secrets/db-password-v2-1234\n"
                           "tokenizer: sentence-transformers/all-MiniLM-L6-v2\n"
                           "password_file: C:\\secrets\\db-password-v2-12345\n"
                           "access_token: https://example.com/token/ab12cd34ef56ab78\n"
                           "max_tokens: 1000000000000000\n"
                           "api_key: 123e4567-e89b-12d3-a456-426614174000\n",
            "t.py": 'a = "https://host.net/path"\nb = "postgres://host:5432/db"\nc = "git@github.com:org/repo.git"\n'
                    'd = "https://github.com/org/repo"\n',
        }), [])

    def test_short_secrets_are_masked_completely(self):
        self.assertEqual(secrets.mask("pw"), "** (2 chars)")
        self.assertEqual(secrets.mask("a" * 20), "aaaa" + "*" * 12 + " (20 chars)")  # long values print as before


if __name__ == "__main__":
    unittest.main()
