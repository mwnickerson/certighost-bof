import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ReadmeWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.readme = (ROOT / "README.md").read_text(encoding="utf-8")
        cls.integration = (ROOT / "docs" / "mythic-integration.md").read_text(encoding="utf-8")
        cls.manual = (ROOT / "docs" / "manual-full-chain-validation.md").read_text(encoding="utf-8")
        cls.primary = cls.readme.split("## Optional Offline Helpers", 1)[0]

    def test_disclosure_remains_immediately_below_title(self):
        lines = self.readme.splitlines()
        self.assertEqual(lines[0], "# Certighost BOF")
        self.assertEqual(lines[2], "> **Disclosure:** This project was developed entirely by AI using the Hermes harness.")

    def test_primary_path_is_stock_mythic_and_shell_only(self):
        self.assertIn("register_file", self.primary)
        self.assertIn("file picker", self.primary)
        self.assertIn("openssl req -new -newkey", self.primary)
        self.assertIn("openssl base64 -A", self.primary)
        self.assertNotIn("python3", self.primary)
        self.assertIn("There is no custom Mythic command", self.primary)

    def test_primary_command_uses_one_base64_and_five_strings(self):
        commands = [
            line
            for line in self.primary.splitlines()
            if line.startswith("execute_coff -Coff certighost.x64.o")
        ]
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0].count("base64:"), 1)
        self.assertEqual(commands[0].count("string:"), 5)
        self.assertIn("string:Machine", commands[0])

    def test_primary_path_covers_output_continuity_pfx_cleanup_and_scope(self):
        for required in (
            "CERTIGHOST_RESULT disposition=3",
            "certighost: request not issued",
            "The two SHA-256 SPKI digests must match",
            "hidden export-password prompt",
            "rm -f",
            "-just-dc-user 'krbtgt'",
            "broad_dump_performed",
        ):
            self.assertIn(required, self.primary)

    def test_related_docs_describe_the_same_mixed_contract(self):
        for document in (self.integration, self.manual):
            self.assertIn("register_file", document)
            commands = [
                line
                for line in document.splitlines()
                if line.startswith("execute_coff -Coff certighost.x64.o")
            ]
            self.assertTrue(commands)
            self.assertTrue(any(command.count("base64:") == 1 for command in commands))
            self.assertTrue(any(command.count("string:") == 5 for command in commands))
            self.assertIn("terminal NUL", document)
            self.assertIn("legacy all-base64", document)


if __name__ == "__main__":
    unittest.main()
