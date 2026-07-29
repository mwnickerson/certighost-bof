import base64
import io
import json
import shutil
import stat
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from tools import certighost_operator as operator
from tools.certighost_mythic import FIELD_NAMES, validate_task_descriptor


OPENSSL = shutil.which("openssl")


@unittest.skipUnless(OPENSSL, "local openssl is required for operator workflow tests")
class OperatorCliTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.coff_object = self.root / "certighost.x64.o"
        self.coff_object.write_bytes(b"fixture-coff-object")

    def run_cli(self, argv):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            rc = operator.main(argv)
        return rc, stdout.getvalue(), stderr.getvalue()

    def prepare_args(self, run_dir):
        return [
            "prepare",
            "--callback-id",
            "callback-fixture-001",
            "--ca-config",
            "ca01.lab.local\\LAB-CA",
            "--template",
            "Machine",
            "--target-dc",
            "dc01.lab.local",
            "--cdc",
            "listener.lab.local",
            "--run-dir",
            str(run_dir),
            "--coff-object",
            str(self.coff_object),
            "--agent-version",
            "apollo-fixture-1.0",
        ]

    def prepare_run(self, name="run"):
        run_dir = self.root / name
        rc, stdout, stderr = self.run_cli(self.prepare_args(run_dir))
        self.assertEqual(rc, 0, stderr)
        return run_dir, stdout

    def openssl(self, args, *, input_bytes=None):
        completed = subprocess.run(
            [OPENSSL, *args],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", "replace"))
        return completed.stdout

    def issued_output(self, cert_der):
        cert_b64 = base64.b64encode(cert_der).decode("ascii")
        return (
            "CERTIGHOST_RESULT disposition=3 request_id=41 cert_encoding=base64 "
            f"cert_der_bytes={len(cert_der)} cert_base64_chars={len(cert_b64)}"
            "CERTIGHOST_CERT_BEGIN\n"
            f"{cert_b64}\n"
            "CERTIGHOST_CERT_END\n"
        )

    def make_matching_certificate_der(self, run_dir):
        cert_pem = self.root / f"{run_dir.name}-matching-cert.pem"
        cert_der = self.root / f"{run_dir.name}-matching-cert.der"
        self.openssl(
            [
                "x509",
                "-req",
                "-in",
                str(run_dir / operator.CSR_PEM_NAME),
                "-signkey",
                str(run_dir / operator.KEY_NAME),
                "-days",
                "1",
                "-out",
                str(cert_pem),
            ]
        )
        self.openssl(["x509", "-in", str(cert_pem), "-outform", "DER", "-out", str(cert_der)])
        return cert_der.read_bytes()

    def make_mismatched_certificate_der(self):
        key = self.root / "mismatch.key.pem"
        cert_pem = self.root / "mismatch-cert.pem"
        cert_der = self.root / "mismatch-cert.der"
        self.openssl(
            [
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(key),
                "-out",
                str(cert_pem),
                "-subj",
                "/CN=other.lab.local",
                "-days",
                "1",
            ]
        )
        self.openssl(["x509", "-in", str(cert_pem), "-outform", "DER", "-out", str(cert_der)])
        return cert_der.read_bytes()

    def write_output_file(self, name, text):
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_parser_requires_extract_arguments_and_positive_timeout(self):
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                operator.main(["extract", "--run-dir", str(self.root / "missing-output")])
            with self.assertRaises(SystemExit):
                operator.main(["prepare", "--timeout", "0"])
            with self.assertRaises(SystemExit):
                operator.main(
                    [
                        "extract",
                        "--run-dir",
                        str(self.root / "conflicting-pfx"),
                        "--mythic-output",
                        str(self.root / "output.txt"),
                        "--pfx",
                        "--pfx-password-stdin",
                    ]
                )
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            with self.assertRaises(SystemExit):
                operator.main(
                    [
                        "extract",
                        "--run-dir",
                        str(self.root / "removed-argv-password"),
                        "--mythic-output",
                        str(self.root / "output.txt"),
                        "--pfx-password",
                        "removed-password-value",
                    ]
                )
        self.assertNotIn("removed-password-value", stderr.getvalue())

    def test_prepare_requires_missing_values_and_does_not_create_a_run_dir(self):
        run_dir = self.root / "missing-required"
        with patch("builtins.input", side_effect=EOFError):
            rc, stdout, stderr = self.run_cli(["prepare", "--run-dir", str(run_dir)])
        self.assertEqual(rc, 1)
        self.assertEqual(stdout, "")
        self.assertIn("Callback ID is required", stderr)
        self.assertFalse(run_dir.exists())

    def test_prepare_rejects_invalid_field_input_before_creating_secrets(self):
        run_dir = self.root / "invalid-ca"
        args = self.prepare_args(run_dir)
        args[args.index("--ca-config") + 1] = "ca01.lab.local/LAB-CA"
        rc, stdout, stderr = self.run_cli(args)
        self.assertEqual(rc, 1)
        self.assertEqual(stdout, "")
        self.assertIn("ca_config", stderr)
        self.assertFalse(run_dir.exists())

    def test_prepare_rejects_stock_cli_unrepresentable_text_before_creating_secrets(self):
        run_dir = self.root / "space-template"
        args = self.prepare_args(run_dir)
        args[args.index("--template") + 1] = "Domain Controller"
        rc, stdout, stderr = self.run_cli(args)
        self.assertEqual(rc, 1)
        self.assertEqual(stdout, "")
        self.assertIn("cannot contain spaces", stderr)
        self.assertFalse(run_dir.exists())

    def test_prepare_noninteractive_emits_one_six_field_command_and_secure_modes(self):
        run_dir, stdout = self.prepare_run("noninteractive")
        lines = stdout.splitlines()
        self.assertTrue(lines[0].startswith("execute_coff -Coff certighost.x64.o -Function go"))
        self.assertEqual(stdout.count("execute_coff"), 1)
        self.assertEqual(lines[0].count("base64:"), 1)
        self.assertEqual(lines[0].count("string:"), 5)
        self.assertEqual(stat.S_IMODE(run_dir.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((run_dir / operator.KEY_NAME).stat().st_mode), 0o600)

        descriptor = json.loads((run_dir / operator.DESCRIPTOR_NAME).read_text(encoding="utf-8"))
        validate_task_descriptor(descriptor)
        self.assertEqual(descriptor["arguments"]["field_order"], list(FIELD_NAMES))
        typed_args = descriptor["task_payload"]["params"]["coff_arguments"]
        self.assertEqual(typed_args[0][0], "base64")
        self.assertTrue(base64.b64decode(typed_args[0][1]).startswith(b"\x30"))
        self.assertEqual(typed_args[1:], [
            ["string", "ca01.lab.local\\LAB-CA"],
            ["string", "Machine"],
            ["string", "dc01.lab.local"],
            ["string", "listener.lab.local"],
            ["string", "dc01.lab.local"],
        ])
        self.assertEqual(lines[0], descriptor["operator_command"])

    def test_prepare_prompts_only_for_omitted_required_values(self):
        run_dir = self.root / "interactive"
        args = [
            "prepare",
            "--template",
            "Machine",
            "--coff-object",
            str(self.coff_object),
        ]
        answers = [
            "callback-interactive-001",
            "ca01.lab.local\\LAB-CA",
            "dc01.lab.local",
            "listener.lab.local",
            str(run_dir),
        ]
        with patch("builtins.input", side_effect=answers) as prompt:
            rc, stdout, stderr = self.run_cli(args)
        self.assertEqual(rc, 0, stderr)
        self.assertEqual(prompt.call_count, len(answers))
        self.assertIn("execute_coff", stdout)
        descriptor = json.loads((run_dir / operator.DESCRIPTOR_NAME).read_text(encoding="utf-8"))
        self.assertEqual(descriptor["mythic"]["agent_version"], operator.DEFAULT_AGENT_VERSION)
        self.assertTrue(run_dir.exists())

    def test_extract_rejects_malformed_and_non_issued_output_but_stores_capture(self):
        cases = {
            "malformed": "unrelated output\n",
            "nonissued": "certighost: request not issued (disposition=2 request_id=42 last_status=0x80094800)\n",
        }
        for name, text in cases.items():
            with self.subTest(name=name):
                run_dir, _ = self.prepare_run(f"extract-{name}")
                source = self.write_output_file(f"{name}.txt", text)
                rc, stdout, stderr = self.run_cli(
                    ["extract", "--run-dir", str(run_dir), "--mythic-output", str(source)]
                )
                self.assertEqual(rc, 1)
                self.assertEqual(stdout, "")
                self.assertTrue((run_dir / operator.MYTHIC_OUTPUT_NAME).exists())
                self.assertEqual((run_dir / operator.MYTHIC_OUTPUT_NAME).read_text(encoding="utf-8"), text)
                self.assertFalse((run_dir / operator.CERT_DER_NAME).exists())
                if name == "nonissued":
                    self.assertIn("certificate was not issued", stderr)
                else:
                    self.assertIn("not a valid issued result", stderr)

    def test_extract_retries_after_pre_certificate_parse_failures(self):
        cases = {
            "malformed": "unrelated output\n",
            "nonissued": "certighost: request not issued (disposition=2 request_id=42 last_status=0x80094800)\n",
        }
        for name, text in cases.items():
            with self.subTest(name=name):
                run_dir, _ = self.prepare_run(f"retry-{name}")
                failed_source = self.write_output_file(f"retry-{name}-failed.txt", text)
                rc, stdout, stderr = self.run_cli(
                    ["extract", "--run-dir", str(run_dir), "--mythic-output", str(failed_source)]
                )
                self.assertEqual(rc, 1)
                self.assertEqual(stdout, "")
                self.assertFalse((run_dir / operator.CERT_DER_NAME).exists())

                cert_der = self.make_matching_certificate_der(run_dir)
                issued_source = self.write_output_file(f"retry-{name}-issued.txt", self.issued_output(cert_der))
                rc, stdout, stderr = self.run_cli(
                    ["extract", "--run-dir", str(run_dir), "--mythic-output", str(issued_source)]
                )
                self.assertEqual(rc, 0, stderr)
                self.assertIn("VERIFIED certificate/private-key continuity", stdout)
                self.assertEqual((run_dir / operator.MYTHIC_OUTPUT_NAME).read_bytes(), issued_source.read_bytes())
                self.assertEqual((run_dir / operator.CERT_DER_NAME).read_bytes(), cert_der)

    def test_extract_verifies_matching_certificate_and_copies_output_inside_run_dir(self):
        run_dir, _ = self.prepare_run("extract-match")
        cert_der = self.make_matching_certificate_der(run_dir)
        source = self.write_output_file("matching-output.txt", self.issued_output(cert_der))
        rc, stdout, stderr = self.run_cli(
            ["extract", "--run-dir", str(run_dir), "--mythic-output", str(source)]
        )
        self.assertEqual(rc, 0, stderr)
        self.assertIn("VERIFIED certificate/private-key continuity", stdout)
        self.assertEqual((run_dir / operator.MYTHIC_OUTPUT_NAME).read_text(encoding="utf-8"), source.read_text(encoding="utf-8"))
        self.assertEqual((run_dir / operator.CERT_DER_NAME).read_bytes(), cert_der)
        self.assertTrue((run_dir / operator.CERT_PEM_NAME).exists())
        self.assertEqual(stat.S_IMODE((run_dir / operator.CERT_DER_NAME).stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((run_dir / operator.CERT_PEM_NAME).stat().st_mode), 0o600)

    def test_extract_reruns_preserve_successful_capture_and_certificate_bytes(self):
        mismatched_der = self.make_mismatched_certificate_der()
        cases = {
            "malformed": "unrelated output\n",
            "nonissued": "certighost: request not issued (disposition=2 request_id=42 last_status=0x80094800)\n",
            "key-mismatch": self.issued_output(mismatched_der),
        }
        for name, text in cases.items():
            with self.subTest(name=name):
                run_dir, _ = self.prepare_run(f"rerun-{name}")
                cert_der = self.make_matching_certificate_der(run_dir)
                issued_source = self.write_output_file(f"rerun-{name}-issued.txt", self.issued_output(cert_der))
                rc, stdout, stderr = self.run_cli(
                    ["extract", "--run-dir", str(run_dir), "--mythic-output", str(issued_source)]
                )
                self.assertEqual(rc, 0, stderr)
                self.assertIn("VERIFIED certificate/private-key continuity", stdout)
                stored_output_before = (run_dir / operator.MYTHIC_OUTPUT_NAME).read_bytes()
                cert_der_before = (run_dir / operator.CERT_DER_NAME).read_bytes()

                rerun_source = self.write_output_file(f"rerun-{name}-failed.txt", text)
                rc, stdout, stderr = self.run_cli(
                    ["extract", "--run-dir", str(run_dir), "--mythic-output", str(rerun_source)]
                )
                self.assertEqual(rc, 1)
                self.assertEqual(stdout, "")
                self.assertIn("certificate artifacts already exist", stderr)
                self.assertEqual((run_dir / operator.MYTHIC_OUTPUT_NAME).read_bytes(), stored_output_before)
                self.assertEqual((run_dir / operator.CERT_DER_NAME).read_bytes(), cert_der_before)

    def test_extract_fails_closed_on_certificate_private_key_mismatch(self):
        run_dir, _ = self.prepare_run("extract-mismatch")
        source = self.write_output_file("mismatch-output.txt", self.issued_output(self.make_mismatched_certificate_der()))
        rc, stdout, stderr = self.run_cli(
            ["extract", "--run-dir", str(run_dir), "--mythic-output", str(source)]
        )
        self.assertEqual(rc, 1)
        self.assertEqual(stdout, "")
        self.assertIn("does not match", stderr)
        self.assertFalse((run_dir / operator.CERT_DER_NAME).exists())
        self.assertFalse((run_dir / operator.CERT_PEM_NAME).exists())

    def test_extract_can_create_transient_password_protected_pfx_with_hidden_prompt(self):
        run_dir, _ = self.prepare_run("extract-pfx")
        cert_der = self.make_matching_certificate_der(run_dir)
        source = self.write_output_file("pfx-output.txt", self.issued_output(cert_der))
        password = "fixture-pfx-password"
        argv = [
            "extract",
            "--run-dir",
            str(run_dir),
            "--mythic-output",
            str(source),
            "--pfx",
        ]
        with patch.object(operator.getpass, "getpass", side_effect=[password, password]) as prompt:
            with patch.object(operator.subprocess, "run", wraps=subprocess.run) as run:
                rc, stdout, stderr = self.run_cli(argv)
        self.assertEqual(rc, 0, stderr)
        self.assertEqual(prompt.call_count, 2)
        self.assertNotIn(password, " ".join(argv))
        self.assertNotIn(password, stdout)
        self.assertNotIn(password, stderr)
        for call in run.call_args_list:
            self.assertNotIn(password, " ".join(call.args[0]))
        pfx = run_dir / operator.PFX_NAME
        self.assertTrue(pfx.exists())
        self.assertEqual(stat.S_IMODE(pfx.stat().st_mode), 0o600)
        self.openssl(["pkcs12", "-in", str(pfx), "-passin", "stdin", "-noout"], input_bytes=(password + "\n").encode())

    def test_extract_can_create_pfx_from_protected_password_file_without_password_in_argv_or_output(self):
        run_dir, _ = self.prepare_run("extract-pfx-file")
        cert_der = self.make_matching_certificate_der(run_dir)
        source = self.write_output_file("pfx-file-output.txt", self.issued_output(cert_der))
        password = "fixture-file-pfx-password"
        password_file = self.root / "pfx-password.txt"
        password_file.write_text(password + "\n", encoding="utf-8")
        password_file.chmod(0o600)
        argv = [
            "extract",
            "--run-dir",
            str(run_dir),
            "--mythic-output",
            str(source),
            "--pfx-password-file",
            str(password_file),
        ]
        with patch.object(operator.subprocess, "run", wraps=subprocess.run) as run:
            rc, stdout, stderr = self.run_cli(argv)
        self.assertEqual(rc, 0, stderr)
        self.assertNotIn(password, " ".join(argv))
        self.assertNotIn(password, stdout)
        self.assertNotIn(password, stderr)
        for call in run.call_args_list:
            self.assertNotIn(password, " ".join(call.args[0]))
        pfx = run_dir / operator.PFX_NAME
        self.assertTrue(pfx.exists())
        self.openssl(["pkcs12", "-in", str(pfx), "-passin", "stdin", "-noout"], input_bytes=(password + "\n").encode())

    def test_extract_rerun_after_pfx_success_preserves_all_final_artifacts(self):
        run_dir, _ = self.prepare_run("extract-pfx-rerun")
        cert_der = self.make_matching_certificate_der(run_dir)
        source = self.write_output_file("pfx-rerun-issued.txt", self.issued_output(cert_der))
        password_file = self.root / "pfx-rerun-password.txt"
        password_file.write_text("fixture-rerun-pfx-password\n", encoding="utf-8")
        password_file.chmod(0o600)
        rc, stdout, stderr = self.run_cli(
            [
                "extract",
                "--run-dir",
                str(run_dir),
                "--mythic-output",
                str(source),
                "--pfx-password-file",
                str(password_file),
            ]
        )
        self.assertEqual(rc, 0, stderr)
        self.assertIn("VERIFIED certificate/private-key continuity", stdout)
        snapshots = {
            name: (run_dir / name).read_bytes()
            for name in (
                operator.MYTHIC_OUTPUT_NAME,
                operator.CERT_DER_NAME,
                operator.CERT_PEM_NAME,
                operator.PFX_NAME,
            )
        }

        rerun_source = self.write_output_file("pfx-rerun-malformed.txt", "unrelated output\n")
        rc, stdout, stderr = self.run_cli(
            ["extract", "--run-dir", str(run_dir), "--mythic-output", str(rerun_source)]
        )
        self.assertEqual(rc, 1)
        self.assertEqual(stdout, "")
        self.assertIn("certificate artifacts already exist", stderr)
        for name, content in snapshots.items():
            self.assertEqual((run_dir / name).read_bytes(), content)

    def test_extract_rejects_group_readable_pfx_password_file(self):
        run_dir, _ = self.prepare_run("extract-pfx-file-permissions")
        cert_der = self.make_matching_certificate_der(run_dir)
        source = self.write_output_file("pfx-file-permissions-output.txt", self.issued_output(cert_der))
        password = "fixture-exposed-pfx-password"
        password_file = self.root / "pfx-password-exposed.txt"
        password_file.write_text(password + "\n", encoding="utf-8")
        password_file.chmod(0o640)
        rc, stdout, stderr = self.run_cli(
            [
                "extract",
                "--run-dir",
                str(run_dir),
                "--mythic-output",
                str(source),
                "--pfx-password-file",
                str(password_file),
            ]
        )
        self.assertEqual(rc, 1)
        self.assertEqual(stdout, "")
        self.assertIn("must not be accessible by group or others", stderr)
        self.assertNotIn(password, stderr)
        self.assertFalse((run_dir / operator.CERT_DER_NAME).exists())
        self.assertFalse((run_dir / operator.PFX_NAME).exists())

    def test_extract_can_create_pfx_from_stdin_without_password_in_argv_or_output(self):
        run_dir, _ = self.prepare_run("extract-pfx-stdin")
        cert_der = self.make_matching_certificate_der(run_dir)
        source = self.write_output_file("pfx-stdin-output.txt", self.issued_output(cert_der))
        password = "fixture-stdin-pfx-password"
        argv = [
            "extract",
            "--run-dir",
            str(run_dir),
            "--mythic-output",
            str(source),
            "--pfx-password-stdin",
        ]
        with patch.object(operator.sys, "stdin", io.BytesIO((password + "\n").encode())):
            with patch.object(operator.subprocess, "run", wraps=subprocess.run) as run:
                rc, stdout, stderr = self.run_cli(argv)
        self.assertEqual(rc, 0, stderr)
        self.assertNotIn(password, " ".join(argv))
        self.assertNotIn(password, stdout)
        self.assertNotIn(password, stderr)
        for call in run.call_args_list:
            self.assertNotIn(password, " ".join(call.args[0]))
        pfx = run_dir / operator.PFX_NAME
        self.assertTrue(pfx.exists())
        self.openssl(["pkcs12", "-in", str(pfx), "-passin", "stdin", "-noout"], input_bytes=(password + "\n").encode())

    def test_extract_redacts_password_if_pfx_export_fails(self):
        run_dir, _ = self.prepare_run("extract-pfx-failure")
        cert_der = self.make_matching_certificate_der(run_dir)
        source = self.write_output_file("pfx-failure-output.txt", self.issued_output(cert_der))
        password = "fixture-failed-pfx-password"
        original_run = subprocess.run

        def fail_pfx_export(command, *args, **kwargs):
            if command[1:3] == ["pkcs12", "-export"]:
                return subprocess.CompletedProcess(command, 1, stdout=b"", stderr=(password + "\n").encode())
            return original_run(command, *args, **kwargs)

        with patch.object(operator.getpass, "getpass", side_effect=[password, password]):
            with patch.object(operator.subprocess, "run", side_effect=fail_pfx_export):
                rc, stdout, stderr = self.run_cli(
                    ["extract", "--run-dir", str(run_dir), "--mythic-output", str(source), "--pfx"]
                )
        self.assertEqual(rc, 1)
        self.assertEqual(stdout, "")
        self.assertIn("openssl pkcs12 -export failed: exit status 1", stderr)
        self.assertNotIn(password, stderr)
        self.assertFalse((run_dir / operator.CERT_DER_NAME).exists())
        self.assertFalse((run_dir / operator.CERT_PEM_NAME).exists())
        self.assertFalse((run_dir / operator.PFX_NAME).exists())

    def test_extract_rejects_mismatched_hidden_pfx_password_confirmation(self):
        run_dir, _ = self.prepare_run("extract-pfx-confirmation")
        cert_der = self.make_matching_certificate_der(run_dir)
        source = self.write_output_file("pfx-confirmation-output.txt", self.issued_output(cert_der))
        with patch.object(operator.getpass, "getpass", side_effect=["first-password", "second-password"]):
            rc, stdout, stderr = self.run_cli(
                ["extract", "--run-dir", str(run_dir), "--mythic-output", str(source), "--pfx"]
            )
        self.assertEqual(rc, 1)
        self.assertEqual(stdout, "")
        self.assertIn("confirmation does not match", stderr)
        self.assertNotIn("first-password", stderr)
        self.assertNotIn("second-password", stderr)
        self.assertFalse((run_dir / operator.CERT_DER_NAME).exists())
        self.assertFalse((run_dir / operator.PFX_NAME).exists())

    def test_cleanup_removes_only_known_files_and_reports_unrelated_files(self):
        run_dir, _ = self.prepare_run("cleanup-preserve")
        unrelated = run_dir / "operator-notes.txt"
        unrelated.write_text("keep me\n", encoding="utf-8")
        rc, stdout, stderr = self.run_cli(["cleanup", "--run-dir", str(run_dir)])
        self.assertEqual(rc, 0, stderr)
        self.assertIn(f"removed: {operator.KEY_NAME}", stdout)
        self.assertIn("preserved unrelated: operator-notes.txt", stdout)
        self.assertTrue(unrelated.exists())
        self.assertFalse((run_dir / operator.KEY_NAME).exists())
        self.assertFalse((run_dir / operator.MARKER_NAME).exists())

    def test_cleanup_refuses_unmarked_and_unsafe_directories(self):
        unmarked = self.root / "unmarked"
        unmarked.mkdir()
        for path in (unmarked, Path("/"), Path.home(), operator._repository_root()):
            with self.subTest(path=path):
                rc, stdout, stderr = self.run_cli(["cleanup", "--run-dir", str(path)])
                self.assertEqual(rc, 1)
                self.assertEqual(stdout, "")
                self.assertTrue("unsafe run directory" in stderr or "run marker" in stderr)

    def test_cleanup_refuses_symlink_run_dirs_and_symlink_files(self):
        run_dir, _ = self.prepare_run("cleanup-symlinks")
        alias = self.root / "run-alias"
        alias.symlink_to(run_dir, target_is_directory=True)
        rc, stdout, stderr = self.run_cli(["cleanup", "--run-dir", str(alias)])
        self.assertEqual(rc, 1)
        self.assertEqual(stdout, "")
        self.assertIn("symlink", stderr)
        self.assertTrue((run_dir / operator.KEY_NAME).exists())

        linked = run_dir / "linked-output.txt"
        linked.symlink_to(self.root / "outside.txt")
        rc, stdout, stderr = self.run_cli(["cleanup", "--run-dir", str(run_dir)])
        self.assertEqual(rc, 1)
        self.assertEqual(stdout, "")
        self.assertIn("symlink", stderr)
        self.assertTrue((run_dir / operator.KEY_NAME).exists())


if __name__ == "__main__":
    unittest.main()
