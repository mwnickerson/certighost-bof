import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from tools.certighost_mythic import (
    CertighostInputs,
    ValidationError,
    build_task_descriptor,
    compare_filesystem_snapshots,
    main,
    pack_apollo_execute_coff_arguments,
    pack_bof_args,
    parse_bof_output,
    unpack_bof_args,
    validate_evidence_bundle,
    validate_task_descriptor,
)


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "mythic"


def load_fixture(name):
    return json.loads((FIXTURE_ROOT / name).read_text(encoding="utf-8"))


def sample_inputs():
    return CertighostInputs.from_text(
        csr_der=bytes.fromhex("3003020100"),
        ca_config="ca01.lab.local\\LAB-CA",
        template="Machine",
        san_dns="ghost01.lab.local",
        cdc="10.10.10.44",
        rmd="dc01.lab.local",
    )


class PackingTests(unittest.TestCase):
    def test_pack_bof_args_is_byte_exact_for_apollo_fields(self):
        expected = bytes.fromhex(
            "050000003003020100"
            "15000000636130312e6c61622e6c6f63616c5c4c41422d4341"
            "070000004d616368696e65"
            "1100000067686f737430312e6c61622e6c6f63616c"
            "0b00000031302e31302e31302e3434"
            "0e000000646330312e6c61622e6c6f63616c"
        )
        self.assertEqual(pack_bof_args(sample_inputs()), expected)
        self.assertEqual(unpack_bof_args(expected), sample_inputs())

    def test_apollo_frame_prefixes_go_buffer_length(self):
        go_buffer = pack_bof_args(sample_inputs())
        apollo_frame = pack_apollo_execute_coff_arguments(sample_inputs())
        self.assertEqual(apollo_frame[:4], len(go_buffer).to_bytes(4, "little"))
        self.assertEqual(apollo_frame[4:], go_buffer)

    def test_unpack_rejects_trailing_data_and_invalid_inputs(self):
        with self.assertRaisesRegex(ValidationError, "trailing data"):
            unpack_bof_args(pack_bof_args(sample_inputs()) + b"\x00")
        with self.assertRaisesRegex(ValidationError, "template"):
            pack_bof_args(
                CertighostInputs.from_text(
                    csr_der=bytes.fromhex("3003020100"),
                    ca_config="ca01.lab.local\\LAB-CA",
                    template="Machine\ncdc:evil",
                    san_dns="ghost01.lab.local",
                    cdc="10.10.10.44",
                    rmd="dc01.lab.local",
                )
            )


class TaskDescriptorTests(unittest.TestCase):
    def test_descriptor_pins_execute_coff_v3_and_six_binary_arguments(self):
        descriptor = build_task_descriptor(
            inputs=sample_inputs(),
            callback_id="callback-fixture-001",
            agent_version="fixture-apollo-1.0",
            coff_name="certighost.x64.o",
            coff_sha256="26752802e3f48f8eb1424a15e4bad0d8b879937ba65e2a7339a31087dc803795",
        )
        validate_task_descriptor(descriptor)
        self.assertEqual(descriptor["mythic"]["command_name"], "execute_coff")
        self.assertEqual(descriptor["mythic"]["command_version"], 3)
        self.assertEqual(descriptor["coff"]["entrypoint"], "go")
        self.assertEqual(
            descriptor["task_payload"]["params"]["coff_arguments"],
            [
                ["base64", "MAMCAQA="],
                ["base64", "Y2EwMS5sYWIubG9jYWxcTEFCLUNB"],
                ["base64", "TWFjaGluZQ=="],
                ["base64", "Z2hvc3QwMS5sYWIubG9jYWw="],
                ["base64", "MTAuMTAuMTAuNDQ="],
                ["base64", "ZGMwMS5sYWIubG9jYWw="],
            ],
        )

    def test_descriptor_rejects_argument_order_drift(self):
        descriptor = load_fixture("vulnerable-success.json")["task"]
        descriptor["arguments"]["field_order"][0] = "template"
        with self.assertRaisesRegex(ValidationError, "order"):
            validate_task_descriptor(descriptor)

    def test_descriptor_rejects_operator_command_drift(self):
        descriptor = load_fixture("vulnerable-success.json")["task"]
        descriptor["operator_command"] += " base64:AA=="
        with self.assertRaisesRegex(ValidationError, "operator_command"):
            validate_task_descriptor(descriptor)

    def test_describe_task_cli_stays_offline_and_emits_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            csr = tmp / "request.der"
            coff = tmp / "certighost.x64.o"
            output = tmp / "task.json"
            csr.write_bytes(bytes.fromhex("3003020100"))
            coff.write_bytes(b"fixture-coff")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                rc = main(
                    [
                        "describe-task",
                        "--callback-id",
                        "callback-fixture-001",
                        "--agent-version",
                        "fixture-apollo-1.0",
                        "--coff-object",
                        str(coff),
                        "--csr-der",
                        str(csr),
                        "--ca-config",
                        "ca01.lab.local\\LAB-CA",
                        "--template",
                        "Machine",
                        "--san-dns",
                        "ghost01.lab.local",
                        "--cdc",
                        "10.10.10.44",
                        "--rmd",
                        "dc01.lab.local",
                        "--output",
                        str(output),
                    ]
                )
            self.assertEqual(rc, 0)
            descriptor = json.loads(stdout.getvalue())
            self.assertEqual(descriptor["mode"], "describe_only")
            self.assertEqual(descriptor["external_effects"], "none")
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), descriptor)


class OutputAndEvidenceTests(unittest.TestCase):
    def test_output_parser_handles_issued_and_non_issued_results(self):
        vulnerable = load_fixture("vulnerable-success.json")
        vulnerable_text = "".join(record["text"] for record in vulnerable["output_records"])
        parsed_vulnerable = parse_bof_output(vulnerable_text)
        self.assertEqual(parsed_vulnerable.kind, "issued")
        self.assertEqual(parsed_vulnerable.request_id, 41)
        self.assertEqual(parsed_vulnerable.certificate_der, bytes.fromhex("3003020101"))

        patched = load_fixture("patched-negative-control.json")
        patched_text = "".join(record["text"] for record in patched["output_records"])
        parsed_patched = parse_bof_output(patched_text)
        self.assertEqual(parsed_patched.kind, "non_issued")
        self.assertEqual(parsed_patched.request_id, 42)
        self.assertEqual(parsed_patched.last_status, "80094800")

    def test_output_parser_rejects_mismatched_certificate_lengths(self):
        parsed = parse_bof_output(
            "CERTIGHOST_RESULT disposition=3 request_id=1 cert_encoding=base64 "
            "cert_der_bytes=7 cert_base64_chars=8\n"
            "CERTIGHOST_CERT_BEGIN\nMAMCAQE=\nCERTIGHOST_CERT_END\n"
        )
        self.assertEqual(parsed.kind, "invalid")
        self.assertIn("DER byte count", parsed.errors[0])

    def test_output_parser_rejects_missing_request_id_and_non_der_certificate(self):
        parsed = parse_bof_output(
            "CERTIGHOST_RESULT disposition=3 request_id=-1 cert_encoding=base64 "
            "cert_der_bytes=4 cert_base64_chars=8\n"
            "CERTIGHOST_CERT_BEGIN\nAQIDBA==\nCERTIGHOST_CERT_END\n"
        )
        self.assertEqual(parsed.kind, "invalid")
        self.assertIn("request ID", " ".join(parsed.errors))
        self.assertIn("DER", " ".join(parsed.errors))

    def test_filesystem_compare_detects_before_after_changes(self):
        fixture = load_fixture("vulnerable-success.json")
        before = fixture["victim_filesystem"]["before"]
        after = copy.deepcopy(fixture["victim_filesystem"]["after"])
        after["entries"][0]["sha256"] = "0" * 64
        comparison = compare_filesystem_snapshots(before, after)
        self.assertFalse(comparison.unchanged)
        self.assertEqual(
            comparison.modified,
            ("C:\\ProgramData\\redantonetta\\baseline-sentinel.txt",),
        )

    def test_vulnerable_fixture_classifies_and_preserves_identifiers(self):
        fixture = load_fixture("vulnerable-success.json")
        assessment = validate_evidence_bundle(fixture)
        self.assertTrue(assessment.valid)
        self.assertEqual(assessment.classification, "vulnerable_issuance")
        self.assertEqual(
            fixture["identifiers"]["output_ids"],
            [record["output_id"] for record in fixture["output_records"]],
        )

    def test_patched_fixture_classifies_as_negative_control(self):
        assessment = validate_evidence_bundle(load_fixture("patched-negative-control.json"))
        self.assertTrue(assessment.valid)
        self.assertEqual(assessment.classification, "patched_negative_control")

    def test_identifier_drift_is_invalid_incomplete_evidence(self):
        fixture = load_fixture("vulnerable-success.json")
        fixture["identifiers"]["output_ids"].reverse()
        assessment = validate_evidence_bundle(fixture)
        self.assertFalse(assessment.valid)
        self.assertEqual(assessment.classification, "invalid_incomplete_evidence")
        self.assertIn("output record IDs", assessment.reasons[0])

    def test_repeatability_and_cleanup_records_are_required(self):
        fixture = load_fixture("patched-negative-control.json")
        fixture["repeatability"]["attempts"] = fixture["repeatability"]["attempts"][:1]
        assessment = validate_evidence_bundle(fixture)
        self.assertFalse(assessment.valid)
        self.assertIn("at least two", assessment.reasons[0])

        fixture = load_fixture("patched-negative-control.json")
        fixture["cleanup"]["records"] = fixture["cleanup"]["records"][:1]
        assessment = validate_evidence_bundle(fixture)
        self.assertFalse(assessment.valid)
        self.assertIn("rollback verification", assessment.reasons[0])

        fixture = load_fixture("patched-negative-control.json")
        fixture["cleanup"]["records"][0]["status"] = "failed"
        assessment = validate_evidence_bundle(fixture)
        self.assertFalse(assessment.valid)
        self.assertIn("recorded or verified", assessment.reasons[0])


if __name__ == "__main__":
    unittest.main()
