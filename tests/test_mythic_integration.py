import base64
import copy
import io
import json
import struct
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
    pack_legacy_bof_args,
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


def pack_wire_fields(fields):
    payload = b"".join(struct.pack("<I", len(value)) + value for value in fields)
    return struct.pack("<I", len(payload)) + payload


def canonical_wire_fields(inputs):
    return [inputs.csr_der, *(value + b"\x00" for value in inputs.ordered_fields()[1:])]


class PackingTests(unittest.TestCase):
    def test_pack_bof_args_is_byte_exact_for_canonical_apollo_frame(self):
        expected = bytes.fromhex(
            "68000000"
            "050000003003020100"
            "16000000636130312e6c61622e6c6f63616c5c4c41422d434100"
            "080000004d616368696e6500"
            "1200000067686f737430312e6c61622e6c6f63616c00"
            "0c00000031302e31302e31302e343400"
            "0f000000646330312e6c61622e6c6f63616c00"
        )
        self.assertEqual(pack_bof_args(sample_inputs()), expected)
        self.assertEqual(unpack_bof_args(expected), sample_inputs())

    def test_apollo_frame_is_the_intact_go_buffer(self):
        go_buffer = pack_bof_args(sample_inputs())
        apollo_frame = pack_apollo_execute_coff_arguments(sample_inputs())
        self.assertEqual(apollo_frame, go_buffer)
        self.assertEqual(apollo_frame[:4], (len(go_buffer) - 4).to_bytes(4, "little"))

    def test_apollo_frame_matches_source_string_and_base64_loader_rules(self):
        typed_args = [
            ["base64", base64.b64encode(sample_inputs().csr_der).decode("ascii")],
            ["string", "ca01.lab.local\\LAB-CA"],
            ["string", "Machine"],
            ["string", "ghost01.lab.local"],
            ["string", "10.10.10.44"],
            ["string", "dc01.lab.local"],
        ]
        packed = bytearray()
        for kind, value in typed_args:
            raw = base64.b64decode(value) if kind == "base64" else (value + "\x00").encode("utf-8")
            packed.extend(struct.pack("<I", len(raw)))
            packed.extend(raw)
        source_compatible = struct.pack("<I", len(packed)) + packed
        self.assertEqual(pack_apollo_execute_coff_arguments(sample_inputs()), source_compatible)

    def test_unpack_strips_one_terminal_nul_and_accepts_legacy_text(self):
        self.assertEqual(unpack_bof_args(pack_bof_args(sample_inputs())), sample_inputs())
        self.assertEqual(unpack_bof_args(pack_legacy_bof_args(sample_inputs())), sample_inputs())

        optional_san = CertighostInputs.from_text(
            csr_der=bytes.fromhex("3003020100"),
            ca_config="ca01.lab.local\\LAB-CA",
            template="Machine",
            san_dns="",
            cdc="10.10.10.44",
            rmd="dc01.lab.local",
        )
        self.assertEqual(unpack_bof_args(pack_bof_args(optional_san)), optional_san)

    def test_unpack_rejects_embedded_nul_double_terminal_nul_and_empty_required_text(self):
        fields = canonical_wire_fields(sample_inputs())
        fields[2] = b"Mac\x00hine\x00"
        with self.assertRaisesRegex(ValidationError, "embedded NUL"):
            unpack_bof_args(pack_wire_fields(fields))

        fields = canonical_wire_fields(sample_inputs())
        fields[2] = b"Machine\x00\x00"
        with self.assertRaisesRegex(ValidationError, "embedded NUL"):
            unpack_bof_args(pack_wire_fields(fields))

        fields = canonical_wire_fields(sample_inputs())
        fields[4] = b"\x00"
        with self.assertRaisesRegex(ValidationError, "cdc must not be empty"):
            unpack_bof_args(pack_wire_fields(fields))

    def test_unpack_rejects_trailing_data_and_invalid_inputs(self):
        with self.assertRaisesRegex(ValidationError, "trailing data"):
            unpack_bof_args(pack_bof_args(sample_inputs()) + b"\x00")
        with self.assertRaisesRegex(ValidationError, "trailing data"):
            unpack_bof_args(pack_wire_fields(canonical_wire_fields(sample_inputs()) + [b""]))
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

    def test_unpack_rejects_outer_length_mismatch(self):
        with self.assertRaisesRegex(ValidationError, "outer length"):
            unpack_bof_args(b"\x00\x00\x00")

        frame = bytearray(pack_bof_args(sample_inputs()))
        frame[:4] = (len(frame) - 3).to_bytes(4, "little")
        with self.assertRaisesRegex(ValidationError, "outer length"):
            unpack_bof_args(bytes(frame))

        frame = bytearray(pack_bof_args(sample_inputs()))
        frame[:4] = (len(frame) - 5).to_bytes(4, "little")
        with self.assertRaisesRegex(ValidationError, "outer frame"):
            unpack_bof_args(bytes(frame))

        frame = bytearray(pack_bof_args(sample_inputs()))
        frame[-19:-15] = (0xFFFFFFFF).to_bytes(4, "little")
        with self.assertRaisesRegex(ValidationError, "truncated inside rmd"):
            unpack_bof_args(bytes(frame))


class TaskDescriptorTests(unittest.TestCase):
    def test_descriptor_pins_execute_coff_v3_and_mixed_arguments(self):
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
                ["string", "ca01.lab.local\\LAB-CA"],
                ["string", "Machine"],
                ["string", "ghost01.lab.local"],
                ["string", "10.10.10.44"],
                ["string", "dc01.lab.local"],
            ],
        )
        self.assertEqual(
            descriptor["arguments"]["field_types"],
            ["base64", "string", "string", "string", "string", "string"],
        )
        self.assertEqual(descriptor["operator_command"].count("base64:"), 1)
        self.assertEqual(descriptor["operator_command"].count("string:"), 5)

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

    def test_descriptor_rejects_type_order_drift_and_extra_argument(self):
        descriptor = load_fixture("vulnerable-success.json")["task"]
        descriptor["task_payload"]["params"]["coff_arguments"][1][0] = "base64"
        with self.assertRaisesRegex(ValidationError, "string typed"):
            validate_task_descriptor(descriptor)

        descriptor = load_fixture("vulnerable-success.json")["task"]
        descriptor["task_payload"]["params"]["coff_arguments"].append(["string", "extra"])
        with self.assertRaisesRegex(ValidationError, "exactly six"):
            validate_task_descriptor(descriptor)

    def test_descriptor_rejects_text_tokens_stock_apollo_cli_cannot_preserve(self):
        spaced_template = CertighostInputs.from_text(
            csr_der=bytes.fromhex("3003020100"),
            ca_config="ca01.lab.local\\LAB-CA",
            template="Domain Controller",
            san_dns="ghost01.lab.local",
            cdc="10.10.10.44",
            rmd="dc01.lab.local",
        )
        self.assertEqual(unpack_bof_args(pack_bof_args(spaced_template)), spaced_template)
        with self.assertRaisesRegex(ValidationError, "cannot contain spaces"):
            build_task_descriptor(
                inputs=spaced_template,
                callback_id="callback-fixture-001",
                agent_version="fixture-apollo-1.0",
                coff_name="certighost.x64.o",
                coff_sha256="26752802e3f48f8eb1424a15e4bad0d8b879937ba65e2a7339a31087dc803795",
            )

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

    def test_output_parser_accepts_apollo_newline_free_issued_aggregation(self):
        parsed = parse_bof_output(
            "CERTIGHOST_RESULT disposition=3 request_id=41 cert_encoding=base64 "
            "cert_der_bytes=5 cert_base64_chars=8"
            "CERTIGHOST_CERT_BEGIN\nMAMCAQE=\nCERTIGHOST_CERT_END\n"
        )
        self.assertEqual(parsed.kind, "issued")
        self.assertEqual(parsed.request_id, 41)
        self.assertEqual(parsed.certificate_der, bytes.fromhex("3003020101"))

    def test_output_parser_rejects_mixed_markers_with_apollo_aggregation(self):
        parsed = parse_bof_output(
            "CERTIGHOST_RESULT disposition=3 request_id=41 cert_encoding=base64 "
            "cert_der_bytes=5 cert_base64_chars=8"
            "CERTIGHOST_CERT_BEGIN\nMAMCAQE=\nCERTIGHOST_CERT_END\n"
            "certighost: request not issued (disposition=2 request_id=42)\n"
        )
        self.assertEqual(parsed.kind, "invalid")
        self.assertIn("mixed", " ".join(parsed.errors))

    def test_output_parser_rejects_detached_or_reordered_certificate_blocks(self):
        detached = parse_bof_output(
            "CERTIGHOST_RESULT disposition=3 request_id=41 cert_encoding=base64 "
            "cert_der_bytes=5 cert_base64_chars=8\n"
            "unrelated output\n"
            "CERTIGHOST_CERT_BEGIN\nMAMCAQE=\nCERTIGHOST_CERT_END\n"
        )
        self.assertEqual(detached.kind, "invalid")
        self.assertIn("immediately followed", " ".join(detached.errors))

        reordered = parse_bof_output(
            "CERTIGHOST_CERT_BEGIN\nMAMCAQE=\nCERTIGHOST_CERT_END\n"
            "CERTIGHOST_RESULT disposition=3 request_id=41 cert_encoding=base64 "
            "cert_der_bytes=5 cert_base64_chars=8"
        )
        self.assertEqual(reordered.kind, "invalid")
        self.assertIn("immediately followed", " ".join(reordered.errors))

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
