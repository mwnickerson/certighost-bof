#!/usr/bin/env python3
"""Offline Mythic task description and evidence validation for Certighost."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

TASK_SCHEMA_VERSION = "certighost.mythic.task/v1"
EVIDENCE_SCHEMA_VERSION = "certighost.mythic.evidence/v1"
APOLLO_ADAPTER = "apollo.execute_coff/v3"
APOLLO_COMMAND_NAME = "execute_coff"
APOLLO_COMMAND_VERSION = 3
ENTRYPOINT = "go"
FIELD_NAMES = ("csr_der", "ca_config", "template", "san_dns", "cdc", "rmd")

MAX_CSR_LEN = 262144
MAX_CA_CONFIG_LEN = 512
MAX_TEMPLATE_LEN = 128
MAX_DNS_VALUE_LEN = 255
MAX_CERT_LEN = 1048576

ISSUED_HEADER_RE = re.compile(
    r"^CERTIGHOST_RESULT disposition=(?P<disposition>-?\d+) "
    r"request_id=(?P<request_id>-?\d+) cert_encoding=base64 "
    r"cert_der_bytes=(?P<cert_der_bytes>\d+) "
    r"cert_base64_chars=(?P<cert_base64_chars>\d+)"
    r"(?=\n|CERTIGHOST_CERT_BEGIN\n|\Z)",
    re.MULTILINE,
)
CERT_BLOCK_RE = re.compile(
    r"CERTIGHOST_CERT_BEGIN\n(?P<certificate>.*?)\nCERTIGHOST_CERT_END",
    re.DOTALL,
)
NON_ISSUED_RE = re.compile(
    r"certighost: request not issued \(disposition=(?P<disposition>-?\d+) "
    r"request_id=(?P<request_id>-?\d+)"
    r"(?: last_status=0x(?P<last_status>[0-9a-fA-F]{8}))?\)"
)


class ValidationError(ValueError):
    """Raised when an offline task or evidence object violates the contract."""


@dataclass(frozen=True)
class CertighostInputs:
    csr_der: bytes
    ca_config: bytes
    template: bytes
    san_dns: bytes
    cdc: bytes
    rmd: bytes

    @classmethod
    def from_text(
        cls,
        *,
        csr_der: bytes,
        ca_config: str,
        template: str,
        san_dns: str,
        cdc: str,
        rmd: str,
    ) -> "CertighostInputs":
        try:
            fields = {
                "ca_config": ca_config.encode("ascii"),
                "template": template.encode("ascii"),
                "san_dns": san_dns.encode("ascii"),
                "cdc": cdc.encode("ascii"),
                "rmd": rmd.encode("ascii"),
            }
        except UnicodeEncodeError as exc:
            raise ValidationError("all text arguments must be ASCII") from exc
        return cls(csr_der=csr_der, **fields)

    def ordered_fields(self) -> tuple[bytes, bytes, bytes, bytes, bytes, bytes]:
        return (
            self.csr_der,
            self.ca_config,
            self.template,
            self.san_dns,
            self.cdc,
            self.rmd,
        )


@dataclass(frozen=True)
class ParsedOutput:
    kind: str
    disposition: int | None
    request_id: int | None
    certificate_der: bytes | None
    last_status: str | None
    errors: tuple[str, ...]


@dataclass(frozen=True)
class FilesystemComparison:
    unchanged: bool
    before_capture_id: str
    after_capture_id: str
    added: tuple[str, ...]
    removed: tuple[str, ...]
    modified: tuple[str, ...]


@dataclass(frozen=True)
class EvidenceAssessment:
    classification: str
    valid: bool
    reasons: tuple[str, ...]
    parsed_output: ParsedOutput
    filesystem: FilesystemComparison | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification,
            "valid": self.valid,
            "reasons": list(self.reasons),
            "parsed_output": {
                "kind": self.parsed_output.kind,
                "disposition": self.parsed_output.disposition,
                "request_id": self.parsed_output.request_id,
                "certificate_der_bytes": (
                    len(self.parsed_output.certificate_der)
                    if self.parsed_output.certificate_der is not None
                    else None
                ),
                "last_status": self.parsed_output.last_status,
                "errors": list(self.parsed_output.errors),
            },
            "filesystem": (
                {
                    "unchanged": self.filesystem.unchanged,
                    "before_capture_id": self.filesystem.before_capture_id,
                    "after_capture_id": self.filesystem.after_capture_id,
                    "added": list(self.filesystem.added),
                    "removed": list(self.filesystem.removed),
                    "modified": list(self.filesystem.modified),
                }
                if self.filesystem is not None
                else None
            ),
        }


def _require_nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or value == "":
        raise ValidationError(f"{label} must be a non-empty string")
    return value


def _validate_der_sequence(value: bytes, label: str, limit: int) -> None:
    if len(value) == 0:
        raise ValidationError(f"{label} must not be empty")
    if len(value) > limit:
        raise ValidationError(f"{label} exceeds {limit} bytes")
    if len(value) < 2 or value[0] != 0x30:
        raise ValidationError(f"{label} must be a bounded outer DER SEQUENCE")
    first_len = value[1]
    if first_len & 0x80 == 0:
        header_len = 2
        content_len = first_len
    else:
        octets = first_len & 0x7F
        if octets == 0 or octets > 4 or len(value) < 2 + octets:
            raise ValidationError(f"{label} must be a bounded outer DER SEQUENCE")
        if value[2] == 0:
            raise ValidationError(f"{label} must use minimal DER length encoding")
        content_len = int.from_bytes(value[2 : 2 + octets], "big")
        if content_len < 128:
            raise ValidationError(f"{label} must use minimal DER length encoding")
        header_len = 2 + octets
    if content_len != len(value) - header_len:
        raise ValidationError(f"{label} outer DER length does not match the buffer")


def _validate_visible_ascii(value: bytes, label: str, limit: int) -> None:
    if len(value) == 0:
        raise ValidationError(f"{label} must not be empty")
    if len(value) > limit:
        raise ValidationError(f"{label} exceeds {limit} bytes")
    if any(byte < 0x20 or byte > 0x7E for byte in value):
        raise ValidationError(f"{label} must contain visible ASCII only")


def _validate_ca_config(value: bytes) -> None:
    _validate_visible_ascii(value, "ca_config", MAX_CA_CONFIG_LEN)
    if b":" in value or b"/" in value or b"\r" in value or b"\n" in value:
        raise ValidationError("ca_config must be ASCII host\\CAName without separators")
    if value.count(b"\\") != 1 or value.startswith(b"\\") or value.endswith(b"\\"):
        raise ValidationError("ca_config must be ASCII host\\CAName")


def _validate_template(value: bytes) -> None:
    _validate_visible_ascii(value, "template", MAX_TEMPLATE_LEN)
    if b":" in value or b"\r" in value or b"\n" in value:
        raise ValidationError("template contains an invalid attribute separator")


def _validate_dns_value(value: bytes, label: str, optional: bool) -> None:
    if len(value) == 0:
        if optional:
            return
        raise ValidationError(f"{label} must not be empty")
    if len(value) > MAX_DNS_VALUE_LEN:
        raise ValidationError(f"{label} exceeds {MAX_DNS_VALUE_LEN} bytes")
    allowed = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_"
    if any(byte not in allowed for byte in value):
        raise ValidationError(f"{label} contains an invalid DNS/IP-like character")


def validate_inputs(inputs: CertighostInputs) -> None:
    _validate_der_sequence(inputs.csr_der, "csr_der", MAX_CSR_LEN)
    _validate_ca_config(inputs.ca_config)
    _validate_template(inputs.template)
    _validate_dns_value(inputs.san_dns, "san_dns", optional=True)
    _validate_dns_value(inputs.cdc, "cdc", optional=False)
    _validate_dns_value(inputs.rmd, "rmd", optional=False)


def _pack_bof_payload(inputs: CertighostInputs) -> bytes:
    validate_inputs(inputs)
    packed = bytearray()
    for value in inputs.ordered_fields():
        packed.extend(struct.pack("<I", len(value)))
        packed.extend(value)
    return bytes(packed)


def pack_bof_args(inputs: CertighostInputs) -> bytes:
    """Return the canonical outer frame received intact by go."""
    payload = _pack_bof_payload(inputs)
    return struct.pack("<I", len(payload)) + payload


def unpack_bof_args(buffer: bytes) -> CertighostInputs:
    if len(buffer) < 4:
        raise ValidationError("packed buffer is truncated before the outer length")
    payload_len = struct.unpack_from("<I", buffer, 0)[0]
    available_payload_len = len(buffer) - 4
    if payload_len > available_payload_len:
        raise ValidationError("packed buffer outer length exceeds the available payload")
    if payload_len < available_payload_len:
        raise ValidationError("packed buffer contains trailing data outside the outer frame")
    payload = buffer[4:]
    fields: list[bytes] = []
    offset = 0
    for field_name in FIELD_NAMES:
        if len(payload) - offset < 4:
            raise ValidationError(f"packed buffer is truncated before {field_name}")
        field_len = struct.unpack_from("<I", payload, offset)[0]
        offset += 4
        if field_len > len(payload) - offset:
            raise ValidationError(f"packed buffer is truncated inside {field_name}")
        fields.append(payload[offset : offset + field_len])
        offset += field_len
    if offset != len(payload):
        raise ValidationError("packed buffer contains trailing data")
    inputs = CertighostInputs(*fields)
    validate_inputs(inputs)
    return inputs


def pack_apollo_execute_coff_arguments(inputs: CertighostInputs) -> bytes:
    """Return Apollo execute_coff v3's outer argument frame passed intact to go."""
    return pack_bof_args(inputs)


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def build_task_descriptor(
    *,
    inputs: CertighostInputs,
    callback_id: str,
    agent_version: str,
    coff_name: str,
    coff_sha256: str,
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    """Build a describe-only Apollo execute_coff v3 task payload."""
    _require_nonempty_string(callback_id, "callback_id")
    _require_nonempty_string(agent_version, "agent_version")
    _require_nonempty_string(coff_name, "coff_name")
    if not re.fullmatch(r"[A-Za-z0-9._-]+\.o", coff_name):
        raise ValidationError("coff_name must be a basename ending in .o")
    if not re.fullmatch(r"[0-9a-f]{64}", coff_sha256):
        raise ValidationError("coff_sha256 must be a lowercase SHA-256 hex digest")
    if timeout_seconds <= 0:
        raise ValidationError("timeout_seconds must be greater than zero")
    go_buffer = pack_bof_args(inputs)
    apollo_buffer = pack_apollo_execute_coff_arguments(inputs)
    typed_args = [["base64", _b64(value)] for value in inputs.ordered_fields()]
    operator_args = " ".join(f"base64:{entry[1]}" for entry in typed_args)
    return {
        "schema_version": TASK_SCHEMA_VERSION,
        "mode": "describe_only",
        "external_effects": "none",
        "victim_write_policy": "forbid",
        "mythic": {
            "callback_id": callback_id,
            "agent": "apollo",
            "agent_version": agent_version,
            "command_name": APOLLO_COMMAND_NAME,
            "command_version": APOLLO_COMMAND_VERSION,
            "adapter": APOLLO_ADAPTER,
        },
        "coff": {
            "name": coff_name,
            "sha256": coff_sha256,
            "architecture": "x64",
            "entrypoint": ENTRYPOINT,
            "delivery": "existing_agent_in_memory_cache",
        },
        "arguments": {
            "field_order": list(FIELD_NAMES),
            "field_types": ["base64"] * len(FIELD_NAMES),
            "go_buffer_encoding": "base64",
            "go_buffer_b64": _b64(go_buffer),
            "go_buffer_sha256": _sha256(go_buffer),
            "go_buffer_bytes": len(go_buffer),
            "apollo_execute_coff_frame_encoding": "hex",
            "apollo_execute_coff_frame_hex": apollo_buffer.hex(),
            "apollo_execute_coff_frame_bytes": len(apollo_buffer),
        },
        "task_payload": {
            "command": APOLLO_COMMAND_NAME,
            "params": {
                "coff_name": coff_name,
                "function_name": ENTRYPOINT,
                "timeout": timeout_seconds,
                "coff_arguments": typed_args,
            },
        },
        "operator_command": (
            f"{APOLLO_COMMAND_NAME} -Coff {coff_name} -Function {ENTRYPOINT} "
            f"-Timeout {timeout_seconds} -Arguments {operator_args}"
        ),
    }


def validate_task_descriptor(task: Mapping[str, Any]) -> None:
    if task.get("schema_version") != TASK_SCHEMA_VERSION:
        raise ValidationError("task schema_version is not supported")
    if task.get("mode") != "describe_only" or task.get("external_effects") != "none":
        raise ValidationError("task must remain describe-only with no external effects")
    if task.get("victim_write_policy") != "forbid":
        raise ValidationError("task must forbid victim-side writes")
    mythic = task.get("mythic")
    if not isinstance(mythic, Mapping):
        raise ValidationError("task.mythic must be an object")
    if mythic.get("agent") != "apollo":
        raise ValidationError("task must target the existing apollo agent")
    if mythic.get("command_name") != APOLLO_COMMAND_NAME:
        raise ValidationError("task must use execute_coff")
    if mythic.get("command_version") != APOLLO_COMMAND_VERSION:
        raise ValidationError("task must pin execute_coff command version 3")
    if mythic.get("adapter") != APOLLO_ADAPTER:
        raise ValidationError("task adapter is not supported")
    _require_nonempty_string(mythic.get("callback_id"), "task.mythic.callback_id")
    _require_nonempty_string(mythic.get("agent_version"), "task.mythic.agent_version")
    coff = task.get("coff")
    if not isinstance(coff, Mapping):
        raise ValidationError("task.coff must be an object")
    if coff.get("entrypoint") != ENTRYPOINT or coff.get("architecture") != "x64":
        raise ValidationError("task must invoke x64 entrypoint go")
    if coff.get("delivery") != "existing_agent_in_memory_cache":
        raise ValidationError("task must use an existing in-memory BOF cache")
    _require_nonempty_string(coff.get("name"), "task.coff.name")
    if not re.fullmatch(r"[A-Za-z0-9._-]+\.o", str(coff["name"])):
        raise ValidationError("task.coff.name must be a basename ending in .o")
    if not isinstance(coff.get("sha256"), str) or not re.fullmatch(
        r"[0-9a-f]{64}", coff["sha256"]
    ):
        raise ValidationError("task.coff.sha256 must be a lowercase SHA-256 digest")
    payload = task.get("task_payload")
    if not isinstance(payload, Mapping) or payload.get("command") != APOLLO_COMMAND_NAME:
        raise ValidationError("task_payload.command must be execute_coff")
    params = payload.get("params")
    if not isinstance(params, Mapping):
        raise ValidationError("task_payload.params must be an object")
    if params.get("coff_name") != coff.get("name") or params.get("function_name") != ENTRYPOINT:
        raise ValidationError("task payload BOF name or entrypoint is inconsistent")
    if not isinstance(params.get("timeout"), int) or params["timeout"] <= 0:
        raise ValidationError("task payload timeout must be a positive integer")
    typed_args = params.get("coff_arguments")
    if not isinstance(typed_args, list) or len(typed_args) != len(FIELD_NAMES):
        raise ValidationError("task payload must contain exactly six COFF arguments")
    raw_fields: list[bytes] = []
    for index, entry in enumerate(typed_args):
        if not isinstance(entry, list) or len(entry) != 2 or entry[0] != "base64":
            raise ValidationError(f"coff_arguments[{index}] must be a base64 typed argument")
        try:
            raw_fields.append(base64.b64decode(entry[1], validate=True))
        except (binascii.Error, ValueError) as exc:
            raise ValidationError(f"coff_arguments[{index}] is not valid base64") from exc
    inputs = CertighostInputs(*raw_fields)
    expected_go_buffer = pack_bof_args(inputs)
    arguments = task.get("arguments")
    if not isinstance(arguments, Mapping):
        raise ValidationError("task.arguments must be an object")
    if arguments.get("field_order") != list(FIELD_NAMES):
        raise ValidationError("task argument order does not match the BOF contract")
    if arguments.get("field_types") != ["base64"] * len(FIELD_NAMES):
        raise ValidationError("task argument types must remain six binary fields")
    if arguments.get("go_buffer_encoding") != "base64":
        raise ValidationError("task go buffer encoding must remain base64")
    if arguments.get("go_buffer_b64") != _b64(expected_go_buffer):
        raise ValidationError("task go buffer does not match the six typed arguments")
    if arguments.get("go_buffer_sha256") != _sha256(expected_go_buffer):
        raise ValidationError("task go buffer SHA-256 does not match")
    if arguments.get("go_buffer_bytes") != len(expected_go_buffer):
        raise ValidationError("task go buffer length does not match")
    expected_apollo_frame = pack_apollo_execute_coff_arguments(inputs)
    if arguments.get("apollo_execute_coff_frame_encoding") != "hex":
        raise ValidationError("task Apollo frame encoding must remain hex")
    if arguments.get("apollo_execute_coff_frame_hex") != expected_apollo_frame.hex():
        raise ValidationError("task Apollo frame does not match execute_coff v3 packing")
    if arguments.get("apollo_execute_coff_frame_bytes") != len(expected_apollo_frame):
        raise ValidationError("task Apollo frame length does not match")
    operator_args = " ".join(f"base64:{entry[1]}" for entry in typed_args)
    expected_operator_command = (
        f"{APOLLO_COMMAND_NAME} -Coff {coff['name']} -Function {ENTRYPOINT} "
        f"-Timeout {params['timeout']} -Arguments {operator_args}"
    )
    if task.get("operator_command") != expected_operator_command:
        raise ValidationError("task operator_command does not match the pinned payload")


def parse_bof_output(output_text: str) -> ParsedOutput:
    issued_headers = list(ISSUED_HEADER_RE.finditer(output_text))
    cert_blocks = list(CERT_BLOCK_RE.finditer(output_text))
    non_issued = list(NON_ISSUED_RE.finditer(output_text))
    errors: list[str] = []
    if len(issued_headers) > 1:
        errors.append("multiple issued result headers were found")
    if len(cert_blocks) > 1:
        errors.append("multiple certificate blocks were found")
    if issued_headers:
        header = issued_headers[0]
        if len(cert_blocks) != 1:
            errors.append("issued result is missing exactly one certificate block")
            return ParsedOutput("invalid", None, None, None, None, tuple(errors))
        cert_block = cert_blocks[0]
        if cert_block.start() != header.end():
            newline_block_start = header.end() + 1
            if (
                header.end() >= len(output_text)
                or output_text[header.end()] != "\n"
                or cert_block.start() != newline_block_start
            ):
                errors.append("issued result header is not immediately followed by its certificate block")
        cert_text = "".join(cert_block.group("certificate").split())
        try:
            cert_der = base64.b64decode(cert_text, validate=True)
        except (binascii.Error, ValueError):
            errors.append("certificate block is not valid base64")
            return ParsedOutput("invalid", None, None, None, None, tuple(errors))
        disposition = int(header.group("disposition"))
        request_id = int(header.group("request_id"))
        if disposition != 3:
            errors.append("issued result header must use disposition 3")
        if request_id < 0:
            errors.append("issued result must preserve a non-negative request ID")
        if len(cert_der) != int(header.group("cert_der_bytes")):
            errors.append("certificate DER byte count does not match the header")
        if len(cert_text) != int(header.group("cert_base64_chars")):
            errors.append("certificate base64 character count does not match the header")
        try:
            _validate_der_sequence(cert_der, "certificate_der", MAX_CERT_LEN)
        except ValidationError as exc:
            errors.append(str(exc))
        if non_issued:
            errors.append("issued and non-issued result markers are mixed")
        if errors:
            return ParsedOutput("invalid", disposition, request_id, cert_der, None, tuple(errors))
        return ParsedOutput("issued", disposition, request_id, cert_der, None, ())
    if cert_blocks:
        errors.append("certificate block exists without an issued result header")
    if len(non_issued) > 1:
        errors.append("multiple non-issued result markers were found")
    if non_issued:
        match = non_issued[0]
        if errors:
            return ParsedOutput("invalid", None, None, None, None, tuple(errors))
        disposition = int(match.group("disposition"))
        request_id = int(match.group("request_id"))
        if request_id < 0:
            return ParsedOutput(
                "invalid",
                disposition,
                request_id,
                None,
                match.group("last_status"),
                ("non-issued result must preserve a non-negative request ID",),
            )
        return ParsedOutput(
            "non_issued",
            disposition,
            request_id,
            None,
            match.group("last_status"),
            (),
        )
    errors.append("no Certighost result marker was found")
    return ParsedOutput("invalid", None, None, None, None, tuple(errors))


def _snapshot_entries(snapshot: Mapping[str, Any], label: str) -> dict[str, tuple[Any, ...]]:
    _require_nonempty_string(snapshot.get("capture_id"), f"{label}.capture_id")
    _require_nonempty_string(snapshot.get("host"), f"{label}.host")
    _require_nonempty_string(snapshot.get("collected_at"), f"{label}.collected_at")
    entries = snapshot.get("entries")
    if not isinstance(entries, list):
        raise ValidationError(f"{label}.entries must be a list")
    normalized: dict[str, tuple[Any, ...]] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            raise ValidationError(f"{label}.entries[{index}] must be an object")
        path = _require_nonempty_string(entry.get("path"), f"{label}.entries[{index}].path")
        if path in normalized:
            raise ValidationError(f"{label}.entries contains duplicate path {path}")
        kind = _require_nonempty_string(entry.get("kind"), f"{label}.entries[{index}].kind")
        size = entry.get("size")
        sha256 = entry.get("sha256")
        if not isinstance(size, int) or size < 0:
            raise ValidationError(f"{label}.entries[{index}].size must be a non-negative integer")
        if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise ValidationError(f"{label}.entries[{index}].sha256 must be a SHA-256 digest")
        normalized[path] = (kind, size, sha256)
    return normalized


def compare_filesystem_snapshots(
    before: Mapping[str, Any], after: Mapping[str, Any]
) -> FilesystemComparison:
    before_entries = _snapshot_entries(before, "victim_filesystem.before")
    after_entries = _snapshot_entries(after, "victim_filesystem.after")
    if before.get("host") != after.get("host"):
        raise ValidationError("victim filesystem snapshots must refer to the same host")
    if before.get("capture_id") == after.get("capture_id"):
        raise ValidationError("victim filesystem snapshots must use distinct capture IDs")
    before_paths = set(before_entries)
    after_paths = set(after_entries)
    added = tuple(sorted(after_paths - before_paths))
    removed = tuple(sorted(before_paths - after_paths))
    modified = tuple(
        sorted(path for path in before_paths & after_paths if before_entries[path] != after_entries[path])
    )
    return FilesystemComparison(
        unchanged=not added and not removed and not modified,
        before_capture_id=str(before["capture_id"]),
        after_capture_id=str(after["capture_id"]),
        added=added,
        removed=removed,
        modified=modified,
    )


def _ordered_output_records(bundle: Mapping[str, Any]) -> tuple[list[str], str]:
    records = bundle.get("output_records")
    if not isinstance(records, list) or not records:
        raise ValidationError("output_records must be a non-empty list")
    seen_ids: set[str] = set()
    ordered: list[tuple[int, str, str]] = []
    for index, record in enumerate(records):
        if not isinstance(record, Mapping):
            raise ValidationError(f"output_records[{index}] must be an object")
        output_id = _require_nonempty_string(record.get("output_id"), f"output_records[{index}].output_id")
        if output_id in seen_ids:
            raise ValidationError("output_records must preserve distinct output IDs")
        seen_ids.add(output_id)
        sequence = record.get("sequence")
        if not isinstance(sequence, int) or sequence < 0:
            raise ValidationError(f"output_records[{index}].sequence must be a non-negative integer")
        channel = record.get("channel")
        if channel not in ("stdout", "stderr"):
            raise ValidationError(f"output_records[{index}].channel must be stdout or stderr")
        text = record.get("text")
        if not isinstance(text, str):
            raise ValidationError(f"output_records[{index}].text must be a string")
        ordered.append((sequence, output_id, text))
    ordered.sort(key=lambda item: item[0])
    if len({item[0] for item in ordered}) != len(ordered):
        raise ValidationError("output_records must preserve distinct sequence numbers")
    return [item[1] for item in ordered], "".join(item[2] for item in ordered)


def _validate_identifiers(bundle: Mapping[str, Any], output_ids: Sequence[str]) -> None:
    identifiers = bundle.get("identifiers")
    if not isinstance(identifiers, Mapping):
        raise ValidationError("identifiers must be an object")
    callback_id = _require_nonempty_string(identifiers.get("callback_id"), "identifiers.callback_id")
    _require_nonempty_string(identifiers.get("task_id"), "identifiers.task_id")
    preserved_output_ids = identifiers.get("output_ids")
    if preserved_output_ids != list(output_ids):
        raise ValidationError("identifiers.output_ids must preserve output record IDs in sequence order")
    task = bundle.get("task")
    if not isinstance(task, Mapping):
        raise ValidationError("task must be an object")
    validate_task_descriptor(task)
    mythic = task.get("mythic")
    if not isinstance(mythic, Mapping) or mythic.get("callback_id") != callback_id:
        raise ValidationError("task callback_id must match preserved identifiers")


def _validate_repeatability(bundle: Mapping[str, Any]) -> None:
    repeatability = bundle.get("repeatability")
    if not isinstance(repeatability, Mapping):
        raise ValidationError("repeatability must be an object")
    snapshot = repeatability.get("snapshot")
    revert = repeatability.get("revert")
    attempts = repeatability.get("attempts")
    if not isinstance(snapshot, Mapping) or not isinstance(revert, Mapping):
        raise ValidationError("repeatability must include snapshot and revert records")
    snapshot_name = _require_nonempty_string(snapshot.get("snapshot_name"), "repeatability.snapshot.snapshot_name")
    snapshot_record_id = _require_nonempty_string(snapshot.get("record_id"), "repeatability.snapshot.record_id")
    _require_nonempty_string(snapshot.get("created_at"), "repeatability.snapshot.created_at")
    if revert.get("snapshot_name") != snapshot_name:
        raise ValidationError("repeatability revert must reference the captured snapshot")
    revert_record_id = _require_nonempty_string(revert.get("record_id"), "repeatability.revert.record_id")
    if revert_record_id == snapshot_record_id:
        raise ValidationError("repeatability snapshot and revert records must be distinct")
    _require_nonempty_string(revert.get("post_revert_checks_record_id"), "repeatability.revert.post_revert_checks_record_id")
    if not isinstance(attempts, list) or len(attempts) < 2:
        raise ValidationError("repeatability must preserve at least two vulnerable baseline attempts")
    vulnerable_attempts = 0
    attempt_ids: set[str] = set()
    for index, attempt in enumerate(attempts):
        if not isinstance(attempt, Mapping):
            raise ValidationError(f"repeatability.attempts[{index}] must be an object")
        attempt_id = _require_nonempty_string(attempt.get("attempt_id"), f"repeatability.attempts[{index}].attempt_id")
        if attempt_id in attempt_ids:
            raise ValidationError("repeatability attempts must preserve distinct attempt IDs")
        attempt_ids.add(attempt_id)
        if attempt.get("scenario") == "vulnerable" and attempt.get("classification") == "vulnerable_issuance":
            vulnerable_attempts += 1
    if vulnerable_attempts < 2:
        raise ValidationError("repeatability must preserve two vulnerable_issuance attempts")


def _validate_cleanup(bundle: Mapping[str, Any]) -> None:
    cleanup = bundle.get("cleanup")
    if not isinstance(cleanup, Mapping):
        raise ValidationError("cleanup must be an object")
    records = cleanup.get("records")
    if not isinstance(records, list) or not records:
        raise ValidationError("cleanup.records must be a non-empty list")
    action_record_ids: dict[str, str] = {}
    record_ids: set[str] = set()
    for index, record in enumerate(records):
        if not isinstance(record, Mapping):
            raise ValidationError(f"cleanup.records[{index}] must be an object")
        record_id = _require_nonempty_string(record.get("record_id"), f"cleanup.records[{index}].record_id")
        if record_id in record_ids:
            raise ValidationError("cleanup.records must preserve distinct record IDs")
        record_ids.add(record_id)
        action = _require_nonempty_string(record.get("action"), f"cleanup.records[{index}].action")
        if action in action_record_ids:
            raise ValidationError("cleanup.records must preserve distinct actions")
        status = _require_nonempty_string(record.get("status"), f"cleanup.records[{index}].status")
        if status not in ("recorded", "verified"):
            raise ValidationError(f"cleanup.records[{index}].status must be recorded or verified")
        action_record_ids[action] = record_id
    if "revert_ca_snapshot" not in action_record_ids or "verify_rollback_baseline" not in action_record_ids:
        raise ValidationError("cleanup must preserve revert and rollback verification records")
    rollback = cleanup.get("rollback")
    if not isinstance(rollback, Mapping):
        raise ValidationError("cleanup.rollback must be an object")
    revert_record_id = _require_nonempty_string(rollback.get("revert_record_id"), "cleanup.rollback.revert_record_id")
    post_rollback_checks_record_id = _require_nonempty_string(
        rollback.get("post_rollback_checks_record_id"),
        "cleanup.rollback.post_rollback_checks_record_id",
    )
    if revert_record_id != action_record_ids["revert_ca_snapshot"]:
        raise ValidationError("cleanup.rollback.revert_record_id must reference revert_ca_snapshot")
    if post_rollback_checks_record_id != action_record_ids["verify_rollback_baseline"]:
        raise ValidationError(
            "cleanup.rollback.post_rollback_checks_record_id must reference verify_rollback_baseline"
        )
    if rollback.get("final_state") != "vulnerable_baseline":
        raise ValidationError("cleanup.rollback.final_state must be vulnerable_baseline")


def _require_observation(observations: Mapping[str, Any], key: str, expected: Any) -> None:
    if observations.get(key) != expected:
        raise ValidationError(f"observations.{key} must be {expected!r}")


def validate_evidence_bundle(bundle: Mapping[str, Any]) -> EvidenceAssessment:
    parsed = ParsedOutput("invalid", None, None, None, None, ("evidence was not parsed",))
    filesystem: FilesystemComparison | None = None
    reasons: list[str] = []
    try:
        if bundle.get("schema_version") != EVIDENCE_SCHEMA_VERSION:
            raise ValidationError("evidence schema_version is not supported")
        if bundle.get("evidence_mode") not in ("offline_fixture", "operator_collected"):
            raise ValidationError("evidence_mode must be offline_fixture or operator_collected")
        scenario = bundle.get("scenario")
        if scenario not in ("vulnerable", "patched_negative_control"):
            raise ValidationError("scenario must be vulnerable or patched_negative_control")
        output_ids, output_text = _ordered_output_records(bundle)
        _validate_identifiers(bundle, output_ids)
        parsed = parse_bof_output(output_text)
        if parsed.kind == "invalid":
            raise ValidationError("; ".join(parsed.errors))
        victim_filesystem = bundle.get("victim_filesystem")
        if not isinstance(victim_filesystem, Mapping):
            raise ValidationError("victim_filesystem must be an object")
        filesystem = compare_filesystem_snapshots(
            victim_filesystem.get("before", {}),
            victim_filesystem.get("after", {}),
        )
        if not filesystem.unchanged:
            raise ValidationError("victim filesystem before/after evidence is not unchanged")
        _validate_repeatability(bundle)
        _validate_cleanup(bundle)
        observations = bundle.get("observations")
        if not isinstance(observations, Mapping):
            raise ValidationError("observations must be an object")
        if scenario == "vulnerable":
            if parsed.kind != "issued" or parsed.disposition != 3 or parsed.certificate_der is None:
                raise ValidationError("vulnerable evidence must preserve an issued certificate result")
            _require_observation(observations, "ca_callback_445", True)
            _require_observation(observations, "ca_callback_389", True)
            _require_observation(observations, "certificate_identity_matches_target", True)
            _require_observation(observations, "certificate_sid_matches_target", True)
            _require_observation(observations, "target_certificate_absent", False)
            return EvidenceAssessment("vulnerable_issuance", True, (), parsed, filesystem)
        if parsed.kind != "non_issued" or parsed.disposition == 3:
            raise ValidationError("patched negative control must preserve a non-issued result")
        _require_observation(observations, "ca_callback_445", False)
        _require_observation(observations, "ca_callback_389", False)
        _require_observation(observations, "certificate_identity_matches_target", False)
        _require_observation(observations, "certificate_sid_matches_target", False)
        _require_observation(observations, "target_certificate_absent", True)
        _require_nonempty_string(observations.get("patched_build_record_id"), "observations.patched_build_record_id")
        _require_nonempty_string(observations.get("patch_kb_record_id"), "observations.patch_kb_record_id")
        return EvidenceAssessment("patched_negative_control", True, (), parsed, filesystem)
    except ValidationError as exc:
        reasons.append(str(exc))
    return EvidenceAssessment("invalid_incomplete_evidence", False, tuple(reasons), parsed, filesystem)


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValidationError(f"file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValidationError(f"invalid JSON in {path}: {exc}") from exc


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _describe_task(args: argparse.Namespace) -> int:
    try:
        csr_der = Path(args.csr_der).read_bytes()
        coff_bytes = Path(args.coff_object).read_bytes()
        inputs = CertighostInputs.from_text(
            csr_der=csr_der,
            ca_config=args.ca_config,
            template=args.template,
            san_dns=args.san_dns,
            cdc=args.cdc,
            rmd=args.rmd,
        )
        descriptor = build_task_descriptor(
            inputs=inputs,
            callback_id=args.callback_id,
            agent_version=args.agent_version,
            coff_name=args.coff_name or Path(args.coff_object).name,
            coff_sha256=_sha256(coff_bytes),
            timeout_seconds=args.timeout,
        )
        validate_task_descriptor(descriptor)
    except (OSError, ValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.output is not None:
        _write_json(Path(args.output), descriptor)
    print(json.dumps(descriptor, indent=2, sort_keys=True))
    return 0


def _validate_evidence(args: argparse.Namespace) -> int:
    try:
        bundle = _load_json(Path(args.bundle))
        if not isinstance(bundle, Mapping):
            raise ValidationError("evidence bundle must be a JSON object")
        assessment = validate_evidence_bundle(bundle)
    except ValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(assessment.to_dict(), indent=2, sort_keys=True))
    return 0 if assessment.valid else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    describe = subparsers.add_parser(
        "describe-task",
        help="emit a describe-only Apollo execute_coff v3 task descriptor",
    )
    describe.add_argument("--callback-id", required=True)
    describe.add_argument("--agent-version", required=True)
    describe.add_argument("--coff-object", required=True)
    describe.add_argument("--coff-name")
    describe.add_argument("--csr-der", required=True)
    describe.add_argument("--ca-config", required=True)
    describe.add_argument("--template", required=True)
    describe.add_argument("--san-dns", default="")
    describe.add_argument("--cdc", required=True)
    describe.add_argument("--rmd", required=True)
    describe.add_argument("--timeout", type=int, default=30)
    describe.add_argument("--output")
    describe.set_defaults(func=_describe_task)

    validate = subparsers.add_parser(
        "validate-evidence",
        help="validate an offline or operator-collected evidence bundle",
    )
    validate.add_argument("bundle")
    validate.set_defaults(func=_validate_evidence)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
