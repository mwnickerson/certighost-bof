# Certighost BOF

*This BOF was researched, developed, and tested using a Large Language Model and Hermes Agent*

This repository contains a minimal Windows x64 Beacon Object File for the enrollment-only portion of the Certighost / CVE-2026-54121 lab chain. The BOF submits a caller-supplied in-memory PKCS#10 request through `ICertRequest::Submit` with `CR_IN_BINARY | CR_IN_PKCS10 | CR_IN_RPC`, then returns the disposition, request ID, and issued certificate bytes as base64 text over Beacon output.

Run: `certighost-bof-20260727T143312Z`

This is REDANTONETTA lab-only work. No push, publication, deployment, or live target execution is authorized.

## Scope

The BOF implements only the AD CS enrollment chase trigger. It does not create machine accounts, host rogue SMB/LSA or LDAP callback services, generate a CSR, perform PKINIT, write PFX/ccache files, recover hashes, spawn a process, or write any target-side file. The CSR, request attributes, returned certificate, and transient BSTR/base64 buffers stay in memory; allocated buffers are cleared before release where practical.

The rogue SMB/LDAP callback services described in [the research notes](docs/research/CVE-2026-54121.md) are external in-memory lab prerequisites. PKINIT and any post-certificate action are also external prerequisites and are intentionally not implemented here.

## Argument Schema

The `go` entrypoint expects the standard Beacon `bof_pack` frame: one little-endian `u32` payload length followed by six little-endian length-prefixed binary fields. Apollo `execute_coff` v3 passes that frame intact:

```sleep
$args = bof_pack($bid, "bbbbbb",
    $csr_der,
    $ca_config,
    $template,
    $san_dns,
    $cdc,
    $rmd);
```

Fields are ordered as follows:

| Field | Meaning | Validation |
| --- | --- | --- |
| `csr_der` | DER PKCS#10 request bytes | Non-empty, at most 256 KiB, bounded outer DER `SEQUENCE` |
| `ca_config` | CA configuration string such as `ca01.lab.local\LAB-CA` | ASCII `host\CAName`, at most 512 bytes |
| `template` | Certificate template value | Printable ASCII without `:`/newlines, at most 128 bytes |
| `san_dns` | DNS SAN value without the `dns=` prefix | Optional empty field, otherwise DNS/IP-like ASCII, at most 255 bytes |
| `cdc` | Chase callback host/IP value | Required DNS/IP-like ASCII, at most 255 bytes |
| `rmd` | Remote-domain/principal lookup DNS value | Required DNS/IP-like ASCII, at most 255 bytes |

The portable parser validates the canonical outer payload length, the six inner field length prefixes, exact field count, and trailing data before the BOF passes the intact frame to `BeaconDataParse`/`BeaconDataExtract`. The BOF constructs this exact attribute string in memory:

```text
CertificateTemplate:<template>
SAN:dns=<san_dns>
cdc:<cdc>
rmd:<rmd>
```

The `SAN:dns=` line is omitted only when `san_dns` is empty.

## Output

On issuance, the BOF emits a text header and a base64-framed DER certificate:

```text
CERTIGHOST_RESULT disposition=3 request_id=<id> cert_encoding=base64 cert_der_bytes=<n> cert_base64_chars=<n>CERTIGHOST_CERT_BEGIN
<base64 DER certificate>
CERTIGHOST_CERT_END
```

Apollo aggregates the issued `BeaconPrintf` header directly with the next `BeaconOutput` marker, so the canonical exported text has no newline between `cert_base64_chars=<n>` and `CERTIGHOST_CERT_BEGIN`. No output field is a filesystem path. For a denied, pending, or failed submission, the BOF emits the disposition, request ID when available, last status HRESULT when available, and a sanitized CA disposition message. Input validation failures occur before COM enrollment is attempted.

## Prerequisites

Operational use requires all of the following outside this BOF:

- A vulnerable Enterprise CA and an enrollable template that reaches the chase path.
- A Beacon security context that already has enrollment rights for the selected template.
- A caller-generated in-memory PKCS#10 request matching the intended requester identity and SAN.
- A reachable lab-only rogue SMB/LSA plus LDAP callback service for the supplied `cdc` value.
- Any later PKINIT handling, certificate inspection, or post-certificate validation performed separately in memory.

## Build And Test

```sh
make test
make bof
make lint
make imports
git diff --check
```

`make bof` prefers `x86_64-w64-mingw32-gcc` when present. In this worktree it falls back to the installed LLVM clang cross-target path and emits `build/certighost.x64.o` as `coff-x86-64`. `make test` builds and runs the macOS host harness plus the offline Mythic packing, task-schema, output, filesystem-evidence, repeatability, and cleanup tests.

## Recovery

If the CA returns a non-issued disposition, retain the reported request ID and CA message as evidence and correct the lab prerequisite or request input before rerunning. The BOF does not retrieve pending requests later, persist certificates, or attempt any recovery action that changes target state.

## Research

- [CVE-2026-54121 / Certighost primary-source research](docs/research/CVE-2026-54121.md)

## Mythic Integration

- [Offline Apollo execute_coff v3 workflow and evidence validation](docs/mythic-integration.md)

## Lab Design

- [REDANTONETTA declarative lab runbook](docs/lab/CVE-2026-54121-redantonetta-runbook.md)
- [Ludus range config](ludus/ranges/redantonetta-certighost.yml)
- [Local Certighost lab role](ludus/roles/certighost_lab)
