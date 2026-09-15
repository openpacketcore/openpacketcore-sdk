# opc-n3iwf-fixtures

SDK-owned synthetic N3IWF wire and transport fixture contracts.

This crate publishes independently reviewable manifests for the ten N3IWF
primitive subsets tracked by issue 784. It owns fixture metadata, SHA-256
digests, subset completion records, and catalog detectors only. It does not
activate a codec, adapter, key handle, transport, or dataplane runtime.

`runtime_claim` is false on every manifest and completion record.

## Subsets

Each subset is independently complete. Consumers may depend on one record
without waiting for the remaining subsets.

| Subset | Contract |
| --- | --- |
| `eap5g` | TS 24.502 EAP-5G envelopes; spare AN-parameters ignored; duplicate selected-PLMN is caller policy |
| `nwu-ike` | TS 24.502 / RFC 7296 notify and Delete wire; XFRM roster is out of scope |
| `ngap` | Release 18 NGSetupRequest reuse of the issue 493 DecodeContext vector; constructed typed encode unsupported |
| `n2-sctp` | TS 38.412 PPID 60 / port 38412; PPID 66 belongs to `n2-dtls` |
| `gre-qfi` | NWu GRE C=0 K=1 S=0; received nonzero Protocol Type ignored |
| `n3-gtpu` | Reuses issue 341 Echo/Recovery/PSC vectors by digest; uplink and downlink PSC are distinct |
| `protocol-key` | Synthetic KAT labels only; no key material |
| `nas-tcp` | Two-octet length plus opaque NAS; partial reads stay need-more-data |
| `xfrm-roster` | Backend roster labels; IKE notify parsing is out of scope |
| `n2-dtls` | RFC 6083 PPID 66, handshake/identity labels, SCTP-AUTH length, rekey, restart, redacted errors |

Issue 644 checksum-offload behavior is dataplane runtime and is not duplicated.

## Manifest fields

Every JSON manifest includes a stable SDK fixture ID, source release and
clauses, direction and role, prerequisite, provenance, sanitized-field
inventory, wire digest, semantic assertions, expected outcome, and
`runtime_claim=false`.

## Verification

```bash
python3 scripts/generate-n3iwf-fixtures.py --self-test
python3 scripts/check-n3iwf-fixture-contracts.py --check
cargo test -p opc-n3iwf-fixtures
```

See [CONFORMANCE.md](CONFORMANCE.md) and
[docs/n3iwf-fixture-contracts.md](../../docs/n3iwf-fixture-contracts.md).
