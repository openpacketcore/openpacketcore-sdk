# opc-n3iwf-fixtures

SDK-owned synthetic N3IWF wire and transport fixture contracts.

This crate publishes independently reviewable manifests for the ten N3IWF
primitive subsets tracked by issue 784. It owns fixture metadata, SHA-256
digests, subset completion records, and catalog detectors only. It does not
activate a codec, adapter, key handle, transport, or dataplane runtime.

`runtime_claim` is false on every manifest and completion record.

This crate publishes reusable SDK contracts only. It does not encode
application policy, subscriber authentication decisions, AMF selection,
deployment topology, readiness, or product claims. Tracking issue 795 is
tracking-only and is not implemented here.

## Subsets

Each subset is independently complete. Consumers may depend on one record
without waiting for the remaining subsets.

| Subset | Contract |
| --- | --- |
| `eap5g` | TS 24.502 V18.8.0 EAP-5G Start/NAS/Notification/Stop; spare ignore ≠ caller duplicate-singleton |
| `nwu-ike` | TS 24.502 7.5/7.6 create/modify plus notify/Delete/MOBIKE wire; XFRM roster is out of scope |
| `ngap` | TS 38.413 V18.10.0 Rel-18 NGSetupRequest plus 29.413 5.2–5.4 IE matrices; constructed send unsupported |
| `n2-sctp` | TS 38.412 V18.1.0 clause 7 PPID 60 / port 38412; PPID 66 belongs to `n2-dtls` |
| `gre-qfi` | NWu GRE C=0 K=1 S=0; received nonzero Protocol Type ignored |
| `n3-gtpu` | Reuses issue 341 Echo/Recovery/PSC vectors; direction-specific PSC; Recovery zero/ignored |
| `protocol-key` | Synthetic KAT labels only; wrong-generation, reuse, drop, cancellation; no key material |
| `nas-tcp` | Two-octet length plus opaque NAS; need-more-data until EOF/loss or bounded finalization |
| `xfrm-roster` | Backend overlap, SPI provenance, rekey, relocation; IKE notify parsing is out of scope |
| `n2-dtls` | RFC 6083 PPID 66, handshake/identity, SCTP-AUTH, reliable DATA, rekey/rotation, restart, redacted errors |

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
