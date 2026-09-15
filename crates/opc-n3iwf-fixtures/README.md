# opc-n3iwf-fixtures

SDK-owned synthetic N3IWF fixture contracts. The crate validates bounded
catalog files, SHA-256 digests, provenance, inventories, and pinned NGAP IE
matrices. It activates no protocol, key, transport, or dataplane runtime.
Every manifest and completion record has `runtime_claim=false`.

## Published scope

`COMPLETION.json` means the inventory is complete **at the manifest's
`validation_scope`**. It does not establish protocol implementation, a valid
complete exchange, or external interoperability. Each subset can be loaded
independently with `FixtureCatalog::load_subset_from(root, subset)`.

| Subset | Evidence boundary |
| --- | --- |
| `eap5g` | EAP Expanded envelope, AN TLVs, opaque inner NAS |
| `nwu-ike` | Notify/Delete payload chains; create/modify labels identify intended use |
| `ngap` | Structural APER dispatch and exact TS 38.413 V18.10.0 IE matrices |
| `n2-sctp` | PPID 60/port 38412 metadata and a DATA chunk with opaque user data |
| `gre-qfi` | GRE header, QFI/RQI fields, opaque trailing payload, QFI constructor bound |
| `n3-gtpu` | Existing SDK GTP-U codecs: Echo, Recovery, PSC, End Marker |
| `protocol-key` | Synthetic labels and consume/cancel/drop reference state transitions |
| `nas-tcp` | Two-octet length, caller bounds, partial reads/EOF, opaque inner NAS |
| `xfrm-roster` | Synthetic SPI roster records and explicit provenance/relocation preconditions |
| `n2-dtls` | PPID 66, isolated DTLS record/DATA framing, lifecycle preconditions |

Key and transport scenario labels contain no key material. They are not
cryptographic known-answer tests. A reference state called `zeroized` is an
obligation for a future implementation; it does not prove memory erasure.

## Validation layers

Each manifest separates `encoding` (protocol wire, metadata, scenario, or
construction input), `validation_scope`, and `context` (caller bounds and
preconditions) from its outcome and semantic assertions.

`FixtureCatalog::load` validates before exposing bytes. Files must be regular,
bounded, and located at canonical subset paths. Unknown fields, duplicate JSON
keys, digest changes, duplicate IDs, incomplete inventories, and matrix drift
are errors. Debug output is redacted; errors contain constant codes. Content
screening is a bounded denylist, not a general detector of subscriber data.
Provenance and sanitized fields still require review. Load from a stable local
checkout; this API does not sandbox a concurrently hostile filesystem.

The repository gate adds read-only regeneration, independent envelope/scenario
oracles, existing SDK codec tests, and verification of Git publication history.
The Python reference oracles never import the fixture writer.

```bash
python3 scripts/check-n3iwf-fixture-contracts.py --self-test
cargo test --locked -p opc-n3iwf-fixtures
```

See [CONFORMANCE.md](CONFORMANCE.md) for limitations and
[fixture maintenance](../../docs/n3iwf-fixture-contracts.md) for regeneration
and publication. Product integration and issue 795 remain outside this crate.
