# N3IWF fixture contracts

Synthetic wire and transport contracts for N3IWF primitives. Owned by
`opc-n3iwf-fixtures`. This is fixture and conformance evidence only.

These contracts do not activate a codec, adapter, key handle, or transport
runtime. `runtime_claim` is false.

## Why a dedicated crate

Several N3IWF primitives (NWu GRE, NAS-over-TCP, protocol-key KATs, XFRM
roster, N2 DTLS metadata) have no owning codec crate yet. ADR 0015 still
requires spec-authored bytes, provenance, and honest unsupported outcomes
before a later codec lands. Independent subset completion records let
consumers depend on one primitive without waiting for the remaining nine.

## Public SDK publication

`crates/opc-n3iwf-fixtures/fixtures/PUBLIC_SDK.json` publishes:

- repository URL
- public SDK base commit used as the reuse floor
- landing head commit
- fixtures tree path and tree object
- constructed / receive / unsupported outcomes on each subset completion record
- provenance class and SHA-256 wire digest on every manifest

Round trips of these bytes do not prove external interoperability.

## Subset layout

```
crates/opc-n3iwf-fixtures/fixtures/
  PUBLIC_SDK.json
  <subset>/
    COMPLETION.json
    README.md
    <case>.json
    wire/<case>.hex
```

Each manifest carries a stable `opc.n3iwf.<subset>.v1.<name>` identifier,
source release and clauses, direction and role, prerequisite, provenance,
sanitized-field inventory, wire digest, semantic assertions, expected
outcome, and `runtime_claim=false`.

## Required case classes

Every subset publishes at least one fixture in each class:

- positive
- malformed
- duplicate
- unknown-critical
- ordering
- truncation
- bounded-overflow

## Semantic distinctions the catalog locks

- EAP-5G spare AN-parameters are ignored; duplicate selected-PLMN is a caller
  duplicate-singleton policy, not the spare-parameter ignore rule.
- NAS-over-TCP partial prefixes remain `need-more-data` until a complete
  frame, EOF/loss, or bounded finalization.
- NGAP reuses the issue 493 Release 18 DecodeContext vector. Canonical typed
  encode remains unsupported.
- NWu GRE received nonzero Protocol Type is ignored.
- N3 GTP-U downlink PSC is type 0; uplink PSC is type 1 QFI-only. Received
  Recovery is ignored and canonicalized to zero.
- IKE notify wire and XFRM backend roster are separate subsets.
- Protocol-key fixtures are labels only. No key, MSK, or K_N3IWF bytes.
- N2 DTLS requires PPID 66. Ordinary PPID 60 associations cannot satisfy that
  subset. Errors are redacted labels.

## Gates

- Crate: `cargo test -p opc-n3iwf-fixtures` loads the catalog, asserts
  subset completion, and proves fix-removal plus adversarial mutation fail
  the detector.
- Repository: `scripts/check-n3iwf-fixture-contracts.py` is invoked from
  rust-gates.

## Regeneration

```bash
python3 scripts/generate-n3iwf-fixtures.py --write
python3 scripts/check-n3iwf-fixture-contracts.py --self-test
```

The generator is the deterministic writer. It never copies production
captures or key material.
