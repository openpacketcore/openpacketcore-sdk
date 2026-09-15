# N3IWF fixture contracts

Synthetic wire and transport contracts for N3IWF primitives. Owned by
`opc-n3iwf-fixtures`. This is fixture and conformance evidence only.

These contracts do not activate a codec, adapter, key handle, or transport
runtime. `runtime_claim` is false.

Scope is reusable SDK contracts only. They do not encode application policy,
subscriber authentication decisions, AMF selection, deployment topology,
readiness, or product claims. Tracking issue 795 is tracking-only and is not
implemented here.

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

- EAP-5G spare AN-parameters and AN-parameter reordering are permitted on
  receive. Duplicate selected-PLMN is a caller duplicate-singleton policy,
  not the spare-parameter ignore rule. Notification is Message-Id 3; Stop is
  Message-Id 4.
- NAS-over-TCP partial prefixes remain `need-more-data` while the stream is
  open. EOF/loss of an incomplete frame or bounded-length overflow finalizes
  as reject.
- NGAP reuses the issue 493 Rel-18 DecodeContext vector (TS 38.413 V18.10.0).
  TS 29.413 V18.5.0 5.2–5.4 decide admission for the issue 493 first-CNF
  typed subset. Every admitted first-CNF sent/received outcome publishes an
  IE cardinality/criticality matrix. Paging is 5.4 unsupported. Clause 5.3
  RAN-specific ignore is documented, not encoded. Canonical typed encode
  remains unsupported. 5.2 messages outside that typed subset stay
  unpublished.
- NWu GRE received nonzero Protocol Type is ignored.
- N3 GTP-U downlink PSC is type 0; uplink PSC is type 1 QFI-only. Received
  Recovery is ignored and canonicalized to zero.
- IKE wire notifies/create/modify/delete/mobility stay in `nwu-ike`. Backend
  overlap, SPI provenance, rekey, and roster relocation stay in `xfrm-roster`.
- Protocol-key fixtures are synthetic known-answer labels only. Wrong
  generation, reuse, drop, and cancellation are published. No key, MSK, or
  K_N3IWF bytes.
- N2 DTLS requires handshake/identity labels, PPID 66, SCTP-AUTH, reliable
  DATA B/E delivery, rekey/rotation, and restart/path-failure labels.
  Ordinary PPID 60 associations cannot satisfy that subset. Errors are
  bounded redacted labels.

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
