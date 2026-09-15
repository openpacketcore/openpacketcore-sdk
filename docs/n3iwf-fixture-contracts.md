# N3IWF fixture contracts

`opc-n3iwf-fixtures` publishes ten independently consumable synthetic fixture
inventories. See its [README](../crates/opc-n3iwf-fixtures/README.md) and
[conformance boundary](../crates/opc-n3iwf-fixtures/CONFORMANCE.md).

## Layout and interpretation

```
crates/opc-n3iwf-fixtures/
  oracles/ngap-rel18.json
  fixtures/
    PUBLIC_SDK.json
    <subset>/
      COMPLETION.json
      README.md
      <case>.json
      wire/<case>.hex
```

Every manifest records a stable ID, pinned source, provenance, sanitized-field
inventory, byte digest, assertions, expected outcome, and `runtime_claim=false`.
`encoding` distinguishes protocol bytes from metadata, construction arguments,
and scenario records. `validation_scope` defines what acceptance proves.
`context` contains explicit caller bounds and preconditions; those values are
not necessarily protocol constants. Completion covers that declared inventory.

Required case classes describe envelope errors or scenario conditions as
appropriate. For example, an unknown key purpose is a local scenario, not an
unknown critical network IE. No wire encoding is attempted for QFI input 64.

## Important boundaries

- EAP spare AN parameters are ignored; duplicate singleton handling is a
  separate caller policy. NAS contents remain opaque.
- Partial NAS-over-TCP input stays `need-more-data` while the stream is open.
  EOF of an incomplete frame rejects. The example bound of 256 is inclusive.
- IKE examples contain generic payload headers, not complete authenticated
  IKE exchanges. Chained payloads must name the next payload correctly.
- GRE nonzero Protocol Type is ignored as a field. The packet and opaque
  payload remain receivable, including payload bytes resembling a GRE header.
- GTP-U receive Recovery canonicalizes to zero. End Marker extension chains
  and direction-specific PSCs are tested through existing SDK codecs.
- SCTP DATA has nonempty user data and excludes padding from its length.
  B/E flags describe fragmentation; reliable delivery is a separate policy.
- DTLS ServerHelloDone is an isolated record. Identity verification,
  64-octet exporter output, key switching before Finished, and retiring old
  keys after acknowledgment are caller obligations, not established sessions.
- SPI records use a documented synthetic encoding, not Linux netlink wire.
  Reusing an inbound SPI in one receiver namespace differs from equal numeric
  inbound/outbound SPIs in opposite receiver namespaces.

## NGAP evidence

`oracles/ngap-rel18.json` pins the ETSI PDF URL, document SHA-256, and ASN.1
clause 9.4.3 for TS 38.413 V18.10.0. It records each IE's identifier,
criticality, singleton cardinality, and mandatory/optional/conditional
presence. These rows were extracted from that release, independently of the
SDK's current policy tables, which also admit later extensions.

The legacy libngap NGSetupRequest is a **sanitized structural derivative**.
Its original source digest and exact transforms are recorded in the manifest
and verified against the complete upstream literal. Test PLMN 001/01 replaces
operator PLMNs, the RAN name becomes synthetic, and outer procedure criticality
is corrected to reject. This is not independent Release-18 N3IWF message
conformance evidence.

Empty IE wrappers exercise dispatch only. Mandatory presence, inner IE values,
TS 29.413 clause 5.3 content exceptions, complete N3IWF messages, and canonical
typed encoding remain unproven/unsupported. Paging is unsupported by the
N3IWF application under clause 5.4 even though its APER wrapper can be parsed.
Issue 784 remains the tracker for evidence beyond these published boundaries.

## Maintenance and publication

Both `--check` and `--self-test` generate into temporary directories. They
reject changed, missing, extra, or symlinked files without repairing the input.
Only explicit `--write` changes fixtures.

```bash
python3 scripts/generate-n3iwf-fixtures.py --write
python3 scripts/test-n3iwf-fixture-contracts.py
python3 scripts/n3iwf_fixture_oracles.py
cargo test --locked -p opc-n3iwf-fixtures
```

Commit the reviewed content first. On that clean commit:

```bash
python3 scripts/generate-n3iwf-fixtures.py --stamp-git
python3 scripts/check-n3iwf-fixture-contracts.py --self-test
```

Commit the resulting publication stamp separately. `PUBLIC_SDK.json` names
an actual ancestor content commit and its fixtures tree; it cannot name its
own commit without creating a self-reference. The gate verifies base/head
ancestry, tree identity, and every current fixture blob against that commit,
excluding only the root publication stamp. Any later fixture change requires
a new content commit and stamp. Preserve the content commit when merging;
squashing/rebasing requires restamping before the final gate.

Round trips alone do not prove external interoperability. These gates do not
prove live dataplane, authenticated transport, cryptography, or kernel state.
