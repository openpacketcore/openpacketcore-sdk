# N3IWF fixture contracts

`opc-n3iwf-fixtures` publishes ten independently consumable synthetic fixture
inventories. See its [README](../crates/opc-n3iwf-fixtures/README.md) and
[conformance boundary](../crates/opc-n3iwf-fixtures/CONFORMANCE.md).
The [SDK work order](n3iwf-work-order.md) maps these prerequisites to the
implementation queue and existing public work.

## Layout and interpretation

```
crates/opc-n3iwf-fixtures/
  oracles/ngap-rel18.json
  oracles/ngap-rel18-messages.json
  oracles/ike-auth-sha256.json
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
clause 9.4.4 for TS 38.413 V18.10.0. It records each IE's identifier,
criticality, singleton cardinality, and mandatory/optional/conditional
presence. These rows were extracted from that release, independently of the
SDK's current policy tables, which also admit later extensions.

The legacy libngap NGSetupRequest is a **sanitized structural derivative**.
Its original source digest and exact transforms are recorded in the manifest
and verified against the complete upstream literal. Test PLMN 001/01 replaces
operator PLMNs, the RAN name becomes synthetic, and outer procedure criticality
is corrected to reject. This is not independent Release-18 N3IWF message
conformance evidence.

`oracles/ngap-rel18-messages.json` adds complete messages for all 15 admitted
outcomes, independently encoded with Pycrate 0.8.1. The reference gate extracts
and compiles all six ASN.1 modules from the exact PDF. Counted layout repairs
restore wrapped comments and split identifiers; six SHA-256 hashes verify the
resulting complete schema. No SDK source or encoder supplies reference bytes.
The checked-in recipes use explicit `hex`, `bits`/`length`, and `type`/`value`
notation for ASN.1 octets, bit strings, choices and open types.

The 52 cases include complete N3IWF node/location information, IPv4 and IPv6,
nested session setup/release transfers, partial resource results, absent
mandatory/conditional fields, duplicates, unknown criticality, reordered IEs,
malformed nested transfers and caller bounds. Independent mutation tests
remove every mandatory IE, duplicate every present IE, change each criticality
and truncate every prefix of the 15 base messages. Re-encoded mutations bypass
the digest check and must still fail semantic validation. The report records
source/tool hashes and actual case counts; hosted CI archives it.

The reviewed QoS profile is standardized non-GBR 5QI 9. Its session setup
transfer must include Session AMBR (TS 38.413 clause 8.2.1.4); an initial
context request carrying session resources also requires UE AMBR (clause
9.2.2.1). Separate negative cases omit each conditional field, omit the nested
tunnel, or duplicate a QFI. Other QoS profiles need their own reviewed
conditional evidence. A reference rejection means the message cannot be
admitted as a successful corpus case; it does not execute the network's
failure procedure.

The SDK test compares each decoded IE's identifier, criticality and opaque
value bytes with the independent encoder's results. It also verifies all
procedure/outcome variants and raw-preserving output. Each manifest records
`sdk_structural_outcome` separately: absence of a mandatory field or a malformed
nested transfer can still pass the SDK's structural decoder. This is an
explicit runtime gap tracked by #787. The corpus exposed and fixed the SDK's
acceptance of incorrect procedure criticality.

NAS remains opaque; the mandatory SecurityKey field uses an all-zero synthetic
placeholder. Neither establishes a NAS procedure, key derivation, authentication
or a complete AMF exchange. Canonical SDK encoding and full clause 5.3 content
handling remain unsupported. Paging is inapplicable under clause 5.4.
Issue 784 continues tracking evidence beyond these boundaries.

### Running the independent NGAP gate

Use an isolated environment with the hash-pinned tools:

```bash
python3 -m venv /tmp/ngap-reference
/tmp/ngap-reference/bin/pip install --require-hashes --only-binary=:all: \
  -r scripts/n3iwf-ngap-reference-requirements.txt
/tmp/ngap-reference/bin/python scripts/check-n3iwf-ngap-reference.py \
  --report /tmp/ngap-reference-report.json
```

The command downloads only the pinned public specification over HTTPS. Supply
`--spec /path/to/ts_138413v181000p.pdf` to use a local copy; its digest must
match. The gate never updates fixtures, weakens compiler constraints or imports
the manifest writer. Pycrate (LGPL-2.1-or-later) and pypdf (BSD-3-Clause) are
external test tools; no tool code or generated reference schema is linked into
or distributed with the SDK. The SDK gains no runtime dependency.

To author a new reference case, edit the explicit recipe, independently encode
its complete PDU and each IE value using `Reference.encode` and
`Reference.encoded_fields`, and record the resulting hex and SHA-256. Review
the semantic expectation against the pinned standards before publishing it.
`generate-n3iwf-fixtures.py --write` publishes these recorded results; it does
not encode NGAP. Run the independent gate as well as the catalog gate before
committing the content and publication stamp.

## Protocol-key cryptographic evidence

`oracles/ike-auth-sha256.json` records independent answers for the existing
RFC 7296 IKE key schedule and final shared-key AUTH calculation in both
directions. The declared profile is PRF-HMAC-SHA256, AES-GCM-16 with a 256-bit
key, and ECP-256. Every derived key is compared, including the four-byte GCM
salts and empty separate integrity keys. Complete synthetic SA_INIT messages
are independently assembled and decoded through the SDK's existing codec.

The source uses public test scalars 1 and 2, fixed incrementing test nonces,
synthetic SPIs, an initiator ID_KEY_ID as required by TS 33.501 clause 7.2.1,
and the reserved responder name `n3iwf.example`. OpenSSL independently
reproduces both public points and both directions of agreement. Python's
standard-library HMAC-SHA256 and the RFC 7296 PRF+ equations reproduce every
answer; RFC 4231 section 4.2 checks the HMAC primitive itself. The fixture
writer publishes recorded answers without importing either implementation.

The all-zero 256-bit SecurityKey from the complete NGAP Initial Context Setup
Request supplies the synthetic K_N3IWF input. The SDK test decodes that message
and passes the placeholder to its existing AUTH calculation. This proves the
octet-level connection for this vector. It does not implement typed key
import, consume-once custody, operation/generation binding, or K_AMF derivation.
Legacy wrong-generation, reuse, cancellation and drop cases remain reference
state models pending #791's implementation and zeroization evidence.

Thirty published cases cover positive AUTH, altered MIC/key/transcript/SPI/
nonce/identity/direction/DH input, empty key, short data and unsupported method.
Changed reserved ID bytes invalidate AUTH because the exact ID body is signed.
Changed reserved AUTH bytes remain receivable under RFC 7296. Both the
independent gate and SDK additionally reject 1,549 bit/octet/prefix mutations,
without using a digest comparison to decide authentication.

```bash
python3 scripts/n3iwf_key_reference.py --report /tmp/ike-auth-reference-report.json
cargo test --locked -p opc-n3iwf-fixtures --test protocol_key_known_answers
```

The reference needs Python's standard library and OpenSSL 3; it uses no network
or live peer. Hosted CI archives its report. AUTH bodies and SA_INIT inputs do
not prove certificate validation, EAP success, a protected IKE_AUTH exchange,
SCTP/DTLS interoperability or kernel installation. These remain in #784.

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

Round trips alone do not prove external interoperability. The independent
known answers prove only the declared cryptographic calculations. These gates
do not prove live dataplane, authenticated transport or kernel state.
