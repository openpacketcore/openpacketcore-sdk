# opc-n3iwf-fixtures conformance

## Claim

Synthetic fixture inventories, catalog validation, bounded envelope checks,
independently compiled complete NGAP messages, and local reference scenarios.
Independent synthetic IKE AUTH known answers exercise the existing SDK crypto.
`runtime_claim=false` throughout. The crate
has no runtime protocol dependencies; test-only dependencies exercise the
existing NGAP and GTP-U codecs and IKE crypto against the published bytes.

`complete` in a subset record means its declared fixture inventory is complete
at its `validation_scope`. It does not mean a N3IWF primitive is implemented
or that all acceptance evidence for issue 784 has been supplied.

## Specification baseline

| Document | Release | Evidence |
| --- | --- | --- |
| 3GPP TS 24.502 | V18.8.0 | EAP-5G, IKE payloads, GRE/QFI, NAS-over-TCP envelopes |
| 3GPP TS 29.413 | V18.5.0 | N3IWF application scope, clauses 5.2–5.4 |
| 3GPP TS 38.413 | V18.10.0 | Six independently compiled ASN.1 modules, complete messages, IE rows and nested transfers |
| 3GPP TS 38.412 | V18.1.0 | PPID 60/66 and port 38412, clause 7 |
| 3GPP TS 29.281 | V18.4.0 | GTP-U Echo, Recovery, extension chains |
| 3GPP TS 38.415 | V18.2.0 | Direction-specific PSC, clause 5.5.3 |
| 3GPP TS 33.501 | V18.12.0 | K_N3IWF purpose; no derivation evidence |
| IETF RFC 7296 / RFC 4555 | Published RFCs | IKE payloads, MOBIKE notification, independent IKE key schedule and AUTH answers |
| IETF RFC 4231 | Published RFC | SHA-256 HMAC primitive known answer, section 4.2 |
| IETF RFC 4960 | Published RFC | SCTP DATA framing |
| IETF RFC 6083 | Published RFC | Reliable delivery and AUTH/exporter lifecycle obligations, §4.8/§5 |
| IETF RFC 6347 / RFC 5246 | Published RFCs | DTLS 1.2 record and isolated ServerHelloDone |

## Provenance and reuse

Allowed provenance classes are `spec-authored`, `referenced-public-vector`,
`synthetic-negative`, and `synthetic-kat`. The last is a legacy schema name
for legacy scenario labels; only `ike-auth-known-answer` claims cryptographic evidence.
No subscriber captures or real key material are published. Complete NGAP
InitialContextSetupRequest vectors include the mandatory SecurityKey field
with an all-zero 256-bit placeholder. It is neither a peer key nor a key
derivation known answer. Documentation addresses, reserved test PLMN, and
synthetic identifiers are used.

The protocol-key corpus uses that same zero placeholder for both final AUTH
directions under RFC 7296 sections 2.15/2.16. Complete synthetic SA_INIT messages
select PRF-HMAC-SHA256, AES-GCM-16-256 and ECP-256. P-256 scalars 1 and 2,
incrementing nonce octets, a test ID_KEY_ID, and `n3iwf.example` are public test
inputs. OpenSSL reproduces the two public points and shared value; a separate
Python standard-library reference computes the IKE key schedule and AUTH.
Recorded answers use explicit JSON integer octets, with strict byte bounds.
The SDK compares every derived key, constructs exact AUTH bodies, and verifies
30 cases plus 1,549 mutations. The NGAP test passes the decoded placeholder
octets to the existing raw-slice IKE API. It does not import into a custody
handle or establish a complete protected exchange. Tests print case names and
constant errors, with no key/transcript assertions that render input bytes.

The NGAP legacy vector is transformed before publication. Its full original
literal is SHA-256 pinned and its precise sanitization is tested. The source
is not evidence of Release-18 N3IWF message conformance. Exact Release-18
matrices instead come from the independently pinned ETSI ASN.1 extraction.
The complete-message corpus uses Pycrate 0.8.1 compiled from that exact PDF;
the bundled Pycrate NGAP schema and the SDK generator are not used. The gate
checks mandatory presence, criticality, singleton cardinality, nested ASN.1
transfers, N3IWF node/location choice, conditional resource results, UE AMBR
when initial context setup includes session resources, and Session AMBR for
the reviewed non-GBR 5QI 9 profile. It exercises all 15 admitted outcomes.
The current SDK checks framing and opaque IE bytes against those independent
results, and rejects incorrect procedure criticality before typed decoding.
The complete existing Echo Request/Response and downlink PSC literals are
compared to the published GTP-U bytes. Codec execution adds semantic checks;
round trips alone do not prove external interoperability.

## Unsupported evidence

- SDK NGAP mandatory/conditional presence, typed inner IE validation and
  canonical typed encode (#787). Reference validation does not implement
  those runtime functions. Full clause 5.3 content handling, procedures outside
  the admitted 15 outcomes, other QoS profiles and live AMF interoperability
  remain unproven.
- Complete protected IKE exchanges, subscriber or certificate authentication,
  K_AMF hierarchy derivation, consume-once protocol-key custody (#791), key
  export, and actual memory zeroization. Synthetic IKE key-schedule answers
  are distinct from these unimplemented or unproven boundaries.
- Established DTLS sessions, verified peer certificates, actual exporter
  output, SCTP reliability, restart recovery, and authenticated relocation.
- Kernel XFRM installation, live dataplane, AMF selection, deployment,
  readiness, and product claims. Issue 795 remains tracking-only.

The [README](README.md) maps each subset to its exact evidence boundary.
The [maintenance guide](../../docs/n3iwf-fixture-contracts.md) describes
publication history and the independently executable gates.

## Validation

Catalog loading fails on invalid or oversized files, noncanonical paths,
symlinks, unknown/duplicate JSON fields, incorrect digests, redaction denylist
matches, inventory drift, and Release-18 matrix drift. Debug and errors are
redacted. Content screening complements provenance review; it cannot identify
all possible sensitive input.

The repository gate checks regeneration without mutation, independent wire
and scenario oracles, existing SDK codec execution, and actual Git publication
content/ancestry. Regression tests cover fix removal and adversarial mutations,
including changed bytes with refreshed digests and changed caller context.
