# opc-n3iwf-fixtures conformance

## Claim

Synthetic fixture inventories, catalog validation, bounded envelope checks,
and local reference scenarios. `runtime_claim=false` throughout. The crate
has no runtime protocol dependencies; test-only dependencies exercise the
existing NGAP and GTP-U codecs against the published bytes.

`complete` in a subset record means its declared fixture inventory is complete
at its `validation_scope`. It does not mean a N3IWF primitive is implemented
or that all acceptance evidence for issue 784 has been supplied.

## Specification baseline

| Document | Release | Evidence |
| --- | --- | --- |
| 3GPP TS 24.502 | V18.8.0 | EAP-5G, IKE payloads, GRE/QFI, NAS-over-TCP envelopes |
| 3GPP TS 29.413 | V18.5.0 | N3IWF application scope, clauses 5.2–5.4 |
| 3GPP TS 38.413 | V18.10.0 | Exact ASN.1 message IE rows, clause 9.4.3 |
| 3GPP TS 38.412 | V18.1.0 | PPID 60/66 and port 38412, clause 7 |
| 3GPP TS 29.281 | V18.4.0 | GTP-U Echo, Recovery, extension chains |
| 3GPP TS 38.415 | V18.2.0 | Direction-specific PSC, clause 5.5.3 |
| 3GPP TS 33.501 | V18.12.0 | K_N3IWF purpose; no derivation evidence |
| IETF RFC 7296 / RFC 4555 | Published RFCs | IKE payloads and MOBIKE address notification |
| IETF RFC 4960 | Published RFC | SCTP DATA framing |
| IETF RFC 6083 | Published RFC | Reliable delivery and AUTH/exporter lifecycle obligations, §4.8/§5 |
| IETF RFC 6347 / RFC 5246 | Published RFCs | DTLS 1.2 record and isolated ServerHelloDone |

## Provenance and reuse

Allowed provenance classes are `spec-authored`, `referenced-public-vector`,
`synthetic-negative`, and `synthetic-kat`. The last is a legacy schema name
for scenario labels here; it does not claim a cryptographic known-answer test.
No subscriber captures or key material are published. Documentation addresses,
reserved test PLMN, and synthetic identifiers are used.

The NGAP legacy vector is transformed before publication. Its full original
literal is SHA-256 pinned and its precise sanitization is tested. The source
is not evidence of Release-18 N3IWF message conformance. Exact Release-18
matrices instead come from the independently pinned ETSI ASN.1 extraction.
The complete existing Echo Request/Response and downlink PSC literals are
compared to the published GTP-U bytes. Codec execution adds semantic checks;
round trips alone do not prove external interoperability.

## Unsupported evidence

- NGAP mandatory presence/inner IE validation, clause 5.3 content exceptions,
  independently validated complete N3IWF messages, and canonical typed encode.
- Complete IKE exchanges, subscriber authentication, key derivation/export,
  and actual memory zeroization.
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
