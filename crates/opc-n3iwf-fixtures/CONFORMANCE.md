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
the reviewed non-GBR 5QI 9 profile. It exercises all 23 qualified outcomes. The eight added outcomes reuse 16
positive/negative vectors from four existing independent codec corpora. Each
reference pins its source file, case and digest; an updated local wire digest
cannot replace that evidence. The catalog inventory, direction, procedure and
outcome must match the runtime applicability rules for every qualified codec.
The current SDK checks framing and opaque IE bytes against those independent
results, and rejects incorrect procedure criticality before typed decoding.
The complete existing Echo Request/Response and downlink PSC literals are
compared to the published GTP-U bytes. Twenty-two additional PSC packets reuse
unchanged cases from the independent `opc-gtpu-dataplane/tests/n3_reference.tsv`
corpus (SHA-256 `31da0a1658218432817bc181be4233fadd4fd1f36c36f3d29f087bc131b8424a`).
At QFI 9 they cover both downlink RQI values and all absent/present PPI values;
QFI 0/63 also cover uplink and downlink. The source is generated without SDK
codec or catalog imports under TS 38.415 V18.2.0 5.5.2/5.5.3 and the framing
clauses of TS 29.281 V18.4.0. Each manifest records its source path, digest,
case and expected fields. A separate verifier rejects substituted bytes even
when their local digest is refreshed, or changed source, direction, field,
critical provenance or normative-source claims. Existing fixture wires remain
unchanged. Codec execution checks all 33 GTP-U catalog cases and preserves the
new packets' opaque payload. This qualifies synthetic PSC wire fields only;
forwarding installation, classifier binding and backend capability remain #790.
Round trips alone do not prove external interoperability.

## Unsupported evidence

- SDK NGAP typed field admission is qualified separately by the codec
  corpora in [opc-proto-ngap](../opc-proto-ngap/CONFORMANCE.md) (#787). This
  catalog exercises opaque fields and canonical container construction; it
  does not qualify every optional field or authorize a network procedure.
  Full clause 5.3 content handling, the 17 outcomes requiring an external
  handler, other QoS profiles and live AMF interoperability remain unproven.
- Complete protected IKE exchanges, subscriber or certificate authentication,
  K_AMF hierarchy derivation, hardware-backed custody, key export, and external
  memory-zeroization observation. The executable volatile custody and private
  audit evidence below qualifies its explicitly bounded SDK contract.
- Established DTLS sessions, verified peer certificates, actual exporter
  output, SCTP reliability, restart recovery, and authenticated relocation.
- Kernel XFRM installation, live dataplane, AMF selection, deployment,
  readiness, and product claims. Issue 795 remains tracking-only.

The [README](README.md) maps each subset to its exact evidence boundary.
The [maintenance guide](../../docs/n3iwf-fixture-contracts.md) describes
publication history and the independently executable gates.

## Executable durable object-roster schedules

Nine `durable-object-roster-lifecycle` records bind 636 independent schedules
to the existing grouped XFRM recovery contract: each supported arity 1–8 with
SA-only, policy-only and alternating member kinds. The eight-member bound is
SDK policy. The reference pins the unchanged public contract section and imports
neither runtime code nor the catalog writer. Its JSON and TSV encodings are
regenerated and checked independently; the catalog binds their exact source
digest, family, schedule count and execution scope.

The private replay uses the existing scripted backend with a real authenticated
durable store. It compares declared acquisition order, reverse compensation,
per-member physical presence and authenticated dispositions, store reopening,
recovery verdicts and repeated terminal recovery. Schedules include complete
apply/finalize/adopt, prepared and applied restart, readback failure, foreign
conflict and installation failure at every ordinal, and issuing cuts before and
after every effect. Public inspection rejects every single-byte handle mutation,
wrong group/generation, reordered or substituted members, and superseded handles.

The catalog gate rejects changed schedules even with refreshed local digests,
changed execution or provenance claims, and incomplete inventory. Legacy roster
labels remain separately qualified as scenario labels. These records contain
only synthetic ordinal obligations, not packets or key material. They establish
neither installed packet classification nor authenticated packet provenance,
overlapping Child-SA ownership or complete roster relocation. Those runtime
boundaries remain in #793. Separately executed Linux crash-cut tests are recorded
in PR evidence; the 636 scripted schedules themselves have
`kernel_validation=false` and all catalog records retain `runtime_claim=false`.

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

## N2 port correction — 2026-09-17

Four metadata vectors previously encoded `96 1c` (38428) while claiming the
IANA `ng-control` SCTP service port 38412. They now encode `96 0c`; their
manifest digests change with the bytes. The independent semantic oracle checks
required PPID/port claims in both metadata orders and all repeated tuples, as
well as DATA PPID/type/user length. Python and Rust regressions anchor the
service port to decimal 38412 independently of the generator.

The DATA vector still carries one opaque synthetic user octet; its provenance
now says so. The 65535 negative exceeds a caller-selected maximum of 65534;
65535 remains a valid dynamic port. Fixture classes, dispositions, runtime
claims and transport implementation scope are unchanged. The corrected
publication must be reviewed and merged before qualifying a new N2 consumer
against these vectors.

Authority: [IANA NG Control Plane service registration](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=ng-control),
[TS 38.412 V18.1.0 clause 7](https://www.etsi.org/deliver/etsi_ts/138400_138499/138412/18.01.00_60/ts_138412v180100p.pdf),
and [RFC 6335 section 6](https://www.rfc-editor.org/rfc/rfc6335.html#section-6).

## Executable protocol-key custody schedules

Twenty-five independently authored `protocol-key-lifecycle` records replay the
existing volatile `opc-proto-ikev2::protocol_key` API. Valid imports use a
32-zero-octet synthetic placeholder; invalid-width tests use bounded zero-only
variants. Successful consumption uses the existing independent RFC 7296
initiator/responder AUTH answers and must match both. A successful
scenario means all expected results match, including the refusals inside it;
it does not mean every requested key operation succeeded.

The records cover generation mismatch and non-increasing replacement, foreign
associations, operation reuse/pending slots, duplicate import, invalid width and
purpose, input-limit and transcript-direction failure, handle/operation/owner
drop, explicit release, cancellation of an actually polled pending future,
stale-guard retirement, finite generation exhaustion and two concurrent
consumption attempts. Numeric labels remain caller-owned SDK replay policy,
separate from the cited wire and cryptographic standards.

`scripts/n3iwf_key_lifecycle_reference.py` authors fixed expected results without
importing an SDK runtime or the catalog writer. Its source pins bind the unchanged
public SDK custody contract, private audit source and independent AUTH corpus.
The catalog gate compares the schedule bytes and exact source/claim binding;
refreshed local digests cannot disguise a changed expected result. Legacy
`handle-lifecycle-contract` labels remain separate and unchanged.

Public opaque-handle refusal proves retirement at the API boundary. Memory
clearing is separately qualified by the existing private test audit that observes
the owned buffer after zeroization and before release, including invalid imports
and cancellation. No pointer to freed memory is inspected or published. These
results qualify synthetic SDK software custody only; live-peer authentication,
subscriber authorization, sealed/hardware custody and key hierarchy derivation
remain outside this fixture scope. All manifests retain `runtime_claim=false`.
