# N3IWF procedure routing and trigger contract

This matrix implements the applicability boundary in TS 29.413 V18.5.0
5.1–5.4. Message metadata comes from TS 38.413 V18.10.0 9.4; the procedure
clauses below control behavior, with the non-3GPP exceptions in TS 29.413 5.3.
The 40 applicable outcomes comprise 23 qualified field subsets and 17 requiring
an external handler. The latter have no canonical or typed receive codec in
this SDK boundary and their local triggers are disabled. This matrix does not
upgrade their wire conformance status or establish endpoint readiness.

## Receive boundary

Use `n3iwf::applicability::inspect(bytes, receiver, context)` before the generic
decoder. It checks one complete envelope, direction for applicable messages,
and the assigned criticality and valid outcomes for all 81 Release 18 procedure
codes. It scans all open-type fragments without allocating or coalescing the
body. Trailing bytes, truncation, nonminimal length determinants, nonzero header
padding and outer CHOICE additions fail. The complete byte limit and depth three
are required. No IE count or field policy is consumed by this routing stage.

The returned dispositions have distinct obligations:

- `Qualified(message)`: apply generic decoding and the corresponding typed
  field admission using the same `DecodeContext`. A correctly routed empty IE
  container can still fail mandatory-field admission. Retain the existing
  unknown/duplicate policies and the typed boundary's conditional rules.
- `HandlerRequired(message)`: dispatch to an installed handler implementing the
  applicable procedure and its qualified codec. A missing handler is a caller
  integration gap. Do not describe it as absent from N3IWF applicability, infer
  a successful operation, or enable a local trigger from this result.
- `Unsupported(metadata)`: only procedures absent from the applicability list
  reach TS 29.413 5.4 handling. `ignore` means ignore without an unsupported
  report; `reject` means reject and initiate Error Indication; `notify` means
  ignore and initiate Error Indication (TS 38.413 10.3.4.1). No payload effect
  is authorized. `diagnostics()` supplies the procedure code, triggering outcome
  and procedure criticality required in the report, with no offending value.

Known Release 18 criticality mismatches and invalid outcomes fail classification
instead of selecting a fallback from peer-supplied criticality. Unknown/future
codes use the received criticality because this profile has no assigned metadata
for them. The existing generic decoder and its broader generated schema remain
unchanged; this is an explicit N3IWF profile. For example, generic structural
Paging support does not make Paging N3IWF-applicable.

Routing failures are value-free local errors, not transmitted protocol replies.
The caller distinguishes resource limits from syntax/procedure failures, applies
TS 38.413 clause 10, and supplies the actual signalling context and identifiers
when constructing Error Indication. Transfer syntax errors follow 10.2; missing,
unknown, repeated and erroneously present IEs follow their different 10.3 rules;
logical errors follow 10.4. An initiating procedure with a defined unsuccessful
outcome may require that outcome for an unknown reject-criticality IE, provided
the required response information is available. Procedures without such an
outcome require Error Indication; an erroneous response instead requires local
unsuccessful termination/error handling (10.3.4.2). Do not turn every typed
decode failure into one common network response.

## Local trigger boundary

`ApplicableMessage::local_trigger(sender)` checks direction and wire capability.
`CodecAvailable` identifies a qualified **subset**, not authorization to send.
`DisabledPendingHandler` applies to every pending outcome, including replies.
`WrongDirection` prevents using a peer-originated outcome as a local trigger.
There is no switch that enables a pending codec by asserting a handler exists.

Before using an available codec, the caller must establish transport and
signalling context, request correlation, applicable field conditions and the
procedure state needed by the corresponding clause. In particular:

| Available procedure family | Caller prerequisites and receive/error responsibilities |
|---|---|
| NG Setup, 8.7.1 | Use non-UE signalling, correlate response/failure with setup, apply supplied configuration only after admission, and respect Time to Wait before retry. No decode result establishes an AMF association. |
| Initial UE and NAS transport/non-delivery, 8.6.1–8.6.4 | Allocate/correlate local and peer UE IDs; establish or transfer the logical association only under the procedure's conditions; forward opaque NAS only when eligible. Non-delivery reports require an actual delivery failure and appropriate Cause. |
| Initial Context Setup, 8.3.1 | Correlate UE and session contexts, provide the conditional N3IWF key and applicable location, and report accepted/failed resources from actual results. Security installation and failure cleanup belong to the caller. |
| PDU resource setup/modify/release/notify, 8.2.1–8.2.4 | Check session/QFI ownership, request correspondence and supported QoS; perform resource operations before reporting results; preserve partial failures. Modify NAS is forwarded only under its qualifying success conditions. Notify eligibility requires the established flow classification; decode does not establish it. |
| UE release request/release, 8.3.2–8.3.3 | Requests arise from the appropriate local release condition; correlate commands and complete only the required teardown. An identifier pair is not proof of ownership. |
| Reset/Acknowledge, 8.7.4 | Use non-UE signalling, correlate partial/all reset, retain receiver-ignored empty items for acknowledgement handling, and complete the actual UE-context effects. Reset does not replace setup configuration. |
| Error Indication, 8.7.5 and clause 10 | Choose Cause/diagnostics and UE or non-UE signalling from the actual error; include both IDs when required by the typed UE-associated boundary. No automatic error loop, retry or state change is provided. |

## Applicable procedures requiring handlers

Every outcome named below is present in `APPLICABLE_MESSAGES`. All have disabled
local triggers and require externally qualified receive handling. Requests and
responses are distinct rows in the independent metadata corpus, which records
each field's identifier, presence and criticality. The rules here describe the
caller contract; they do not claim an implemented field codec or state machine.

| Outcomes; code and procedure criticality | Direction/signalling | Required receive and error behavior before enabling a trigger |
|---|---|---|
| UE Context Modification Request/Response/Failure; 40/reject; 8.3.4 | Request AMF → N3IWF; replies reverse; UE | Apply admitted, applicable modifications and report Response; if unable, report Failure with Cause. Handle old/new AMF UE IDs and concurrent class-1 responses as prescribed. TS 29.413 5.3 requires the special old-to-new AMF association change when this is the first message from the new AMF. RAN UE ID lookup, authority, atomic state updates and failure cleanup are caller-owned. |
| Reroute NAS Request; 36/reject; 8.6.5 | AMF → N3IWF; UE | When supported, reroute Initial UE Message to the indicated AMF Set; propagate Allowed NSSAI and Source-to-Target AMF information when present. Partially Allowed NSSAI is conditional on support; overlap with Allowed NSSAI or a combined count above eight fails the procedure. AMF selection and NAS replay are caller policy. No successful or unsuccessful NGAP outcome is defined for this procedure. |
| RAN Configuration Update/Acknowledge/Failure; 35/reject; 8.7.2 | Update N3IWF → AMF; replies reverse; non-UE | Apply supplied applicable configuration while preserving omitted values; acknowledge acceptance or fail with Cause. Respect Time to Wait before another attempt. If no reply arrives, a retried update must carry identical unacknowledged content. TS 29.413 ignores Default Paging DRX and NB-IoT Default Paging DRX. |
| AMF Configuration Update/Acknowledge/Failure; 0/reject; 8.7.3 | Update AMF → N3IWF; replies reverse; non-UE | Preserve omitted configuration, perform qualified TNL association changes and report their accepted/failed results as specified. Inability to accept requires Failure with Cause; Time to Wait gates AMF retries. An unanswered retry must carry identical content. Association selection, setup/release effects, transaction correlation and timer storage are caller-owned. |
| AMF Status Indication; 1/ignore; 8.7.6 | AMF → N3IWF; non-UE | Mark the indicated GUAMIs unavailable and apply the specified reselection/backup-AMF behavior, including supported timing information. Do not continue selecting an unavailable AMF merely because no typed codec is installed. There is no defined successful/unsuccessful outcome. |
| Overload Start/Stop; 22/ignore and 23/reject; 8.7.7–8.7.8 | AMF → N3IWF; non-UE | Start installs/replaces the AMF or slice overload instructions and applies the prescribed traffic reduction/permitted-signalling rules; Stop removes the relevant overload treatment. Map Overload Action to non-3GPP establishment causes under TS 29.413 5.3 and TS 24.502. Caller-owned traffic control must implement these effects before enabling the procedure. Neither message defines a response outcome. |
| UE TNLA Binding Release Request; 45/ignore; 8.13.1 | AMF → N3IWF; UE | Remove the specified UE transport binding while preserving UE context and NG-U/user-plane connectivity. This is neither UE Context Release nor teardown of the whole SCTP association. No response outcome is defined. |
| Trace Start, Trace Failure Indication, Deactivate Trace; 39/ignore, 38/ignore, 3/ignore; 8.11.1–8.11.3 | Start/deactivate AMF → N3IWF; failure reverse; UE | Trace is explicitly applicable to N3IWF. Start may establish the logical association under its stated conditions. Apply/deactivate the identified trace and send Trace Failure Indication with Cause only for the specified failure conditions. It is a separate initiating message, not an unsuccessful outcome of Trace Start. Ignore MDT Configuration per TS 29.413 5.3; do not infer radio handover behavior for N3IWF. |

UE Context Modification also requires the complete TS 29.413 5.3 receiver-ignore
list (including UE Security Capabilities and Response RRC State). Its Security
Key denotes K_N3IWF; UE Aggregate Maximum Bit Rate remains applicable to this
access type. A handler must not substitute radio security or an empty/default
key. These pending fields have no local constructor or decoder in this profile.

## Evidence and remaining scope

`scripts/generate-ngap-applicability-fixtures.py` verifies membership against the
hash-pinned TS 29.413 PDF, compiles the pinned Release 18 NGAP schema independently,
and compares both unmodified reference encoders. Its 2,321 envelopes cover all
256 codes × three outcomes × three criticalities and 17 length/fragment cases
through 131,072 opaque payload bytes. The corpus separately records the 131
defined schema outcomes and metadata for all 40 applicable messages. Independently
encoded diagnostic headers qualify the unsupported-procedure reports.

These are **routing envelopes**, not 2,321 admitted complete messages. Opaque or
empty bodies intentionally do not establish mandatory-field validity. In
particular, the PrivateMessage envelope carries an intentionally unqualified body;
its separate ASN.1 layout is not claimed. Structured reference decoding checks
all other routing vectors. Bounded mutation, exact/one-short byte and depth limits,
every caller policy combination, direction, trigger gates and redaction are
covered by ordinary tests and shared fuzz assertions. Large complete vectors run
in ordinary tests; only one seed above the fuzz cap uses a bounded prefix.

Source digests:

- TS 29.413 V18.5.0 PDF: `c207c2042c6fe60fa98ace159855013b9afb1320ac34a17279530d4b75369953`.
- TS 38.413 V18.10.0 PDF: `21617ad6dd826e05a0e8356ef96f44199cf4c7bc1be65e6b915e9135e10b59e2`.
- Routing oracle: `efba0bcfd1afd6f67953bfa8e2f80917656864aad618c32514ccf2c7c3630bcb`.

Pycrate 0.8.1 and pypdf 6.1.0 are pinned by the reference helper. No generated
SDK schema, dependency or published fixture revision changes. The original
#787 conditional-procedure criterion requires these explicit dispositions and
trigger gates; it does not qualify the 17 pending field codecs. They remain
unsupported with local triggers disabled. The 23 implemented outcomes and
aggregate criterion evidence are recorded in
[N3IWF-ACCEPTANCE.md](N3IWF-ACCEPTANCE.md). Procedure state, deployment readiness
and live AMF interoperability remain outside the codec evidence.
