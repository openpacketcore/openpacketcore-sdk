# opc-proto-gtpv2c conformance subset

## Scope

- **Specification family:** 3GPP TS 29.274 (GTPv2-C), Release 18 naming.
- **Referenced specification:** 3GPP TS 24.008 V20.0.0, clause 10.5.6.3 only,
  for the PCO inner codec. Every 10.5.6.3 reference in this document is to that
  version, and the clause text this crate relies on is unchanged from V13.7.0
  through V20.0.0. The bare TS 24.008 TFT references below (clause 10.5.6.12
  format, cited without a clause or version number) are `opc-proto-tft`'s
  boundary and are pinned in that crate, not by the V20.0.0 pin above.
- **Crate status:** Experimental S2b-focused typed subset with a raw-preserving
  message/IE shell. `S2b Production Profile v1` is the retained candidate
  identifier for the documented boundary, not a maturity attestation.
- **Implemented evidence:** common-header structural parsing including typed
  EPC Message Priority, raw TLIV IE boundary validation, raw-preserving
  encode/decode, provenance-labeled fixture corpus replay, independent-capture
  intake checks, malformed-input replay,
  profile-critical negative fixture replay, typed S2b IE examples, and typed S2b
  views for Echo, Create/Modify/Delete Session-oriented procedures, and
  PGW-triggered Create Bearer/Update Bearer/Delete Bearer procedures.
  The transport-neutral Echo peer helper also tracks Recovery restart counters
  and rejects new Echo exchanges while restart reconciliation is required.
  Public profile constructors cover Echo, Create Session, Modify Bearer,
  Delete Session, Update Bearer, Create Bearer, and Delete Bearer
  profile-owned request/response shapes. A bounded in-memory transaction
  registry provides generation-bound at-most-once dispatch and exact
  committed-response replay for the three inbound triggered procedures. A
  separate zero-allocation fixed-header inspector and bounded typed response
  planner cover the Release 18 protocol-error response boundary without
  retaining packet bodies or transaction state.

## S2b Production Profile v1 — Experimental Target Boundary

S2b Production Profile v1 is a retained public identifier for an experimental
**codec, typed-view, validation, and transport-neutral helper profile** for
ePDG/PGW S2b integration. It is not a production-ready boundary. It does not
claim to implement a PGW, ePDG, UDP transport, retransmission loop, bearer
policy engine, APN/DNN authorization service, charging policy, roaming policy,
independent-peer interoperability, or carrier-accepted control-plane product.

### Profile-owned procedures

The profile owns typed decode, encode, construction, and procedure-aware
validation for these S2b procedure messages:

| Procedure | Message types | Profile requirement |
|:---|:---|:---|
| Echo | Request (1), Response (2) | Recovery IE decode/encode, no-TEID header shape, sequence preservation, restart-counter evidence. |
| Create Session | Request (32), Response (33) | S2b request/response required-IE validation, including subscriber/UICC-less emergency identity, AAA/HSS-provenanced MSISDN, typed charging/trace/location and UE NAT context, a separately typed Create-only ePDG IKEv2 endpoint, PAA-owned requested family with no top-level PDN Type, request Sender F-TEID, response Cause classification, instance-1 PGW S2b control F-TEID, and bearer-context projection. |
| Modify Bearer / S2b UE-initiated IPsec tunnel update | Request (34), Response (35) | Independently optional WLAN location/timestamp, typed Fixed Broadband UE Local IP plus conditional UDP Port, clause 7.7.9 discard of the non-S2b Bearer Context request shape, and Cause-bearing response correlation. |
| Delete Session | Request (36), Response (37) | Linked EPS Bearer ID plus mandatory UE Local IP, procedure-specific UDP/TCP NAT instances, optional WLAN location/timestamp and Diameter/IKEv2 release cause; Cause-bearing response validation. |
| Update Bearer | Request (97), Response (98) | Mandatory APN-AMBR and one to fifteen request contexts; typed per-bearer TFT/QoS changes; mandatory correlated response contexts; message/bearer Cause hierarchy and partial acceptance. |
| Create Bearer | Request (95), Response (96) | One or more correlated Bearer Contexts; typed Bearer TFT/QoS/Charging ID; S2b-U PGW/ePDG F-TEID instance and interface validation; message/bearer Cause hierarchy; partial acceptance. |
| Delete Bearer | Request (99), Response (100) | Mutually exclusive linked/default-bearer and repeated dedicated-EBI request forms; correlated linked or per-bearer response form; partial failure. |

### Protocol-error response boundary

The error-response boundary is deliberately separate from full `Message` and
`S2bMessage` decode. It claims these TS 29.274 Release 18 behaviors:

- Fixed-header inspection allocates nothing and requires the exact eight-byte
  no-TEID or twelve-byte TEID-present header before returning an answerable
  envelope. It retains version, typed request/procedure, 24-bit sequence,
  redacted TEID classification, optional Message Priority, and declared versus
  actual datagram lengths; it never retains IE or packet bytes.
- A complete higher unsupported version maps to header-only message type 3
  using a checked locally supplied sequence. The received sequence is not
  retained as correlation state. The typed continuation takes only the proven
  unsupported-version envelope, so callers do not fabricate request-failure
  evidence; a separate continuation accepts version-2 request envelopes plus
  caller-owned decode/session failure evidence.
- Known S2b requests map to the corresponding response type and copy the
  request sequence. Invalid message length maps to Cause 67. Missing mandatory
  and conditional IEs map to Causes 70 and 103; invalid mandatory/conditional
  IE length maps to Cause 67; semantically incorrect mandatory/conditional IEs
  map to Cause 69. IE failures encode only the standardized four-octet Type,
  zero Length, and Instance identity in the Cause IE.
- `Gtpv2cDecodeError::top_level_offending_ie` is the checked scope projection.
  `Gtpv2cErrorResponsePlanner::plan_invalid_ie_length_from_decode` accepts only
  length-shaped evidence carrying that top-level identity, then applies the
  normal request, Echo and message-length checks. It returns no plan for a
  standalone region whose scope is Unknown or for a grouped member because
  grouped Cause flags are not yet modelled; it never emits either under the
  zero flags octet. The caller still resolves from the message grammar that the
  slot is Mandatory or verifiable Conditional and must preserve the exact
  datagram/decode-error association.
- An unknown received non-zero session TEID is the only plan input that
  produces Context Not Found with header TEID zero. Applying that failure to a
  legitimate zero-TEID initial request is rejected as conflicting evidence.
  Other protocol errors require either a caller-supplied non-zero remote TEID
  or the explicit clause 5.5.2 no-lookup path. The latter uses TEID zero while
  retaining the protocol-error Cause, so Context Not Found is unrepresentable
  in that path.
- Malformed Echo Request IEs map to Echo Response with the caller's local
  Recovery value and no Cause IE. Incomplete headers, lower versions,
  piggybacked messages, unknown message types, responses, malformed fixed
  request header shapes, and Echo length mismatches produce no response plan.
- Canonical output is at most 22 octets. Exact input/output lengths and the
  TEID-zero decision are available before encoding, and `EncodeContext` bounds
  fail before output is written. All TEID- and peer-bearing `Debug` surfaces
  redact values.

The caller retains responsibility for peer admission, reflection/rate-limit
policy, UDP transport, session/remote-TEID lookup, transaction state, and the
decision to send an otherwise standards-valid plan.

### Profile-owned IE families

The profile owns the typed IE families required by the S2b messages above:

- Node and liveness IEs: Recovery.
- Subscriber/session IEs: IMSI, APN, PAA, Selection Mode, RAT Type, Serving
  Network, MEI, and MSISDN. PDN Type remains a typed generic IE for non-S2b
  profiles but is prohibited from the S2b Create Session sender profile.
- Tunnel and bearer IEs: request Sender F-TEID, response PGW S2b control
  F-TEID, Bearer Context, EPS Bearer ID, Bearer QoS, Charging ID, AMBR, APN
  Restriction, and Bearer TFT backed by the shared `opc-proto-tft` TS 24.008
  codec.
- S2b session/tunnel endpoint and context IEs: IP Address (IPv4/IPv6), Port
  Number, Charging Characteristics, exact-length Trace Information with typed
  TS 32.422 Session Trace Depth, explicit
  Diameter/IKEv2 RAN/NAS Cause, complete bounded TWAN Identifier fields, and
  TWAN Identifier Timestamp.
  Their Debug surfaces redact addresses, ports, SSIDs, operator/location
  contents, relay identities, Circuit-ID, and timestamp values.
- Peer node identity IEs: Node Identifier, carrying the clause 8.107 Node
  Name/Node Realm Diameter Identity pair. On S2b this is the Table 7.2.1-1
  3GPP AAA Server Identifier only. Its Debug surface reports subfield lengths
  and redacts both values, which name operator AAA infrastructure. (Distinct
  from the Recovery IE listed under node and liveness IEs above, which carries
  no identity.)
- Response and policy containers: Cause, Indication, PCO, APCO.
- Unknown, private, and unsupported future IEs follow the caller's
  `UnknownIePolicy` at every typed sequence scope: `Drop` omits them from the
  interpreted view, `Preserve` retains byte-exact `TypedIeValue::Raw`, and
  `Reject` returns `UnknownCriticalIe`. They are never interpreted as product
  policy.

### Required semantic validation

Profile-v1 validation must separate structural decode failures from S2b profile
failures and must cover at least these rules:

- Echo messages must be no-TEID messages and must include Recovery.
- Dedicated-bearer messages 95 through 100 require the TEID-present header
  shape. Requests and accepted/partially accepted responses require a non-zero
  TEID; a rejected response may carry TEID zero as specified for an error that
  cannot be associated with a tunnel. The triggered transaction registry still
  requires a caller-supplied non-zero response-routing TEID.
- Create Session Request must include IMSI or, for a UICC-less emergency
  attach, MEI instance 0 plus an instance-0 Indication carrying the UIMSI bit.
  RAT Type, Serving Network, Sender F-TEID, APN, Selection Mode, PAA, and
  Bearer Context with nested EBI remain required in either case. PAA carries
  the requested family; a separate top-level PDN Type IE is never sent on S2b.
  Explicit PAA constructors distinguish dynamic all-zero IP requests from
  AAA-provided static allocation and validate the IPv4, IPv6, IPv4v6, Non-IP,
  or Ethernet field shape before encode.
  Conditional Create context encodes MSISDN/charging/trace at instance 0, UE
  Local IP and UDP Port at instance 0, UE TCP Port at instance 2, Create-only
  Fixed Broadband ePDG IKEv2 IP at instance 3, WLAN Location at instance 1,
  and WLAN Location Timestamp at instance 0. Either NAT port requires UE Local
  IP; UICC-less emergency identity additionally requires the local IP. The
  sender input records AAA/HSS MSISDN provenance and keeps product-owned
  applicability decisions explicit. PCO/APCO, Recovery, MEI, and Indication
  use their existing typed codecs rather than parallel containers.
- Create Session Response must include Cause, PGW S2b control F-TEID instance
  1/interface type 32, and Bearer Context for accepted responses (Cause 16/17).
  The control endpoint requires a non-zero TEID and at least one address;
  instance-0 Sender F-TEID is unexpected on this S2b response profile and is
  discarded. Rejected responses may expose Cause-only summaries.
- S2b Modify Bearer Request is the UE-initiated IPsec tunnel-update profile.
  It requires a non-zero header TEID but no mandatory IE. WLAN Location
  Information (TWAN Identifier instance 0) and WLAN Location Timestamp (TWAN
  Identifier Timestamp instance 0) are independently conditional on
  availability. The Fixed Broadband/local-policy form carries changed UE
  Local IP Address at instance 1 and may carry UE UDP Port at instance 1 only
  when NAT was detected and the local address is present. A UDP port without
  local IP fails closed. The S2b sender intent cannot emit Bearer Context or
  known fields through `additional_ies`, except for the ePDG Overload Control
  Information assigned to instance 2 by Table 7.2.7-1. ProcedureAware receive
  retains that exact optional key, discards an unexpected Bearer Context or
  wrong known instance under clause 7.7.9, and continues with the applicable
  S2b fields. First-occurrence receive applies independently to every allowed
  singleton key.
- Delete Session Request must include linked EPS Bearer ID, a non-zero header
  TEID, and UE Local IP Address instance 0. Optional UDP Port uses instance 0,
  TCP Port instance 1, and both require the typed UE endpoint/NAT declaration.
  WLAN Location and Timestamp use instance 1. Optional RAN/NAS Cause instance
  0 accepts only the S2b Diameter Termination-Cause or an IKEv2 Notify error
  type in RFC 7296's `0..=16383` error range. Delete Session has no
  profile-owned ePDG IP instance-3 role.
- Procedure responses must include Cause where the profile claims response
  semantics.
- Create Bearer Request must carry a linked EBI instance 0 and one to fifteen
  Bearer Contexts instance 0. Every context must contain request EBI value 0,
  Bearer TFT instance 0, Bearer QoS instance 0, S2b-U PGW F-TEID instance 4
  with interface type 33, and Charging ID instance 0.
- Create Bearer TFT must use the TS 24.008 Create-new operation and contain at
  least one packet filter whose direction definitely applies to uplink
  traffic. Projected operation and filter semantic failures expose TS 29.274
  Cause 74 or 76. `dedicated_bearer_decode_rejection_cause` separately maps
  malformed TFT wire syntax and component conflicts to Cause 75, 76, or 77
  without embedding product admission policy.
- Update Bearer Request must carry APN-AMBR instance 0 and one to fifteen
  Bearer Contexts instance 0. Each context requires a unique non-zero EBI and
  may carry Bearer TFT and/or Bearer QoS at instance 0; a multi-context request
  requires a TFT or QoS modification in every context. Applicable optional
  nested APCO instance 0 remains byte-preserved for S2b P-CSCF restoration.
  PCO is restricted to the other interfaces named by Tables 7.2.15 and 7.2.16,
  and S2b-U F-TEIDs are prohibited in this procedure.
- Update Bearer Response requires a Bearer Context for every request context,
  including whole-message rejection. Each result carries a unique EBI and
  Cause at instance 0. Exact EBI-set and count correlation plus outcome/Cause
  consistency support partial acceptance without silently dropping a bearer.
- Create Bearer Response must contain one result for every request context.
  Accepted contexts require a newly allocated EBI, bearer Cause 16, S2b-U
  ePDG F-TEID instance 8/interface 31, and the correlated request PGW F-TEID
  instance 9/interface 33. Rejected contexts prohibit the ePDG endpoint and
  carry a rejection Cause. Message Cause 17 is valid only for mixed results.
- Create, Update, and Delete Bearer response Causes use audited,
  procedure-aware
  allow-lists at both message and Bearer Context level. The lists combine the
  protocol-error handling in TS 29.274 Release 18 clause 7.7, the general
  operational/fallback rejections defined by Table 8.4-1, and the applicable
  message-specific causes in clauses 7.2.4 and 7.2.10.2. Reserved, spare,
  unknown, and causes assigned only to unrelated procedures are rejected.
- Delete Bearer Request must use exactly one target shape: one linked EBI at
  instance 0, or one to fifteen dedicated EBIs at instance 1. Responses must
  use the corresponding linked or grouped per-bearer form and account for
  every requested EBI exactly once.
- The Delete Bearer request reason called "Local release" by Table 7.2.9.2-1
  is represented by `CauseValue::LocalDetach`, the Table 8.4-1 name for its
  exact initial-Cause wire value 2.
- Dedicated-bearer correlation checks sequence number, list cardinality,
  request PGW F-TEID or EBI identity, response shape, and bearer Cause/F-TEID
  hierarchy. Message Priority is not a correlation key: a Triggered Reply
  should normally copy it, but explicit inter-PLMN policy may strip or override
  it. Malformed contexts are rejected rather than skipped.
- F-TEID and PAA typed validation must reject ambiguous malformed address
  shapes instead of silently canonicalizing them.
- Structural and Strict typed IE decode honor the selected
  `DecodeContext::duplicate_ie_policy`. ProcedureAware S2b receive follows TS
  29.274 clause 7.7.10 instead: the first singleton key in each top-level or
  grouped scope is retained, later occurrences are ignored, and bounded
  `S2bReceiveDiagnostics` records only type, instance, scope/depth, first
  offset, and a saturated duplicate count. A malformed or semantically invalid
  first value remains an error and cannot be repaired by a later value.
- ProcedureAware receive classifies every crate-known typed/control IE key
  against one message grammar keyed by procedure, direction, and exact
  enclosing Bearer Context instance before decoding its value. Unexpected
  known type/instance combinations are discarded under clause 7.7.9.
  Genuinely unknown optional keys then follow `UnknownIePolicy`. The grammar applies
  explicit S2b applicability where the profile assigns an exact endpoint role;
  the same entry defines clause 7.7.10 cardinality, including instance-1
  Bearer Context lists and bounded PGW load/overload lists. Typed projections
  enforce required presence, F-TEID interface/value semantics, and correlation.
  If discarding a key leaves a required expected key absent, the missing-key
  error is retained. Canonical profile builders use a separate Reject policy
  and do not emit duplicate singleton keys.
- S2b Create Session receive accepts the required PAA without top-level PDN
  Type. If an otherwise valid request includes the unexpected known IE 99,
  ProcedureAware receive discards it under clause 7.7.9 and continues; the
  canonical S2b sender rejects any attempt to append IE 99.

### Compatibility and API guarantees

- The raw `Message` and `OwnedMessage` layers remain byte-preserving for
  unknown and vendor-specific IEs.
- Unknown-IE filtering applies only to the interpreted typed view. A
  raw-preserving encode from retained `raw_ies` reproduces the original
  unknown IEs, while canonical typed-view encode emits only retained entries;
  callers must not treat raw forwarding as a sanitized re-encode.
- Typed builders added for this profile must not construct messages missing
  mandatory profile-owned IEs.
- Procedure-aware validation APIs and projection/error codes must remain
  additive under semver if this profile is later graduated.
- Product code must continue to enforce APN/DNN policy, bearer policy, roaming
  policy, charging policy, persistence, and transport behavior outside this
  crate.
- Under `UnknownIePolicy::Preserve`, well-formed top-level and nested optional
  IEs are preserved in order through typed dedicated-bearer
  projections/builders. Preserved unknown duplicate IE keys obey the caller's
  `DuplicateIePolicy` for Structural/Strict decode
  and the first-wins receiver rule for ProcedureAware S2b decode. Standardized Bearer
  Context and dedicated-EBI lists are cardinality-aware, as are request-only
  Load Control Information instance 1 (up to ten), Overload Control
  Information instance 0 (one node plus up to ten APN entries), and PGW Change
  Info instance 0 on PGW-triggered Create/Update/Delete Bearer requests.
  Responses do not inherit those request-only repetition exceptions.
- `Gtpv2cTriggeredTransactions` keys requests by peer token, request TEID,
  24-bit sequence number, message type, and procedure. It retains bounded
  request/response bytes, requires a non-zero remote response TEID, rejects
  conflicting identity reuse, and never invokes application work itself.
  Committed replay state expires on caller-supplied monotonic deadlines. A
  pending timeout instead becomes a retained, generation-bound
  cancellation-required tombstone: the caller must cancel or roll back that
  exact application-work generation and acknowledge cancellation before the
  identity can be removed or dispatched again. Its state is not
  crash-persistent.

### Graduation status

Open graduation blockers include independent peer interoperability and
completion of the declared compatibility and negative-evidence matrix. Future
expansion of this boundary must add the same
constructor, `ProcedureAware` validation, positive fixture, malformed negative
fixture, example, and fuzz-seed mirror evidence before claiming additional
coverage.

## Covered in this subset

1. **Common header**
   - Version field must be GTPv2-C version 2.
   - TEID-present and no-TEID header layouts are parsed.
   - The Length field is interpreted as excluding the first four octets.
   - TEID-present EPC headers model the MP flag separately from their two flag
     spare bits and expose a bounded four-bit Message Priority (`0` highest,
     `15` lowest) from octet 12.
   - No-TEID headers continue to treat all three low flag bits and their final
     sequence octet as spare.
   - Strict validation accepts valid MP-bearing headers and rejects non-zero
     spare bits, MP/value inconsistency, and a priority nibble while MP is
     clear.
   - Raw-preserving encode keeps decoded ignored/spare bits and message
     boundaries while honoring the typed priority; canonical encode retains
     the typed MP value and zeroes common-header spare fields.

2. **Raw IE region**
   - IE type, length, instance, spare bits, and value bytes are preserved.
   - IE lengths are checked with bounded arithmetic.
   - `DecodeContext::max_ies` limits raw IE iteration.
   - Strict validation rejects non-zero IE spare bits.
   - Unknown/private/unsupported IEs remain byte-exact in the raw IE region for
     decode → encode forwarding paths.

3. **Typed S2b IE subset**
   - IMSI, Cause, Recovery, APN, Aggregate Maximum Bit Rate, EPS Bearer ID,
     MEI, MSISDN, Indication, Protocol Configuration Options, PDN Address
     Allocation, Bearer QoS, RAT Type, Serving Network, F-TEID, Bearer
     Context, Charging ID, PDN Type, APN Restriction, Selection Mode,
     Node Identifier, and Additional Protocol Configuration Options have typed
     decode/encode support.
   - PCO/APCO and Indication are typed as opaque byte-preserving containers so
     nested or future protocol options/flags are not silently dropped.
   - The optional TS 24.008 PCO inner codec bounds parsing to 64 units,
     projects repeated IPv4/IPv6 DNS and P-CSCF addresses in wire order, and
     safely skips well-formed unknown containers and unsupported configuration
     protocols without changing opaque IE round trips. Its MS-to-network
     request model emits the zero-length P-CSCF reselection-support container
     `0x0012` exactly once when selected, after lower numeric container
     identifiers. A P-CSCF address request does not imply reselection support;
     empty and legacy combinations retain their prior bytes. The same inner
     value can be carried unchanged by PCO or APCO.
   - 10.5.6.3 states of `0x0012` that "This PCO parameter may be present only
     if a container with P-CSCF IPv4 Address Request or P-CSCF IPv6 Address
     Request is present." That conditional presence is enforced by the type
     rather than at encode time: `PcoRequest::p_cscf` is an optional
     `PcscfRequest` pairing `reselection_support` with a `PcscfAddressRequest`
     whose every variant selects `0x0001`, `0x000c`, or both, so an
     unaccompanied `0x0012` is unrepresentable and the encoder stays
     infallible. On receive the rule has no counterpart: `0012H` is Reserved in
     the network-to-MS direction, and 10.5.6.3 states that a container
     identifier "not supported by the receiving entity" shall be ignored, so a
     decoded instance is skipped rather than rejecting the addresses carried in
     the same value. The rule binds the sender and assigns the receiver no
     behavior, unlike the IPv4 Link MTU wrong-length case where the
     specification names the receiver explicitly.
   - IPCP (`0x8021`) is supported in both directions, as 10.5.6.3 requires.
     The request model emits an RFC 1332 Configure-Request whose contents is an
     RFC 1661 packet stripped of its Protocol and Padding octets, carrying the
     RFC 1877 Primary (129) and Secondary (131) DNS Server Address options with
     the all-zero address that requests a peer-supplied value. Because the
     configuration protocol options list occupies octets 4..w and the
     additional parameters list w+1..z, the unit is encoded ahead of every
     container. On receive, only a Configure-Nak whose Identifier matches the
     outstanding Configure-Request is read for addresses, as RFC 1661 5.3
     requires; the uncorrelated `decode_network_contents` entry point holds no
     Identifier and so reads none. A Configure-Ack echoes the request's options
     verbatim and so conveys no server, and an echoed all-zero address is not
     treated as one. Configure-Request, Configure-Ack and Configure-Reject
     remain DNS-inert, but their Configuration Options framing and known DNS
     option lengths are syntactically validated before they are ignored;
     Identifier, Ack equality, Reject subset and PPP response policy remain
     outside this decoder.
     `PcoAddressConfiguration::validate_network_contents_ipcp_syntax` is a
     separate allocation-free inspection boundary. It shares the PCO framing
     cursor and 64-unit cap, validates every `0x8021` packet regardless of
     Identifier correlation or position relative to the additional-parameters
     list, and returns only `()` or the existing exact `PcoDecodeError`.
     Configuration codes 1 through 4 receive Configuration Option framing and
     known RFC 1877 DNS-length validation; other codes receive the common
     header/declared-Length check only. RFC 1661 padding past the declared
     Length is ignored. This result carries no Identifier, address, or packet
     bytes and conveys no authority to use a Configure-Nak: the correlated
     decoder's `NoOutstandingRequest`, `IdentifierMismatch`, and
     `AfterAdditionalParameters` dispositions are unchanged.
     A malformed unit for this identifier is discarded unit-locally and
     reported through `PcoDecoded::ipcp_discards`, and following containers
     survive: RFC 1661's discard unit is the packet and 10.5.6.3 maps one unit
     to one such packet, so a fault inside a unit whose outer container
     boundary already validated does not reach the value. Once any registered
     network-to-MS container establishes the second logical list, including an
     unsupported, reserved or operator-specific identifier, a later IPCP unit
     is discarded with distinct evidence instead of being adopted from outside
     the configuration protocol options list. These local dispositions are
     unlike a known address container with a bad length, which still rejects
     the whole value under this codec's
     configuration-atomicity policy, for which the specification states no
     receiver disposition.
   - The IPv4 Link MTU container `0x0010` is supported in both directions, with
     the direction-dependent shape Table 10.5.154 assigns: zero-length request
     MS to network, two-octet value network to MS. 10.5.6.3 states that a
     contents length other than two "shall be ignored by the receiver", so that
     instance is skipped and parsing continues. This is a deliberate exception
     to the fail-closed rule applied to the address containers, for which the
     specification states no equivalent instruction.
     An instance whose contents length is two but whose value is below the RFC
     791 68-octet minimum is skipped the same way and reported as absent. That
     is a second, SDK-owned deviation: 10.5.6.3 instructs ignoring only a wrong
     *length*, and a length-two `0x0000` is well-formed by its letter. It is
     taken because a caller that applies a zero or 28-octet link MTU blackholes
     the user plane for that session, which is the failure the container exists
     to prevent. The first *usable* value wins, so an unusable instance does
     not shadow a later usable one; `is_empty()` reports on addresses only, so
     an MTU-only value is still empty.
   - Bearer QoS decodes the fixed 22-octet shape into a typed
     Allocation/Retention Priority, QCI, and 40-bit integer-kbit/s maximum and
     guaranteed bit-rate fields. ARP priority level and spare bits are checked.
     GBR QCIs require a non-zero maximum in at least one direction and each GBR
     must be no greater than its same-direction MBR; a direction may
     intentionally carry zero MBR/GBR. Standardized non-GBR QCIs require all
     four fields to be zero. Operator-specific QCI values remain
     wire-representable but semantic validation requires the caller to supply
     their GBR/non-GBR classification. Reserved QCI ranges fail closed.
     Charging ID decodes as a four-octet identifier.
   - Bearer TFT (type 84) decodes to the canonical `opc-proto-tft`
     `TrafficFlowTemplate`; the same value codec is consumed by IKEv2, avoiding
     divergent protocol-specific TFT representations.
   - Cause decoding preserves the mandatory flags/locality octet and opaque
     offending-IE bytes; one-octet Cause values are rejected as malformed.
   - F-TEID uses the TS 29.274 V4/V6 flag bits (`0x80`/`0x40`) and rejects
     surplus value bytes after the declared IPv4/IPv6 address fields. F-TEID
     values with neither V4 nor V6 set are rejected.
   - Non-IP, Ethernet, and unknown PAA typed values are accepted only in their
     one-octet form; over-long shapes are rejected instead of silently
     canonicalized.
   - Bearer Context is decoded as a grouped IE with bounded recursion and raw
     fallback for unsupported nested members.
   - IP Address accepts exactly four or sixteen value octets. The Extendable
     Port Number and TWAN Identifier Timestamp IEs require their two- and
     four-octet Release 18 prefixes and ignore a later-release suffix.
     TWAN Identifier validates its flag-directed field order, 32-octet SSID
     bound, fixed six-octet BSSID, one-octet variable-field bounds, mutually
     exclusive operator PLMN/name forms, typed relay IP/FQDN identity, RFC
     1035 label and 254-octet rootless-name boundaries, Circuit-ID, and
     truncation. As an Extendable IE it ignores unknown trailing fields and,
     per clause 7.7.8, ignores receive-side spare flag bits. Canonical encoding
     emits only the understood prefix with spare bits zero; raw-preserving
     message encoding retains accepted extension octets and spare bits.
   - Node Identifier (clause 8.107) decodes the one-octet-length-prefixed Node
     Name and Node Realm pair and detects a declared subfield length that runs
     past the end of the IE value, or an absent length octet.
     Both subfields stay byte-transparent: clause 8.107 states no charset and
     delegates to Diameter Identity, whose ASCII constraint binds the sender.
     Either subfield may be empty, because clause 8.107 requires a non-zero
     length only for its SGSN Identifier and MME Identifier cases and the
     encoding carries no discriminator distinguishing them from the 3GPP AAA
     Server Identifier case this profile receives. As an Extendable IE it
     ignores the Figure 8.107-1 `(q+1) to (n+4)` octets per clause 8.1;
     canonical encoding emits only the understood prefix with the IE spare
     nibble zero, and raw-preserving message encoding retains both. The
     validated `NodeIdentifier::new` constructor bounds each subfield to the
     255 octets its length field can express, so encoding is infallible and
     performs no truncating cast.
   - A malformed Node Identifier is discarded, not rejected, by the *profiled
     receiver* — `S2bMessage::decode` and `S2bMessage::decode_with_diagnostics`
     — per clauses 7.7.7 and 7.7.8. Both clauses split receiver behaviour on
     the IE's *presence*.
     Clause 7.7.7 governs a length inconsistency in an Extendable IE: "If the
     received value of the Length field and the actual length of the extendable
     length IE are consistent, but the length is less than the number of fixed
     octets defined for that IE, preceding the extended field(s), this shall be
     considered an error, IE shall be discarded and if the IE was received as a
     Mandatory IE or a verifiable Conditional IE in a Request message, an
     appropriate error response with Cause IE value set to "Invalid length"
     together with the type and instance of the offending IE shall be returned
     to the sender." Clause 7.7.8 governs the optional case: the receiver
     "shall discard this IE, but shall treat the rest of the message as if this
     IE was absent and continue processing", and "All semantically incorrect
     optional information elements in a GTP signalling message shall be treated
     as not present in the message." Table 7.2.1-1 lists Node Identifier with
     presence O, so the receiver rule is discard-and-continue and the "Invalid
     length" response clause 7.7.7 names is not owed. Cause, F-TEID, PAA, EBI,
     Bearer Context, and the other typed IEs that are Mandatory or Conditional
     where this profile receives them continue to fail the decode, which is the
     same two clauses applied to the other side of the same split;
     `error_response` remains the layer at which a caller turns such a failure
     into a Cause.
   - This is what the crate's own written selection rule picks. `pco.rs`
     states it: "TS 24.008 10.5.6.3 is explicit that a container whose contents
     length is not two 'shall be ignored by the receiver', so a malformed
     instance is skipped rather than rejecting the whole value. That is
     deliberately unlike the address containers, for which the specification
     states no such rule and this codec fails closed." Clauses 7.7.7 and 7.7.8
     do state such a rule and do name the receiver, so IE 176 belongs in the
     skip bucket and is in it.
   - The discard is uniform across the profiled receive path. It holds at every
     validation level (`Structural`, `Strict`, `ProcedureAware`), in every
     message type this crate models, at every instance 0-15, and nested inside a
     Bearer Context. At `ProcedureAware` an instance other than 0 is discarded
     even earlier, by the clause 7.7.9 receive filter, so both routes reach the
     same result. `Strict` is not an opt-in stricter-than-TS-29.274 mode: it
     enforces "field cardinality, enum ranges, and critical IE rules", and for
     an optional IE clause 7.7.8 *is* the range rule and it says discard.
   - It is deliberately *not* uniform across the whole decode surface, because
     the disposition is not a property of the IE type alone. Both clauses
     condition it on the IE's presence at the slot it arrived in, which is a
     property of the procedure, the direction and the message grammar. The
     profile-less entry points `decode_typed_ie_sequence` and
     `TypedIe::decode_sequence` receive none of those — their whole input is
     `(input, ctx, depth)` and `(input, ctx)` — so they cannot establish the
     condition and are not entitled to the disposition. They fail closed and
     return the error instead. Callers wanting clause 7.7.8 behaviour must go
     through the profiled receiver above.
   - Discard means the IE is absent from the typed view *and* from the clause
     7.7.10 duplicate bookkeeping. "Treat the rest of the message as if this IE
     was absent" is a statement about the whole remaining decode, not only
     about the returned sequence: a discarded IE does not occupy its
     `(type, instance)` slot, so a later well-formed IE at the same key is
     still decoded and is not counted as a repeat, and repeated malformed IEs
     at one key are repeated discards rather than a duplicate. This holds under
     every `DecodeContext::duplicate_ie_policy`, including the `Reject` that
     `DecodeContext::conservative()` selects. Instance 0 is where it matters,
     being the only instance Table 7.2.1-1 lists for the 3GPP AAA Server
     Identifier and therefore the only key at which a spliced malformed IE can
     collide with a genuine one.
   - This is close to, but not identical with, a clause 7.7.9 instance discard.
     The clause 7.7.9 receive filter drops the IE before duplicate handling is
     reached at all; the clause 7.7.8 discard is applied after it, once the
     value has been attempted. The two therefore differ in exactly one case:
     when an interpretable occurrence has already been *retained* at a key, a
     second occurrence there is a genuine clause 7.7.10 repeat and the caller's
     `DuplicateIePolicy` governs it — `Reject` fails the message, `First`
     records `DuplicateIeEvidence`. That evidence describes the repetition,
     which the received message really contains. A discard at a key nothing has
     been retained at emits no diagnostic at all, and clause 7.7.8 requires no
     log for the optional case.
   - The received octets are untouched: the raw-preserving `Message` view and
     `EncodeContext { raw_preserving: true }` still reproduce the malformed IE
     byte-exact, which is now observable because the decode succeeds.
   - The rule is a *receiver* rule and is applied as one. Both clauses open on
     "the receiver of a GTP signalling message". The canonical builder's
     sender-side self-check (`S2bDecodePurpose::CanonicalBuilder`) therefore
     keeps rejecting: a caller-supplied raw IE 176 with a malformed value is a
     build failure, because the octets are already in the message being built
     and discarding the IE from the typed view would emit them anyway.
   - Top-level and grouped typed IE sequences enforce
     `DecodeContext::duplicate_ie_policy` by IE type and instance.
   - Unsupported/private/future IEs outside the typed subset are omitted,
     retained as byte-exact `TypedIeValue::Raw`, or rejected at top-level and
     grouped sequence boundaries according to `UnknownIePolicy`.

4. **S2b message views**
   - `S2bMessage` decodes Echo Request/Response, Create Session
     Request/Response, Modify Bearer Request/Response (the S2b UE-initiated
     IPsec tunnel-update view), Delete Session Request/Response, and the
     triggered Create, Update, and Delete Bearer Request/Response procedures.
   - `ValidationLevel::ProcedureAware` checks the required IE subset claimed
     by this crate's S2b examples: Echo Request/Response Recovery; Create
     Session Request IMSI or emergency MEI plus UIMSI Indication, followed by
     RAT Type/Serving Network/Sender F-TEID/APN/Selection Mode/PAA/Bearer
     Context with nested EBI; Create Session Response Cause/PGW S2b
     control F-TEID instance 1/Bearer Context; Modify request non-zero TEID and
     UDP-Port/local-IP conditional relationship; Delete Session request linked
     EBI; and response Cause IEs. Dedicated
     Create, Update, and Delete Bearer validation follows the stricter rules
     above.
   - Non-S2b message types fall back to the raw `Message` shell.

5. **Dedicated-bearer transaction helper**
   - `Gtpv2cTriggeredTransactions` accepts complete, procedure-aware Create,
     Update, and Delete Bearer requests and returns a generation-bound
     `Dispatch` only for their first observation.
   - An exact duplicate while application work is active returns `Pending`;
     after a correlated response is committed, it returns the exact retained
     bytes in `Replay` without re-running the application side effect.
   - Commit validates procedure, direction, message type, sequence number,
     required non-zero response TEID, message Cause, response form, every
     requested bearer, and PGW F-TEID correlation before retaining the
     response.
   - A pending timeout is never treated as permission to run the application
     side effect again. It returns `CancellationRequired` and consumes bounded
     capacity until the owner cancels or rolls back the exact work token and
     calls `acknowledge_cancellation`. A late commit from an older generation
     fails as stale after redispatch.
    - Conflicting identity reuse, invalid completion/Cause declarations,
      oversized retained bytes, capacity/generation exhaustion, and stale or
      timed-out work return stable redaction-safe errors. Sequence 0 and
      `0x00ff_ffff` are independent keys, so wrap does not alias active
      transactions.
    - `opc-proto-ikev2/examples/dedicated_bearer_sdk_flow.rs` composes this
      boundary with the real non-rekey IKEv2 Child-SA create/delete APIs. It
      commits the GTP response only after IKE response correlation and proves
      that a duplicate GTP request receives the exact cached response without
      repeating application work.

6. **Echo peer helper**
   - `Gtpv2cEchoPeer` tracks Echo request/response liveness, sequence mismatch,
     missed-response degradation/failure, peer Recovery restart-counter changes,
     and redaction-safe readiness blockers.
   - With `Gtpv2cEchoPeerPolicy::require_restart_reconciliation = true`, a
     changed Recovery restart counter enters `ReconciliationRequired` and
     `echo_request_sent` returns
     `Gtpv2cEchoPeerError::RestartReconciliationRequired` until the caller
     completes product reconciliation via `restart_reconciled()`.
   - With restart reconciliation disabled, restart-counter changes remain
     observable but do not fence Echo traffic.

7. **OpenPacketCore protocol framework fit**
   - `Message<'_>` implements `BorrowDecode`, `Encode`, and `ToOwnedPdu`.
   - `OwnedMessage` implements `OwnedDecode` and `Encode`.
   - `MessageType` provides a public typed message-type enum with
     `Unknown(u8)` fallback; raw and S2b message views expose conversion
     helpers without losing unsupported values.
   - `S2bMessage<'_>` and `S2bProcedureMessage<'_>` implement `Encode`, and
     `S2bMessage<'_>` implements `BorrowDecode`.
   - Decode errors use structured `opc-protocol` error types with spec refs.
   - `Debug` output for S2b typed message views redacts IMSI/MEI/MSISDN digits
     and summarizes raw IE buffers by length.

8. **Fixture and corpus replay**
   - `tests/fixtures/spec/` contains the ADR 0015 conformance fixtures for the
     S2b subset. The accompanying `tests/fixtures/README.md` records
     octet-level comments for each spec-authored fixture.
   - `tests/fixtures/independent/` has a metadata-enforced intake harness but is
     intentionally empty except for a README; no independent GTPv2-C capture is
     claimed until capture provenance, license/permission, implementation
     version, redaction status, and expected re-encode behavior are documented.
   - `tests/fixtures/epdg-parity/` contains parity/regression bytes only. These
     inputs exercise raw/private IE preservation but are not counted as
     conformance evidence.
   - `tests/fixtures/malformed/` contains synthetic hostile inputs for
     truncation, declared-length overrun, strict spare-bit rejection,
     grouped-IE recursion-depth rejection, and low-limit IE-count paths.
   - `tests/corpus_replay.rs` replays fixture and fuzz corpora through raw
     decode, owned decode, strict/procedure-aware decode, typed S2b decode,
     IE iteration, raw-preserving encode, and truncation/adversarial no-panic
     checks.

9. **Fuzz shell**
   - `fuzz/Cargo.toml`, `fuzz/fuzz_targets/decode_message.rs`,
     `fuzz/fuzz_targets/decode_s2b.rs`,
     `fuzz/fuzz_targets/error_response_plans.rs`, and
     `fuzz/fuzz_targets/roundtrip.rs` compile decode, typed S2b, owned-decode,
     IE-iteration, reply-safe error planning/encoding, and raw-preserving
     round-trip surfaces under cargo-fuzz.
   - `fuzz/corpus/decode_message/`, `fuzz/corpus/decode_s2b/`,
     `fuzz/corpus/error_response_plans/`, and `fuzz/corpus/roundtrip/` are the
     target-specific seed directories used by cargo-fuzz when the workflow
     runs `cargo +nightly fuzz run "$target"` without explicit corpus
     arguments. Each directory contains a flat, provenance-prefixed mirror of
     the committed spec, ePDG-parity, and malformed seed files.
   - `decode_s2b` additionally accepts bounded, reviewable `hex:` seeds. Its
     session-context seeds cover typed Create/Delete conditional context and
     its exact endpoint/location/release instances; tunnel-update seeds cover
     accepted TWAN/Port/Timestamp extension suffixes, ignored TWAN spare flags,
     ePDG overload-control instance 2, and a flag-directed TWAN truncation
     boundary. Ordinary fuzz inputs stay raw.
   - Two legacy flat seeds, `fuzz/corpus/echo_request` and
     `fuzz/corpus/create_session_shell`, remain at the corpus root for backward
     compatibility and are replayed by the never-panic corpus test.
   - The repository fuzz workflow includes this crate in its scheduled matrix.

## Explicitly out of scope

- A full Release 18 GTPv2-C implementation or a complete S2b IE/procedure
  matrix beyond the typed subset listed above.
- The non-S2b Node Identifier roles. Clause 8.107 also defines SGSN Identifier,
  MME Identifier, and SCEF/IWK-SCEF forms, which TS 29.274 lists only in the
  clause 7.3 S3/S10/S16 mobility tables. This profile models none of those
  messages, so procedure-aware receive, and the three request builders that
  gate `additional_ies` on the same disposition, admit Node Identifier at
  Create Session Request instance 0 only. The response builders gate nothing:
  they validate under `S2bDecodePurpose::CanonicalBuilder`, which skips the
  clause 7.7.9 receive filter, so a caller-supplied raw IE 176 still encodes on
  a response at any instance even though this crate's own procedure-aware
  receiver discards it. That looseness is pre-existing and applies equally to
  every other known IE. This profile also does not enforce the non-zero-length
  rule the SGSN and MME roles carry.
- Product bearer admission, EBI/TEID/SPI allocation, Child-SA/XFRM/eBPF
  programming, crash-persistent transaction storage, charging/QoS policy, and
  UDP transport remain outside this codec/transaction boundary.
- GTPv1-C, GTP-U, Diameter, S1AP, PMIP, or a production ePDG/PGW control plane.
- Claims of carrier acceptance or interoperability beyond this production
  profile boundary until independent, licensed captures exist.

## Canonicalization policy

Raw-preserving encoding keeps decoded header ignored/spare bits and raw IE
bytes while emitting the selected typed Message Priority. Canonical encoding
recomputes the Length field, emits version 2 with the typed MP flag/priority and
header and IE spare bits zeroed, encodes TBCD/APN/PLMN/PAA/F-TEID/Bearer QoS
fields in canonical form, emits typed charging, trace, endpoint, location, and
Diameter/IKEv2 release values at their procedure-owned instances, and
preserves opaque PCO/APCO/Indication bytes. It carries unsupported IEs through
the raw fallback only when the typed decode policy retained them.
Use the raw `Message` layer or `EncodeContext { raw_preserving: true, .. }` on a
freshly decoded S2b view for byte-exact forwarding.

## Fixture provenance

The committed fixture corpus is split by provenance class:

- **Spec-authored conformance fixtures** live in `tests/fixtures/spec/`. They
  are hand-authored from the TS 29.274 common-header and IE TLIV layouts and
  are the only GTPv2-C fixtures currently counted as conformance evidence:
  - Echo Request without TEID validates the no-TEID common-header shape and
    mandatory Recovery IE.
  - Create Session Request with the T flag and TEID 0 validates mandatory S2b
    request examples: IMSI, RAT Type, Serving Network, S2b ePDG control-plane
    F-TEID, APN, Selection Mode, PAA (without top-level PDN Type), Bearer Context/EBI, nested
    S2b-U ePDG F-TEID and Bearer QoS, Indication, APCO, and raw fallback for a
    correctly framed extended IE type.
  - Five compact Create Session Request fixtures independently cover dynamic
    IPv4, dynamic IPv6, dynamic IPv4v6, Non-IP, and Ethernet PAA encodings;
    the full request fixture covers AAA-static IPv4. All omit IE 99.
  - `tests/s2b_session_context.rs` adds specification-authored exact octets for
    Charging Characteristics, Trace Information, and Diameter/IKEv2 RAN/NAS
    Cause, plus table-driven Create combinations for normal/roaming,
    NAT/no-NAT, dynamic/static PAA, UICC-less emergency, AAA MSISDN,
    location, charging, and trace. Delete combinations cover release-cause
    families, UDP/TCP/no-NAT endpoints, and location presence. Negative tests
    cover wrong instances, missing endpoint dependencies, additional-IE
    bypass, bounded malformed values, unknown-option preservation, and Debug
    redaction.
  - Create Session Response with TEID validates response Cause, PGW S2b
    control-plane F-TEID instance 1/interface type 32, PAA, and Bearer Context
    examples.
  - `tests/s2b_tunnel_update.rs` contains independent spec-authored bytes for
    all WLAN-location/timestamp presence combinations and both Fixed Broadband
    endpoint forms. It also covers exact instances, the optional ePDG Overload
    Control Information instance 2, every typed TWAN field, each flag-directed
    truncation boundary, the 254/255-octet rootless FQDN boundary, fixed and
    Extendable IE lengths, ignored TWAN spare flags, canonical extension
    stripping, raw-preserving extension retention, first-occurrence receive,
    unexpected Bearer Context discard, Cause projection, and request/response
    transaction success, rejection, loss/retry, and duplicate receive. The
    retained legacy Modify Bearer fixture is explicit clause 7.7.9 discard
    evidence; raw-preserving encode remains byte-exact while canonical encode
    omits its non-S2b Bearer Context. The Delete Session request fixture carries
    linked EBI plus mandatory S2b UE Local IP instance 0.
  - Create Bearer Request validates linked EBI instance 0 plus a grouped
    request EBI value 0, canonical Bearer TFT, Bearer QoS, S2b-U PGW F-TEID
    instance 4/interface 33, and Charging ID.
  - Create Bearer Response validates message/bearer Cause hierarchy, allocated
    EBI, S2b-U ePDG F-TEID instance 8/interface 31, and correlated PGW F-TEID
    instance 9/interface 33.
  - Update Bearer Request validates mandatory APN-AMBR plus a grouped EBI
    carrying a TFT change; Update Bearer Response validates mandatory
    message-level and grouped per-bearer Causes.
  - Delete Bearer Request validates repeated dedicated EBI instance-1 targets;
    Delete Bearer Response validates a partially accepted grouped result for
    every request EBI.
  - `error_response_plans/*.hex` records independent hand-authored input and
    expected-output octets for Version Not Supported, message/IE Invalid
    Length, Context Not Found, missing/incorrect IE, Echo special handling,
    and silent-discard cases. Tests parse these text fixtures and compare the
    exact planned bytes rather than accepting codec round trips as evidence.

- **Independent-capture fixtures** live in `tests/fixtures/independent/` once
  available. The replay harness requires a finalized metadata sidecar before any
  `.bin` capture can land. None are committed yet, so this crate makes no
  independent-peer interoperability claim.
- **ePDG parity fixtures** live in `tests/fixtures/epdg-parity/`. They are
  regression seeds for raw/private IE and piggybacking preservation only. They
  are not spec-authored, not independently captured, and must not be cited as
  SDK wire-format conformance evidence.
- **Synthetic malformed fixtures** live in `tests/fixtures/malformed/`; they
  exercise hostile-input no-panic behavior and expected structured rejection,
  including low-limit grouped Bearer Context recursion-depth rejection.
- The fuzz seed corpus keeps provenance source directories under
  `fuzz/corpus/spec/`, `fuzz/corpus/epdg-parity/`, and
  `fuzz/corpus/malformed/`. Because cargo-fuzz uses one corpus directory per
  target by default, the same seed bytes are also copied into
  `fuzz/corpus/decode_message/`, `fuzz/corpus/decode_s2b/`,
  `fuzz/corpus/error_response_plans/`, and `fuzz/corpus/roundtrip/` using names like
  `spec__echo_request_recovery.bin`. Scheduled fuzzing therefore starts each
  registered target from the same S2b conformance, parity, and malformed cases
  that `tests/corpus_replay.rs` replays deterministically; the replay test also
  asserts those target-specific mirrors match the provenance source bytes.

Header, raw IE, malformed-input, corpus-replay, and S2b integration tests under
`tests/` exercise strict Message Priority decoding across its full range,
MP/value inconsistency, canonical and raw-preserving spare-bit round trips,
multi-IE unknown TLIV preservation, truncation/count-limit errors,
prefix/malformed input no-panic regressions, typed decode → encode fixtures,
missing-mandatory-IE rejection, and malformed profile-critical F-TEID/PAA
rejection.

`examples/production_profile_v1.rs` exercises the downstream constructor path
for Echo, Create Session, S2b UE-initiated IPsec tunnel update, Delete Session,
and Update Bearer S2b
messages by performing typed construction → encode → decode → ProcedureAware
validation without manual raw byte assembly.

Future typed S2b expansion must add spec-authored fixtures for every newly
claimed message and IE, with octet-level comments and byte-exact decode → encode
tests per ADR 0015.
