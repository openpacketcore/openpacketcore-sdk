# Spec-compliance evidence and scope corrections

This accompanies [umbrella #1532](https://github.com/openpacketcore/openpacketcore-sdk/issues/1532).
It records findings whose requested
change differs from the applicable wire format or existing implementation.
It is not peer-review approval or a claim of complete protocol support.
The umbrella tracks implementation and qualification separately.

## Protocol codec work list #1356

| Finding | Verified behavior and disposition |
| --- | --- |
| TFT error causes | The shared TFT parser returns typed errors. GTPv2-C maps them at the protocol boundary in `bearer_tft_decode_error`, `dedicated_bearer_decode_rejection_cause`, and `DedicatedBearerError::request_rejection_cause`. The existing dedicated-bearer tests cover operation semantics and packet-filter syntax/semantics. Keep the reusable TFT parser independent of GTP-specific Cause values. |
| Extended Bearer QoS | GTPv2-C uses a 22-octet known prefix with four 40-bit rates in kbit/s. TS 24.008's NAS QoS extension bits are a different IE format. The existing codec ignores trailing extension octets and validates the rate bounds. Adding NAS bits to this GTP IE would corrupt the wire format. |
| NAS EEA/EIA suites | The cited `crates/opc-nas/src/security.rs` does not exist. `opc-proto-nas` is a 5GS codec with caller-owned algorithm selection, AES NIA2/NEA2 and explicit null algorithms; it does not implement an EPS UE/MME. TS 33.401 §§5.1.3.2/5.1.4.2 make EEA3/EIA3 optional, while requiring algorithms 1 and 2 in EPS UE/MME endpoints. TS 33.402 §13.3 concerns unauthenticated WLAN emergency calls, not a ZUC negotiation requirement. The missing provider is an explicitly unsupported feature, not a reproduced violation of the cited endpoint requirement. |
| TWAN identifiers | `SwmWlanSsid::try_new` enforces 1–32 UTF-8 octets. `SwmBasicServiceSetIdentifier::from_text` validates the 17-octet textual BSSID, its separators, hex digits, and address validity. The six-byte internal representation is encoded as the specified UTF8String, not a six-octet AVP. No missing decoder length check was reproduced. |
| TFT VLAN identifiers (folded #1364) | Keep the inclusive range 0–4095. TS 24.008 §10.5.6.12 assigns a 12-bit field to C-TAG and S-TAG VID and excludes neither endpoint at the TFT wire layer. The constructor and independent wire fixtures admit 0 and 4095; values above 4095 remain invalid. VLAN assignment policy at other layers does not narrow this wire field. |

Sources: [TS 29.274 §8.15](https://www.etsi.org/deliver/etsi_ts/129200_129299/129274/19.06.00_60/ts_129274v190600p.pdf),
[TS 29.273 §5.2.3.22](https://www.etsi.org/deliver/etsi_ts/129200_129299/129273/18.06.00_60/ts_129273v180600p.pdf),
and [TS 32.299 §7.2.30A](https://www.etsi.org/deliver/etsi_ts/132200_132299/132299/18.00.00_60/ts_132299v180000p.pdf).
The TFT format is defined by
[TS 24.008 V18.6.0 §10.5.6.12](https://www.etsi.org/deliver/etsi_ts/124000_124099/124008/18.06.00_60/ts_124008v180600p.pdf).
The issue's TS 24.302 §7.4.3.1 citation describes ePDG-initiated disconnection,
not TFT encoding.

Code and regression witnesses:

- [GTP TFT error mapping](../crates/opc-proto-gtpv2c/src/ie/typed.rs),
  [dedicated-bearer protocol causes](../crates/opc-proto-gtpv2c/src/dedicated_bearer.rs),
  and [dedicated-bearer tests](../crates/opc-proto-gtpv2c/tests/dedicated_bearer.rs).
- [TWAN value validation](../crates/opc-proto-diameter/src/apps/swm/location.rs)
  and [wire/constructor regression tests](../crates/opc-proto-diameter/tests/swm_diameter_eap_location.rs),
  including `malformed_child_vendor_flags_cardinality_and_values_fail_closed`,
  `common_bssid_spellings_are_accepted_and_canonicalized`, and
  `public_constructors_enforce_bounds_without_value_bearing_errors`.
- [NAS conformance and provider scope](../crates/opc-proto-nas/CONFORMANCE.md).
- [TFT VID boundary fixtures](../crates/opc-proto-tft/tests/tft_codec.rs),
  `vlan_identifier_wire_boundaries_include_zero_and_all_twelve_bits`.

GTPv2-C and Diameter codec tests do not qualify absent NAS providers.

The NAS disposition was checked against
[TS 33.401 V18.0.0 §§5.1.3.2/5.1.4.2](https://www.etsi.org/deliver/etsi_ts/133400_133499/133401/18.00.00_60/ts_133401v180000p.pdf)
and [TS 33.402 V18.0.0 §13.3](https://www.etsi.org/deliver/etsi_ts/133400_133499/133402/18.00.00_60/ts_133402v180000p.pdf).
The existing `nas_aes` tests reject unsupported algorithms before key lookup;
the selected-algorithm codec retains their defined identifiers without
advertising cryptographic support. The AMF-lite crate is an integration fixture,
not an EPS MME or production AMF. A consuming endpoint must supply every
algorithm required by its own profile; the bundled AES provider alone is not
evidence of full endpoint conformance. No security fallback is introduced.
The four original #1356 claims and the folded #1364 item have the dispositions
above. They do not claim complete protocol or runtime qualification.

## PFCP/GTPv2-C work list #1359

The PFCP profile requires mandatory Node ID and permits incremental rule
references to existing session state. Existing GTPv2-C unknown-IE handling defaults to
preservation and offers explicit drop/reject policies; an optional unknown IE
does not abort the default receiver. The witnesses are
[unknown-IE policy tests](../crates/opc-proto-gtpv2c/tests/unknown_ie_policy.rs)
and [procedure receiver tests](../crates/opc-proto-gtpv2c/tests/s2b_receive_policy.rs),
including `procedure_families_discard_known_unexpected_types_and_preserve_unknown_optional_ies`.

The cited PFCP `src/runtime.rs` does not exist. The
[PFCP crate](../crates/opc-proto-pfcp/README.md) explicitly excludes UDP transport,
retransmission, and node lifecycle. Responding to a Heartbeat Request is not
an association supervision state machine. No timeout-state-machine repair is
claimed; implementing such a supervisor remains separate runtime work.

## 5GS interworking work list #1357

NGAP GTP transport addresses now preserve the 160-bit combined form through
uplink/downlink endpoints and nested Setup/Modify transfers. IPv4 occupies the
first 32 bits and IPv6 the remaining 128 bits, as specified by
[TS 38.414 §5.3](https://www.etsi.org/deliver/etsi_ts/138400_138499/138414/18.00.00_60/ts_138414v180000p.pdf)
and referenced by
[TS 38.413 §9.3.2.4](https://www.etsi.org/deliver/etsi_ts/138400_138499/138413/18.02.00_60/ts_138413v180200p.pdf).
The address getter now returns an enum retaining both families. Selecting a
reachable, authorized endpoint remains the caller's decision.

The reported MOBIKE file does not exist. The actual `nwu::mobike` receiver
already accepts IPv6-only outer paths. Its existing
`nat_prohibition_binds_both_addresses_and_ports_for_ipv4_and_ipv6` test performs
an authenticated UPDATE and COOKIE2 exchange over two IPv6 endpoints, verifies
the resulting migration path, and rejects altered addresses/ports. It passes
without a production change.

The IPv4 condition in `ConfigurationReply::new` applies to the requested
**inner** configuration family, not the outer MOBIKE path. The N3IWF reply rule
in [TS 24.502 V18.5.0, page 53](https://www.etsi.org/deliver/etsi_ts/124500_124599/124502/18.05.00_60/ts_124502v180500p.pdf)
conditions MOBIKE advertisement on the initial IPv4 configuration attribute.
The existing configuration-family matrix tests that rule. Removing it would
change the NWu profile rather than fix IPv6 outer transport. Neither test
claims live-peer or kernel migration qualification.

## IP foundations work list #1360

| Finding | Verified behavior and disposition |
| --- | --- |
| IPCP DNS options | `opc-proto-gtpv2c::pco` already parses options 129/131, correlates Configure-Nak identifiers and requested options, and exposes primary/secondary DNS. The PCO regressions cover independent literal replies, unsolicited options, stale identifiers and unit-local malformed-input handling. |
| Raw IPv4 checksum | Injection accepts validated packets rather than assembling a zero-checksum header. `Header::parse` calls `valid_ipv4_header`, which rejects an incorrect checksum; the fragmenter and ICMP builders compute new checksums. Linux raw `IP_HDRINCL` also fills the checksum. `whole_batch_is_validated_before_its_first_send` proves a corrupted fragment prevents any send. No missing checksum computation was reproduced. |
| IPv6 fragment cache cleanup | The cited `model.rs` location has no fragment cache or timer. Outer reassembly belongs to the Linux kernel; the SDK does not own the reported IPv6 reassembly cache. Inner fragments are handled by the documented forwarding profile. No cache-expiry repair is claimed, and this disposition does not qualify full IPv6 outer reassembly. |
| NAI SASLprep | RFC 7542 does not prescribe SASLprep in a Diameter AVP parser. It assigns normalization primarily to the edge with locale information and cautions AAA intermediaries against normalization. Preserve the received identity bytes; automatic parser rewriting could break exact EAP/User-Name correlation. |
| DNS hostname syntax | Address queries validate RFC 1123 hostnames while SRV/S-NAPTR service-owner syntax remains separate (#1355). |
| ICMP quote length | The IPv4 PTB builder already quotes the IPv4 header plus eight payload octets; `icmpv4_ptb_matches_rfc1191_layout_and_verifies_checksums` verifies the exact quote and both checksums. IPv6 uses its separate minimum-MTU quote rule. Moreover, RFC 1812 §4.3.2.3 recommends retaining more original IPv4 data within a 576-byte response; eight octets are not a universal maximum. |
| IPv6 scope ID | The cited `opc-net-util` crate does not exist. The SCTP socket boundary already copies `scope_id` into native `sin6_scope_id` and restores it on readback. The new `link_local_scopes_survive_raw_and_packed_addresses` regression verifies three nonzero scope values, including `u32::MAX`, against literal packed offsets and native byte order. No production change is needed for this address conversion. The session TCP helper passes the complete `SocketAddr` to Tokio. |

Witnesses: [PCO tests](../crates/opc-proto-gtpv2c/tests/pco.rs),
[injection validation](../crates/opc-gtpu-dataplane/src/injection.rs),
[shared IPv4 header validator](../crates/opc-gtpu-dataplane/src/inner_fragment.rs),
[reassembly ownership](../crates/opc-gtpu-dataplane/src/reassembly.rs),
[ICMP builders/tests](../crates/opc-gtpu-dataplane/src/icmp.rs),
[SCTP native address conversion/tests](../crates/opc-libsctp-sys/src/linux.rs),
and [TCP connect helper](../crates/opc-session-net/src/scope/socket.rs).

Standards: [RFC 1877](https://www.rfc-editor.org/rfc/rfc1877.html),
[Linux raw socket checksum behavior](https://www.man7.org/linux/man-pages/man7/raw.7.html),
[RFC 7542 §2.6](https://www.rfc-editor.org/rfc/rfc7542.html#section-2.6),
[RFC 1812 §4.3.2.3](https://www.rfc-editor.org/rfc/rfc1812.html#section-4.3.2.3),
and [RFC 4007 §6](https://www.rfc-editor.org/rfc/rfc4007.html#section-6).

## Management work list (#1363): gNMI subscription behavior

`TARGET_DEFINED` now selects configuration events and operational samples
within the same subtree, using the existing schema-backed path selector and
Subscribe authorization. Zero `SAMPLE` intervals use the server minimum.
Sampling, heartbeat and suppression settings remain local to each subscription;
an ON_CHANGE heartbeat does not require `suppress_redundant`. One initial
authorized observation seeds every schedule, preserving overlapping-path
deduplication and changes arriving during initialization.

The runtime regressions in
[target_defined.rs](../crates/opc-gnmi-server/src/service/tests/target_defined.rs)
check mixed delivery, keyed prefixes, Subscribe-versus-Read authorization,
zero intervals, independent cadences/suppression and heartbeats. ON_CHANGE and
TARGET_DEFINED emit explicit deletes for removed nodes, including the last
selected entry. Changed observations compare individual leaves; SAMPLE with
`suppress_redundant` omits unchanged leaves. Heartbeats refresh the current
observation. Partial notifications are non-atomic. Pending authorization updates
do not turn a temporarily unavailable observation into deletion notifications.
The malformed-first-request metric regression runs in a dedicated test process
so concurrent successful subscriptions cannot alter its exact global-counter
assertion.

Specification: [gNMI 0.10.0 §3.5.1.5.2](https://github.com/openconfig/reference/blob/master/rpc/gnmi/gnmi-specification.md#35152-stream-subscriptions).

## Management work list (#1363): YANG cardinality and NETCONF evidence

YANG `mandatory`, `min-elements` and `max-elements` are now retained in the IR,
validated during source ingestion and Rust generation, bound into the schema
digest, and enforced by generated configuration validation. The compiled
[cardinality fixture](../crates/opc-yanggen/tests/fixtures/cardinality_test.rs)
checks absent non-presence containers, inactive presence containers, per-entry
requirements, zero-valued mandatory booleans, sensitive leaf-lists and both
cardinality boundaries. All four runtime tests failed before the fix.
Source/IR regressions additionally check malformed statements, round trips,
source mismatch and digest changes. Partial patches and ConfigDelta replay check scalar constraints and leaf-list
uniqueness without demanding complete-configuration cardinality at each step.
The completed candidate still undergoes full validation. The
[partial-patch fixture](../crates/opc-yanggen/tests/fixtures/cardinality_patch_test.rs)
checks mandatory siblings, scalar bounds, duplicate values and atomic refusal.
Sensitive leaves remain covered by generated runtime checks. A sensitive
container or list is rejected by the generator's supported-input contract before
code emission; that unsupported input cannot produce the reported missing
`SecretLeaf::get()` call. RFC 7950 §6.3.1 leaves extension processing to the
extension's defined contract. The generator tests preserve this rejection and
compile the supported sensitive-leaf forms.

The remaining non-decimal reports were checked against current code:

| Report | Disposition and evidence |
| --- | --- |
| Unbounded revision index | `source::parse_module` retains one module revision (the first declaration) and the source text used for get-schema. It has no accumulating revision index. RFC 8525 §3 describes the served YANG library and does not mandate the claimed history-retention ceiling. No revision-retention feature is introduced. |
| Missing edit-config operations | Parsing already recognized the operations, but generated existence checks were incomplete. Creating an existing scalar, secret leaf, presence container, keyed-list entry or leaf-list value now reports `data-exists`; deleting an absent node reports `data-missing`. Removing an absent node remains idempotent. Generated-applicator and real RPC regressions cover running, candidate and startup datastores and verify rejected edits do not publish a change. The cited `operations/edit_config.rs` does not exist. |
| Missing notification subscription | `create_subscription_starts_live_config_change_notifications` exercises the real session, subscription RPC, configuration change and delivered notification. `notification_subscription_installs_retained_byte_budget` verifies bounded retention. These pass with the existing binding; replay and filter shapes remain explicitly unsupported by the advertised profile. |
| Missing get-schema/session inventory | The existing monitoring binding serves `/netconf-state` and get-schema, with positive, authorization, absent/ambiguous module, provider-error and size-limit tests. `get_schema_returns_schema_content_when_monitoring_and_nacm_allow` passes. This operation is specified by RFC 6022 §3.1, not RFC 8525 §4. |
| Boolean exactness | Generated JSON uses Rust `bool`; the new fixture verifies `false` is a present valid value while strings, numbers and absent required values are rejected. NETCONF scalar parsers also use the exact boolean parser. |

Retained-storage tests require private disk-backed temporary directories and
`umask 0077`; these admission requirements remain enforced. The decimal64
correction and its verification are described below.

Witnesses: [edit parser](../crates/opc-netconf-server/src/edit_xml.rs),
[server and tests](../crates/opc-netconf-server/src/server.rs),
[source ingestion](../crates/opc-yanggen/src/source.rs),
[RFC 7950 §§7.6.5 and 7.7.5–7.7.6](https://www.rfc-editor.org/rfc/rfc7950.html#section-7.6.5),
[RFC 6241 §7.2](https://www.rfc-editor.org/rfc/rfc6241.html#section-7.2),
[RFC 6022 §3.1](https://www.rfc-editor.org/rfc/rfc6022.html#section-3.1),
[RFC 5277 §2.1.1](https://www.rfc-editor.org/rfc/rfc5277.html#section-2.1.1),
and [RFC 8525 §3](https://www.rfc-editor.org/rfc/rfc8525.html#section-3).

## Management work list (#1363): exact decimal64

`fraction-digits` is now mandatory, unique and retained in source IR and runtime
metadata. Generated `YangDecimal64<F>` stores a signed 64-bit coefficient; the
shared parser rejects unsupported syntax, non-finite numbers, precision loss
and values beyond the declared scale. Canonical output retains all significant
digits and uses `0.0` for zero. JSON requires a string. Redundant fractional
zeros are valid when they do not change the represented value.

The compiled [decimal fixture](../crates/opc-yanggen/tests/fixtures/decimal64_test.rs)
checks literal large adjacent values, both domain endpoints, 18 fractional
digits, canonical zero, defaults, chained leafrefs, list/leaf-list identity,
JSON, XML, gNMI, patches and value-free errors for secret fields. Baseline
runtime tests demonstrated that `900719925474099.21` became
`900719925474099.3` and `9.223372036854775807` lost its last digits. Decimal
leafrefs and list-key patches also exposed generated-code compilation failures;
the corrected types and parsers compile and preserve distinct values. The
shared parser tests every declared scale at signed coefficient boundaries.

XPath comparisons intentionally retain the IEEE 754 number semantics required
by RFC 7950 §6.4. That conversion is confined to evaluation and never modifies
the stored value. Public constraint IR is exercised with both path and
`current()` operands. Source-level must/when lowering and decimal range
restrictions remain explicitly unsupported by the existing generator profile;
this change does not silently accept or discard those restrictions.

Default-omission tests also found that NETCONF trim retained explicit values
equal to their schema default. Both ordinary and bounded subtree projection
now apply value-based omission, with exact decimal comparison. Existing
authorization assertions are preserved using a non-default boolean fixture;
separate tests check trim and explicit reporting of the same default value.

All 78 generated-file pins were first reproduced before the #1363 decimal64 correction.
Only the decimal codec/type/scale-digest changes and RFC 6243 trim changes
appeared in the reviewed generated output; the complete-file assertions remain.
The subsequent RFC 6241 correction reverified all 78 current pins and changed
only the six `netconf_xml_edit.rs` entries, for typed existence errors and
absent-container deletion. The partial-patch fix does not affect these six
models. Every generated file remains covered by its full-file assertion.
The old proof that accepted subnormal/exponent/NaN/infinite float values is
replaced by exact-domain round trips and explicit refusal assertions. Public
IR, metadata and generated-type migrations are documented in the changelog.

Witnesses: [exact scalar](../crates/opc-mgmt-schema/src/decimal64.rs),
[source and IR tests](../crates/opc-yanggen/tests/scalars_and_names/decimal.rs),
[RFC 7950 §§9.3–9.3.4](https://www.rfc-editor.org/rfc/rfc7950.html#section-9.3),
[RFC 7950 §6.4](https://www.rfc-editor.org/rfc/rfc7950.html#section-6.4),
[RFC 7951 §6.1](https://www.rfc-editor.org/rfc/rfc7951.html#section-6.1), and
[RFC 6243 §3.2](https://www.rfc-editor.org/rfc/rfc6243.html#section-3.2).


## DNS/peer-discovery work list #1355

The DNS cache retains stale positive answers only until its configured maximum
stale deadline; once that deadline passes it exposes neither the expired answer
nor a usable freshness deadline. UDP truncation triggers TCP fallback with
length framing and response correlation checks. TCP connections are bounded and
reused for query bursts, with a one-second idle limit. The unnegotiated idle
reuse is an explicit deviation from RFC 7766 §6.2.3's idle-close recommendation;
EDNS TCP keepalive negotiation remains unsupported. The high-bit TTL policy is
also explicitly conservative: such TTLs are treated as zero rather than adopting
RFC 8767's full unsigned TTL domain.

Witnesses: [DNS wire tests](../crates/opc-peer-discovery/tests/dns_client.rs),
[cache contracts](../crates/opc-peer-discovery/tests/dns_contracts.rs), and
[SRV provenance tests](../crates/opc-peer-discovery/tests/dns_srv.rs). The SRV mode
negative uses a valid service owner and matching transport so it isolates the
query-mode check. See the [supported DNS profile](../crates/opc-peer-discovery/README.md)
for the remaining serialized-query timeout limitation.

Sources: [RFC 8767 §4](https://www.rfc-editor.org/rfc/rfc8767.html#section-4)
and [RFC 7766 §§6.2.1–6.2.3](https://www.rfc-editor.org/rfc/rfc7766.html#section-6.2.1).

## Charging and policy work list #1361

| Finding | Verified behavior and disposition |
| --- | --- |
| ARP polarity | The shared ARP type already treats priority 1 as highest and 15 as lowest. The GTPv2-C `arp_priority_polarity` and `bearer_qos` tests cover wire values and domain comparison independently of preemption flags. Do not invert the four-bit wire field. |
| Rf Service-Information | ACR supports the grouped Service-Information and optional PS-Information. The grammar does not require PS-Information in every ACR. Subscription-Id, SGSN/GGSN addresses and Service-Data-Container retain their specified multiplicity; conservative dictionary validation accepts those repetitions and rejects duplicate singleton fields. |
| RADIUS-derived AVPs in Rf | 3GPP-Charging-Id and 3GPP-PDP-Type use vendor 10415 and set M, as required by TS 32.299 §7.2.0. The literal fixture uses flags `0xC0`, and independent encoding assertions check both AVPs. The Gi/SGi table in TS 29.061 does not govern this Rf encoding. |
| Interim accounting | The existing AccountingRecordType::Interim encoding remains supported. This codec does not schedule a charging session or enforce operator charging policy. |

Witnesses: [Rf codec and dictionary](../crates/opc-proto-diameter/src/apps/rf.rs),
[independent wire and cardinality tests](../crates/opc-proto-diameter/tests/app_dictionaries.rs),
and [ARP tests](../crates/opc-proto-gtpv2c/tests/arp_priority_polarity.rs).
The Rf rules come from [TS 32.299 V18.0.0 §§7.2.0, 7.2.158 and 7.2.192](https://www.etsi.org/deliver/etsi_ts/132200_132299/132299/18.00.00_60/ts_132299v180000p.pdf).
Emergency-service admission remains the consuming endpoint's responsibility;
this change does not alter emergency behavior.

## SBI/NRF/OAuth work list #1362

| Finding | Verified behavior and disposition |
| --- | --- |
| NRF registration and heartbeat | Registration includes the supported NF profile fields. A returned heartBeatTimer replaces the remembered interval; 204 and responses without that attribute retain it. Initial registration without a timer uses the documented default. |
| Discovery validity | Query encoding preserves the discovery parameters. Cache reuse is bounded by server validityPeriod. After a failed refresh the cache is looked up again, so an expired or invalidated entry cannot be returned through a saved stale snapshot. |
| Priority and extensible metadata | The `3gpp-Sbi-Message-Priority` header accepts 0–31 (TS 29.500 §5.2.3.2.2). NF status preserves CANARY_RELEASE and unknown string extensions instead of rejecting an otherwise usable profile. |
| Access-token claims | Explicit NRF token configuration accepts the producer NF type as a string or an audience UUID array containing the local producer instance. Signature, issuer/subject UUIDs, time, scope and peer binding remain checked. JWT-SVID retains its separate SPIFFE and audience policy. |
| OAuth response challenge | Trusted API URI and scope configuration supplies the realm on every challenge and scope on insufficient-scope responses. Malformed Bearer credentials receive 401 with `error="invalid_token"` (TS 29.500 §6.7.3); duplicate Authorization headers receive 400 with `error="invalid_request"` (RFC 6750 §3.1). Both include the configured API realm, never request header content. Protected paths without matching challenge configuration fail closed. Problem responses use application/problem+json. |
| HTTP transport and breaker | Cleartext defaults to port 80; TLS requires negotiated h2 and accepts IPv4/IPv6 address identities. Circuit-breaker failures remain scoped to transport/timeout and 5xx outcomes, rather than ordinary 4xx application responses. |
| Service identifiers and metadata URL | The SMF event exposure identifier is nsmf-event-exposure. The console design records RFC 8414 metadata discovery with the well-known component before the issuer path. |

Witnesses: [NRF wire/cache tests](../crates/opc-sbi/tests/nrf_wire.rs),
[token-profile tests](../crates/opc-sbi/tests/nrf_tokens.rs),
[SBI HTTP/TLS tests](../crates/opc-sbi/tests/sbi_integration.rs),
and [service identifiers](../crates/opc-sbi/src/nrf/services.rs).
Sources: [TS 29.510 V18.6.0 §§5.2.2.3.2, 5.3.2.2.1 and 6.3.5.2.4](https://www.etsi.org/deliver/etsi_ts/129500_129599/129510/18.06.00_60/ts_129510v180600p.pdf),
[TS 29.500 V18.6.0 §6.7.3](https://www.etsi.org/deliver/etsi_ts/129500_129599/129500/18.06.00_60/ts_129500v180600p.pdf),
[RFC 6750 §3](https://www.rfc-editor.org/rfc/rfc6750.html#section-3), and
[RFC 8414 §3](https://www.rfc-editor.org/rfc/rfc8414.html#section-3).
