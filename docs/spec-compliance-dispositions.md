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
| IPCP DNS options | `opc-proto-gtpv2c::pco` already parses options 129/131, correlates Configure-Nak identifiers and requested options, and exposes primary/secondary DNS. All 56 PCO tests pass, including independent literal replies, unsolicited options, stale identifiers and unit-local malformed-input handling. |
| Raw IPv4 checksum | Injection accepts validated packets rather than assembling a zero-checksum header. `Header::parse` calls `valid_ipv4_header`, which rejects an incorrect checksum; the fragmenter and ICMP builders compute new checksums. Linux raw `IP_HDRINCL` also fills the checksum. `whole_batch_is_validated_before_its_first_send` proves a corrupted fragment prevents any send. No missing checksum computation was reproduced. |
| IPv6 fragment cache cleanup | The cited `model.rs` location has no fragment cache or timer. Outer reassembly belongs to the Linux kernel; the SDK does not own the reported IPv6 reassembly cache. Inner fragments are handled by the documented forwarding profile. No cache-expiry repair is claimed, and this disposition does not qualify full IPv6 outer reassembly. |
| NAI SASLprep | RFC 7542 does not prescribe SASLprep in a Diameter AVP parser. It assigns normalization primarily to the edge with locale information and cautions AAA intermediaries against normalization. Preserve the received identity bytes; automatic parser rewriting could break exact EAP/User-Name correlation. |
| DNS hostname syntax | Fixed in `b37d5cf84`: address queries validate RFC 1123 hostnames while SRV/S-NAPTR service-owner syntax remains separate. |
| ICMP quote length | The IPv4 PTB builder already quotes the IPv4 header plus eight payload octets; `icmpv4_ptb_matches_rfc1191_layout_and_verifies_checksums` verifies the exact quote and both checksums. IPv6 uses its separate minimum-MTU quote rule. Moreover, RFC 1812 §4.3.2.3 recommends retaining more original IPv4 data within a 576-byte response; eight octets are not a universal maximum. |
| IPv6 scope ID | The cited `opc-net-util` crate does not exist. The SCTP socket boundary already copies `scope_id` into native `sin6_scope_id` and restores it on readback. The new `link_local_scopes_survive_raw_and_packed_addresses` regression verifies three nonzero scope values, including `u32::MAX`, against literal packed offsets and native byte order. The 14 ordinary Linux sys-layer tests pass; no production change is needed. The session TCP helper passes the complete `SocketAddr` to Tokio. |

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

The six runtime regressions in
[target_defined.rs](../crates/opc-gnmi-server/src/service/tests/target_defined.rs)
check mixed delivery, keyed prefixes, Subscribe-versus-Read authorization,
zero intervals, independent cadences/suppression and heartbeats. The complete
Linux gNMI suite passes 274 tests, including 62 keyed-read/subscription tests
and seven retained-audit integration tests. These tests establish the scoped
subscription change; the YANG generation items in #1363 remain open.

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
source mismatch and digest changes. The complete generator suite and its
294-case generated-code lint/runtime matrix pass on Rust 1.99.1; unchanged
legacy artifacts retain their full-file digest pins.

The remaining non-decimal reports were checked against current code:

| Report | Disposition and evidence |
| --- | --- |
| Unbounded revision index | `source::parse_module` retains one module revision (the first declaration) and the source text used for get-schema. It has no accumulating revision index. RFC 8525 §3 describes the served YANG library and does not mandate the claimed history-retention ceiling. No revision-retention feature is introduced. |
| Missing edit-config operations | `edit_xml::parse_operation` already recognizes create, replace and delete, retains per-node operations and passes the parsed edit to the binding applicator. Generated applicators implement their existence and replacement semantics. The full server and generator suites pass. The cited `operations/edit_config.rs` does not exist. |
| Missing notification subscription | `create_subscription_starts_live_config_change_notifications` exercises the real session, subscription RPC, configuration change and delivered notification. `notification_subscription_installs_retained_byte_budget` verifies bounded retention. These pass with the existing binding; replay and filter shapes remain explicitly unsupported by the advertised profile. |
| Missing get-schema/session inventory | The existing monitoring binding serves `/netconf-state` and get-schema, with positive, authorization, absent/ambiguous module, provider-error and size-limit tests. `get_schema_returns_schema_content_when_monitoring_and_nacm_allow` passes. This operation is specified by RFC 6022 §3.1, not RFC 8525 §4. |
| Boolean exactness | Generated JSON uses Rust `bool`; the new fixture verifies `false` is a present valid value while strings, numbers and absent required values are rejected. NETCONF scalar parsers also use the exact boolean parser. |

The complete Linux NETCONF run passes 533 tests, including retained-audit
recovery and process-loss cases. It runs with `umask 0077` so the test directories
satisfy retained-storage admission; the initial group-writable VM directories
were correctly rejected. No production check or test assertion was relaxed.
Exact decimal64 representation remains in progress under #1363.

Witnesses: [edit parser](../crates/opc-netconf-server/src/edit_xml.rs),
[server and tests](../crates/opc-netconf-server/src/server.rs),
[source ingestion](../crates/opc-yanggen/src/source.rs),
[RFC 7950 §§7.6.5 and 7.7.5–7.7.6](https://www.rfc-editor.org/rfc/rfc7950.html#section-7.6.5),
[RFC 6022 §3.1](https://www.rfc-editor.org/rfc/rfc6022.html#section-3.1),
[RFC 5277 §2.1.1](https://www.rfc-editor.org/rfc/rfc5277.html#section-2.1.1),
and [RFC 8525 §3](https://www.rfc-editor.org/rfc/rfc8525.html#section-3).
