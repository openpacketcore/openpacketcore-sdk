# Spec-compliance evidence and scope corrections

This accompanies [umbrella #1532](https://github.com/openpacketcore/openpacketcore-sdk/issues/1532)
and the `compliance/spec-audit` branch. It records findings whose requested
change differs from the applicable wire format or existing implementation.
It is not peer-review approval or a claim of complete protocol support.
The umbrella tracks implementation and qualification separately.

## Protocol codec work list #1356

| Finding | Verified behavior and disposition |
| --- | --- |
| TFT error causes | The shared TFT parser returns typed errors. GTPv2-C maps them at the protocol boundary in `bearer_tft_decode_error`, `dedicated_bearer_decode_rejection_cause`, and `DedicatedBearerError::request_rejection_cause`. The existing dedicated-bearer tests cover operation semantics and packet-filter syntax/semantics. Keep the reusable TFT parser independent of GTP-specific Cause values. |
| Extended Bearer QoS | GTPv2-C uses a 22-octet known prefix with four 40-bit rates in kbit/s. TS 24.008's NAS QoS extension bits are a different IE format. Commit `00def1381` corrects receiver extension handling and pins the rate bounds. Adding NAS bits to this GTP IE would corrupt the wire format. |
| NAS EEA/EIA suites | The cited `crates/opc-nas/src/security.rs` does not exist. `opc-proto-nas` implements 5GS NAS, with AES NIA2/NEA2 and explicit null algorithms; its conformance document excludes EPS formats and SNOW 3G/ZUC providers. Naming NIA/NEA identifiers 1 and 3 does not implement those algorithms. Deployments requiring those providers still have a feature gap. |
| TWAN identifiers | `SwmWlanSsid::try_new` enforces 1–32 UTF-8 octets. `SwmBasicServiceSetIdentifier::from_text` validates the 17-octet textual BSSID, its separators, hex digits, and address validity. The six-byte internal representation is encoded as the specified UTF8String, not a six-octet AVP. No missing decoder length check was reproduced. |

Sources: [TS 29.274 §8.15](https://www.etsi.org/deliver/etsi_ts/129200_129299/129274/19.06.00_60/ts_129274v190600p.pdf),
[TS 29.273 §5.2.3.22](https://www.etsi.org/deliver/etsi_ts/129200_129299/129273/18.06.00_60/ts_129273v180600p.pdf),
and [TS 32.299 §7.2.30A](https://www.etsi.org/deliver/etsi_ts/132200_132299/132299/18.00.00_60/ts_132299v180000p.pdf).

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

The GTPv2-C and Diameter suites passed 445 and 770 tests respectively for the
associated remediation batches. Those results do not qualify absent NAS providers.

## Diameter runtime work list #1358

The cited `src/apps/rfc7683.rs` and `src/routing.rs` do not exist in
`opc-proto-diameter`. The SWm typed messages already parse and preserve DOIC,
DRMP, and redirect AVPs. Queue admission, traffic abatement, realm routing,
and redirect-cache ownership are separate runtime responsibilities. The
[codec conformance scope](../crates/opc-proto-diameter/CONFORMANCE.md) and the
transport adapters do not claim a complete Diameter routing agent.

RFC 8583 defines Diameter load information; the DRMP specification is
[RFC 7944](https://www.rfc-editor.org/rfc/rfc7944.html). A runtime implementation
must separately apply [RFC 7683](https://www.rfc-editor.org/rfc/rfc7683.html)
overload reports and [RFC 6733 §6.1.7](https://www.rfc-editor.org/rfc/rfc6733.html#section-6.1.7)
redirect usage/cache scope. Typed AVP tests do not establish that these runtime
features exist. These runtime gaps remain open.

## PFCP/GTPv2-C work list #1359

The mandatory PFCP Node ID and incremental-rule-reference defects are fixed
in commit `80474f343`. Existing GTPv2-C unknown-IE handling defaults to
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
