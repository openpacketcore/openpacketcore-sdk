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

## GTP-U multi-homing #1347

The eBPF default checked the configured outer peer address exactly. TS 29.281
§4.3.0 defines an entity per IP address and permits “one GTP-U tunnel endpoint
to receive packets from multiple remote GTP-U endpoints”. The issue's
explicit TEID/local validation option is now `GtpuPeerSourcePolicy::TeidAndLocal`.
It is per context and keeps local endpoint, attachment, source-port, inner-PAA,
TEID, ownership/generation and N3 QFI checks. Unspecified sources and malformed
record versions remain rejected; N3 source addresses remain unicast. It does
not authenticate an alternate address, so transport-network admission remains
caller policy. Outgoing routing still uses the configured peer.

`BackendDefault` retains eBPF's exact peer check and Linux GTP's native behavior.
The Linux kernel's `gtp1u_udp_encap_recv` already looks up the incoming TEID
without comparing the outer source to the configured outgoing peer. Linux GTP
rejects the new explicit opt-in because its netlink codec cannot retain that
setting. It is therefore not labelled an exact-peer policy across all backends.

Default-policy bytes retain their existing versions. The opt-in has new binding,
ordinary/N3 entry and durable-descriptor versions; older readers reject them.
Policy bytes enter owner/commit equality and selector-admission fingerprints.
Readback/restart preserve the policy, while exact install/removal and TEID-only
reattachment detect a policy conflict. The shared borrowed checks also serve
the kernel-reassembly consumer.

Witnesses include raw-byte typed/borrowed tests for both families and N3,
malformed-version refusal, ownership mismatch, ordinary/marked restart, grouped
readback, durable descriptor/fingerprint tests, and userspace reassembly parity.
The privileged Linux test injects alternate-source packets, proves default
rejection and opt-in delivery across restart, and rejects wrong local address,
UDP source port, TEID and inner PAA. Existing IPv4 round-trip, ordinary IPv6 and
N3 live contracts qualify the rebuilt object separately. A full Linux test run
initially failed during durable selector fixture provisioning (`Indeterminate`);
the isolated test and complete rerun passed without changing that test or its
assertions. This is retained as test history, not treated as peer-review approval.

Sources: [TS 29.281 v18.4.0 §§4.3.0, 4.4.3.3](https://www.etsi.org/deliver/etsi_ts/129200_129299/129281/18.04.00_60/ts_129281v180400p.pdf),
[Linux v6.8 GTP receive path](https://github.com/torvalds/linux/blob/v6.8/drivers/net/gtp.c),
[shared binding](../crates/opc-gtpu-ebpf-common/src/lib.rs),
[grouped wire authorizers](../crates/opc-gtpu-ebpf-common/src/session.rs), and
[live packet proof](../crates/opc-gtpu-dataplane/tests/ebpf_gtpu_privileged/multihoming.rs).

## S2b GTPv2-C unknown optional IEs #1359

TS 29.274 §§7.7.1 and 7.7.9 require continued processing after an unknown
optional IE. The default `UnknownIePolicy::Preserve` retains its uninterpreted
bytes and `Drop` omits it from the interpreted view. Explicit `Reject` is a
non-conformant diagnostic mode for this network-receive case. The issue's
§7.2.1 citation describes Create Session Request, and its `messages.rs:820`
path is absent from this crate. The existing
[unknown-IE policy tests](../crates/opc-proto-gtpv2c/tests/unknown_ie_policy.rs)
and [S2b receive tests](../crates/opc-proto-gtpv2c/tests/s2b_receive_policy.rs)
qualify this disposition; it makes no PFCP runtime claim.

Source: [TS 29.274 V19.6.0 §§7.7.1, 7.7.9](https://www.etsi.org/deliver/etsi_ts/129200_129299/129274/19.06.00_60/ts_129274v190600p.pdf).
