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
