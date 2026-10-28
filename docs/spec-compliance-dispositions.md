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

The following transport dispositions cover SCTP #1351, PKI/TLS #1353 and Diameter #1358 under
[umbrella #1532](https://github.com/openpacketcore/openpacketcore-sdk/issues/1532).
They describe implemented behavior and its limits. They are not a claim of
complete protocol support or a substitute for qualification at a named revision.

## SCTP work list #1351: mixed-family static multihoming

Bind/connect address sets accept IPv4 and IPv6 together, preserving count,
same-port and wildcard limits. Local and remote sets must have a usable family
in common. Socket-family selection examines both sets; mixed sets use explicit
dual-stack configuration before bind/connect. Single-family sockets retain the
previous host policy. Packed UAPI addresses retain their concrete 16/28-byte
widths. IPv4 and unscoped IPv4-mapped path identities reconcile; wrong ports,
nonzero scopes, IPv4-compatible addresses and different hosts remain distinct.

The portable regression covers mixed-set admission and invalid configurations.
The native regression exercises both family orders, address readback, primary
path selection and payload delivery. The required SCTP CI job selects that
kernel test explicitly and checks its execution count.

Witnesses: [socket boundary](../crates/opc-libsctp-sys/src/linux.rs),
[transport and native tests](../crates/opc-sctp/src/lib.rs),
[portable tests](../crates/opc-sctp/tests/dual_stack.rs), and
[RFC 6458 §§8.1.15, 9.1, 9.3, 9.5, 9.9](https://www.rfc-editor.org/rfc/rfc6458.html#section-9.1).

## SCTP work list #1351: authentication preference and local readback

The sys boundary exposes `SCTP_HMAC_IDENT` and `SCTP_LOCAL_AUTH_CHUNKS`.
Bounded HMAC lists accept SHA-1/SHA-256 identifiers, reject duplicates and
require SHA-1. Configuration offers explicit SHA-256-first preference while
preserving the kernel default otherwise. Requested order and required local
chunk types are read back before setup; local and peer chunk requirements are
verified again on the association. SCTP-AUTH alone proves neither transport
identity nor application authentication.

Linux `accept` creates an endpoint whose HMAC option can report SHA-1 defaults
(or EACCES with global authentication disabled), although the association
inherits the listener's configured list. Preference evidence therefore comes
from the listener before listen; association chunk evidence comes after accept.
The implementation does not rewrite a live endpoint's HMAC parameters.

Tests cover malformed lengths/counts, unsupported or duplicate identifiers,
missing SHA-1, missing DATA/FORWARD-TSN requirements and reversed preference.
The native key-switch/drain test retains the existing key lifecycle and drain
assertions; CI runs it with both namespace authentication-default settings.

Witnesses: [safe boundary](../crates/opc-sctp/src/lib.rs),
[UAPI codecs](../crates/opc-libsctp-sys/src/linux.rs),
[RFC 4895 §§3.3, 6.1](https://www.rfc-editor.org/rfc/rfc4895.html#section-6.1), and
[RFC 6458 §§8.1.17, 8.2.4](https://www.rfc-editor.org/rfc/rfc6458.html#section-8.1.17).

## SCTP work list #1351: lifecycle and terminal framing errors

[RFC 6083 §4.6](https://www.rfc-editor.org/rfc/rfc6083.html#section-4.6)
leaves renegotiation use to the upper layer. It does not require automatic
HelloRequest handling or uninterrupted writes. The generic explicit rekey
profile retains §4.7 drain/key barriers; Diameter uses bounded connection
retirement. [RFC 6525 §6.3.1](https://www.rfc-editor.org/rfc/rfc6525.html#section-6.3.1)
separates enabling stream reconfiguration from subscribing to its events.
Reset requests are disabled by default. The N2 owner observes lifecycle events
but exposes no reset/add-stream initiation API. RFC 6083 §4.8 concerns shared
keys, not stream resets.

`SctpAssociationAbortHandle::abort_on_wire` uses zero-time SO_LINGER and drops
the owned Tokio registration synchronously before closing the descriptor.
Pending I/O is awakened without keeping the descriptor alive. The legacy
`abort()` operation uses SHUT_RDWR and initiates graceful shutdown; ordinary
drop also permits queued sends to drain. The native close regression checks
queued payload delivery before Closed, while retaining the distinction between
local shutdown and delivery guarantees through a peer/network failure.

[RFC 6733 §2.1](https://www.rfc-editor.org/rfc/rfc6733.html#section-2.1)
requires reset/abort when Diameter framing cannot be parsed. Sequential and
concurrent DTLS/SCTP receivers, and both cleartext CER/CEA prelude roles, invoke
wire ABORT before returning a framing failure. The unprotected
`DiameterSctpAssociation` facade returns opaque bytes after SCTP metadata
validation: its caller owns Diameter parsing and must use the exposed
`abort_handle().abort_on_wire()` on an unparseable frame.

Portable tests distinguish abort from graceful close. Kernel tests require
COMM_LOST for both prelude roles and for a caller aborting through the facade,
including while handles and a receive remain alive. The independent
[capture harness](../ci/qualify-sctp-close-wire.py) requires two explicit aborts
and twelve malformed-frame aborts, User-Initiated Abort cause 12, complete
graceful-shutdown controls and zero capture drops. It requires a separate
privileged capture environment; kernel notification evidence alone is not a
packet-capture receipt. Custom abort text is unsupported on Linux one-to-one
sockets.

The TLS/TCP carrier still uses `shutdown(Shutdown::Both)`, which normally sends
FIN. Its terminal close fails closed but does **not** implement the TCP RST
required by RFC 6733 §2.1. This is a known TCP limitation; the SCTP fix does not
qualify TCP reset behavior.

Witnesses: [descriptor ownership](../crates/opc-sctp/src/socket_descriptor.rs),
[native Diameter regression](../crates/opc-diameter-transport/src/dtls_tests/wire_abort.rs),
[RFC 6458 §§4.1.7, 8.1.4](https://www.rfc-editor.org/rfc/rfc6458.html#section-8.1.4), and
[Linux one-to-one flag and linger handling](https://github.com/torvalds/linux/blob/v6.8/net/sctp/socket.c).

## SCTP work list #1351: Diameter stream admission

[RFC 6733 §2.1.1](https://www.rfc-editor.org/rfc/rfc6733.html#section-2.1.1)
requires Diameter receivers to accept any negotiated stream, including
unordered delivery. Sequential and concurrent DTLS/SCTP receivers implement
that contract. DTLS Handshake, CCS and Alert records remain ordered on stream
zero. The sequential `send_message_on_stream` API retains generation-bound
command admission; SCTP enforces the negotiated stream range, and stream 65535
is rejected locally.

Default sends, `DiameterPeerRuntime`, and the unprotected
`DiameterSctpAssociation` facade send on ordered stream zero. The concurrent
runtime and unprotected facade do not expose inbound stream metadata. Those
are API and scheduling limits, not violations of the receiver requirement or
of RFC 6083 §4.4's permission to send application records on stream zero.
The generic RFC 6083 API retains its separately configured stream policy.

[Stream regressions](../crates/opc-diameter-transport/src/dtls_tests/diameter_streams.rs)
cover both roles and runtime forms, unordered delivery, selected-stream sends
and invalid metadata/control placement. Native qualification exercises streams
1, 7 and 15 as well as stream zero. An unordered application record overtaking
Finished during the initial handshake remains a qualification gap; steady-state
multistream tests do not establish that behavior.

## PKI profiles in #1353

`opc-identity` exposes `extract_spiffe_id_from_pki_cert_der`,
`validate_local_pki_identity` and `LocalPkiUsage` for client, server or both TLS
roles. One SPIFFE URI may coexist with other URIs; multiple SPIFFE identities
fail with `SpiffeSanError::MultipleSpiffeIds`. Trust-domain anchors, complete
path validation, validity and matching private key remain mandatory.

This returns `LocalPkiIdentity`, not `IdentityState`. SVID reload sources,
`opc-tls` and Diameter transports retain strict X.509-SVID validation. A present
EKU must contain both clientAuth and serverAuth, and the strict SAN profile
requires exactly one URI. The [role/profile tests](../crates/opc-identity/tests/pki_profiles.rs)
cover EKU, SAN, trust, key and time failures.

This distinction follows [TS 33.310 V18.8.0 §6.1.3a and Table 6.1.3c.3-1](https://www.etsi.org/deliver/etsi_ts/133300_133399/133310/18.08.00_60/ts_133310v180800p.pdf)
and [X.509-SVID §§2, 4.4](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md).
These helpers are not a complete NF certificate-profile validator. In
particular, an NF certificate containing only a `urn:uuid` NF Instance ID and
no SPIFFE URI is not accepted. General-PKI transport integration, full NF
profile validation, authorization and revocation are separate responsibilities.

## TLS and DTLS cipher policy in #1353

The SDK targets the TLS 1.2 cipher restrictions in
[TS 33.210 Release 19 §6.2.3 (V19.3.0)](https://www.etsi.org/deliver/etsi_ts/133200_133299/133210/19.03.00_60/ts_133210v190300p.pdf)
and [RFC 10015 §3](https://www.rfc-editor.org/rfc/rfc10015.html#section-3):
normal compatibility enables ECDHE AEAD suites and excludes FFDHE. TLS 1.3
remains preferred and is the TLS default. This is a cipher-policy target, not
complete TS 33.210 endpoint or validated-module qualification.

`TlsConfigBuilder::with_compat_mode(true)`,
`DiameterTlsPolicy::tls12_compatibility` and management
`TlsBootstrap::with_tls12_compat(true)` do not enable DHE-RSA. Both TLS 1.2
roles now require Extended Master Secret, including management listeners;
legacy peers omitting EMS are rejected.

[TS 33.210 Release 18 §6.2.3 (V18.2.0)](https://www.etsi.org/deliver/etsi_ts/133200_133299/133210/18.02.00_60/ts_133210v180200p.pdf)
still requires DHE-RSA/AES-128-GCM support. To serve that older profile,
`with_legacy_dhe_rsa(true)` is a separate opt-in on the TLS and management
builders, effective only with TLS 1.2 compatibility. Diameter offers
`tls12_legacy_dhe_rsa`, or an explicit DHE cipher allowlist, with the same
separate provider opt-in. DTLS DHE-RSA likewise requires an explicit cipher
allowlist. These are legacy exceptions incompatible with RFC 10015 and the
Release 19 prohibition, not part of the normal compatibility policy. Static
RSA key exchange, CBC and obsolete protocol versions remain excluded.

The legacy DHE implementation supports FFDHE4096 (preferred) and FFDHE2048,
fixed-size fresh exponents, authenticated DH parameters and safe-prime
public-value checks. Custom or smaller groups are unsupported. Known-answer
vectors and committed OpenSSL DTLS interop tests cover the arithmetic and wire
behavior; the TLS tests pair rustls endpoints. Unretained historical external
TLS interop runs are not qualification evidence for this revision.

Known alert deviations remain: rustls returns `handshake_failure` where
[RFC 7919 §4](https://www.rfc-editor.org/rfc/rfc7919.html#section-4)
specifies `insufficient_security`; the vendored DTLS engine fails closed on
invalid DH parameters without emitting the fatal alerts required by §§3–4.
It emits `close_notify` for orderly close. Full RFC 7919 alert compliance is
not claimed.

DTLS ECDHE-RSA suites and RSA-PSS-RSAE/PKCS#1 SHA-256/384 signatures are
available through explicit policy. CertificateRequest types/schemes and
CertificateVerify admission derive from the configured suite families, as
required by [RFC 5246 §§7.4.4, 7.4.8](https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.4).
Default ECDSA-only servers refuse RSA client authentication; an RSA-enabled
policy can admit it even when the server uses an ECDSA certificate. Client
suite offers describe server authentication independently of the client's own
certificate key. The default DTLS ClientHello omits FFDHE groups unless a DHE
suite is enabled, following [RFC 7919 §3](https://www.rfc-editor.org/rfc/rfc7919.html#section-3).
The optional `NdsAfEcdsa` constraint remains ECDSA-only. DTLS 1.3 remains
ECDHE-only and has no RFC 6083 transport claim.

## Diameter runtime work list #1358

The cited `src/apps/rfc7683.rs` and `src/routing.rs` do not exist in
`opc-proto-diameter`. SWm messages parse and preserve DOIC, DRMP and redirect
AVPs. The [peer runtime](../crates/opc-diameter-transport/src/runtime.rs) owns
bounded transport queues, correlated requests, watchdogs and disconnects. It
does not implement DOIC abatement, realm routing, priority scheduling or a
redirect cache. Applications must supply abatement before advertising DOIC.
Codec fields alone do not assert those runtime capabilities.

RFC 8583 specifies Diameter load information; DRMP is specified by
[RFC 7944](https://www.rfc-editor.org/rfc/rfc7944.html). Routing applications
must apply [RFC 7683](https://www.rfc-editor.org/rfc/rfc7683.html) overload
reports and [RFC 6733 §§6.1.8, 6.13, 6.14](https://www.rfc-editor.org/rfc/rfc6733.html#section-6.1.8)
redirect usage/cache scope. Section 6.1.7 is predictive loop avoidance, not
redirect caching.

The [overload tests](../crates/opc-proto-diameter/tests/swm_diameter_eap_overload.rs)
cover request-conditioned negotiation and report bounds. The
[redirect tests](../crates/opc-proto-diameter/tests/swm_diameter_eap_routing.rs)
cover correlation, absent/DONT_CACHE semantics and required cache-time metadata.
These are scope dispositions, not a full routing-agent implementation.
