# Spec-compliance evidence and scope corrections

These dispositions cover SCTP #1351, PKI/TLS #1353 and Diameter #1358 under
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
