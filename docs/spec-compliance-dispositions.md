# Spec-compliance evidence and scope corrections

This accompanies [umbrella #1532](https://github.com/openpacketcore/openpacketcore-sdk/issues/1532)
and the `compliance/spec-audit` branch. It records findings whose requested
change differs from the applicable wire format or existing implementation.
It is not peer-review approval or a claim of complete protocol support.
The umbrella tracks implementation and qualification separately.

## SCTP work list #1351: mixed-family static multihoming

Bind/connect address sets now accept IPv4 and IPv6 together, preserving count,
same-port and wildcard limits. Local and remote sets must have a usable family
in common. Socket-family selection examines both complete sets, and mixed
sets use explicit dual-stack configuration before bind/connect. Existing
single-family sockets retain the previous host policy. Packed UAPI addresses
use their concrete 16/28-byte widths, not a fixed `sockaddr_storage` stride.
Native IPv4 and unscoped IPv4-mapped path identities reconcile; wrong ports,
nonzero scopes, IPv4-compatible addresses and different hosts remain distinct.

The portable mixed-set regression failed against the old guard. Native Linux
coverage forms one association in each configured family order, checks both
local and peer address readback, selects each family as primary and delivers
application records with preserved stream/PPID metadata. The required SCTP
CI job executes this ignored kernel test explicitly and checks its test count.
Other #1351 items are tracked separately; this slice does not claim the whole
work list is complete.

Witnesses: [socket boundary](../crates/opc-libsctp-sys/src/linux.rs),
[transport and native proof](../crates/opc-sctp/src/lib.rs),
[configuration regression](../crates/opc-sctp/tests/dual_stack.rs), and
[RFC 6458 §§8.1.15, 9.1, 9.3, 9.5, 9.9](https://www.rfc-editor.org/rfc/rfc6458.html#section-9.1).

## SCTP work list #1351: authentication preference and local readback

The sys boundary exposes `SCTP_HMAC_IDENT` and `SCTP_LOCAL_AUTH_CHUNKS`.
HMAC lists are bounded to the implemented SHA-1/SHA-256 identifiers, reject
duplicates and require SHA-1. The safe configuration offers explicit
SHA-256-first preference while preserving the kernel default otherwise.
Requested order and required local chunk types are read back before setup;
local and peer chunk requirements are verified again on the association.
No signing, transport identity or application authentication is inferred from
SCTP-AUTH alone.

The native test caught a Linux distinction: the socket returned by `accept`
has a newly created endpoint. Its HMAC option can return SHA-1 defaults (or
EACCES with authentication disabled globally), despite the existing
association inheriting the listener's configured SHA-256-first list.
Preference evidence therefore comes from the listener before listen, while
association-specific chunk evidence is read after accept. The implementation
never rewrites a live association's HMAC parameters to force a readback match.

The real key-switch/drain test now exercises SHA-256 preference and local
readback in both namespace authentication-default modes. Both pass, and the
required SCTP CI job executes both explicitly. Unit tests cover malformed
counts/lengths, unknown or duplicate identifiers, missing SHA-1, missing DATA
or FORWARD-TSN requirements and reversed preference. Existing key lifecycle
and drain assertions remain.

Witnesses: [safe authentication boundary](../crates/opc-sctp/src/lib.rs),
[bounded UAPI codecs](../crates/opc-libsctp-sys/src/linux.rs),
[RFC 4895 §§3.3, 6.1](https://www.rfc-editor.org/rfc/rfc4895.html#section-3.3),
[RFC 6458 §§8.1.17, 8.2.4](https://www.rfc-editor.org/rfc/rfc6458.html#section-8.1.17), and
[Linux endpoint/association readback](https://github.com/torvalds/linux/blob/v6.8/net/sctp/socket.c).

## SCTP work list #1351: remaining lifecycle claims

- RFC 6083 section 4.6 leaves renegotiation use to the upper layer. It does not
  require automatic HelloRequest handling or uninterrupted writes. The existing
  explicit rekey profile retains the section 4.7 drain/key barriers; its native
  multistream rekey and packet-capture proofs pass. The Diameter facade continues
  to use bounded connection retirement instead of offering renegotiation.
- RFC 6525 sections 6.3.1 and 7 distinguish event subscription from enabling
  reconfiguration. Reset requests are disabled by default and require explicit
  application enablement. The documented N2 owner observes lifecycle events;
  it does not advertise a reset/add-stream API. Enabling extensions merely
  because their events are observed is not required. RFC 6083 section 4.8,
  also cited by the issue, concerns shared keys rather than stream resets.
- RFC 6458 section 4.1.7 specifies that SHUT_RDWR initiates SCTP shutdown.
  The expanded native close regression verifies all eight queued 1 KiB
  responses reach the peer before Closed, for both descriptor drop and the
  explicit local terminal-close handle. The required SCTP CI job runs this
  proof explicitly. This is loopback delivery evidence, not a guarantee that
  a peer or network failure cannot interrupt an SCTP shutdown.

The new `SctpAssociationAbortHandle::abort_on_wire` uses RFC 6458 section 8.1.4
zero-time SO_LINGER and synchronously drops the owned Tokio registration before
closing its descriptor. Readiness and syscall borrows cannot escape one poll;
waiting reads/writes are notified without retaining the descriptor. The legacy
`abort` handle retains its SHUT_RDWR semantics. Linux rejects SCTP_ABORT send
flags on one-to-one sockets, so custom user-cause text is not offered. Native
capture verifies the standard User-Initiated Abort cause (12), with no text.

RFC 6733 section 2.1 requires ABORT for unparseable Diameter framing. Both
sequential and concurrent protected receivers now abort before publishing that
failure. The real generic RFC 6083 sender supplies three malformed fixed-frame
forms to each receiver, independently of the Diameter sender's validation.
The required CI capture checks six actual aborting associations, one explicit
abort while handles and a read remain alive, three queued-send graceful closes,
and one reciprocal DTLS close. All captures require zero packet drops. Ordinary
tests cover read/write wakeup, queued readers, cancellation and syscall-error
classification; native regressions retain N2, AUTH, multihoming and rekey checks.

The six #1351 findings are addressed by the implemented fixes and the standards
dispositions above. Optional hitless rekey, custom abort text and stream-reset
initiation are not claimed. Peer review is still required before main.

Witnesses: [native close regression](../crates/opc-sctp/src/lib.rs),
[RFC 6083 sections 4.6–4.8](https://www.rfc-editor.org/rfc/rfc6083.html#section-4.6),
[RFC 6525 section 6.3.1](https://www.rfc-editor.org/rfc/rfc6525.html#section-6.3.1),
[RFC 6458 section 4.1.7](https://www.rfc-editor.org/rfc/rfc6458.html#section-4.1.7), and
[Linux one-to-one flag check and linger-based close](https://github.com/torvalds/linux/blob/v6.8/net/sctp/socket.c).

## PKI profiles in #1353

`opc-identity` now exposes explicit general-PKI URI extraction and local
certificate validation for client, server or both TLS roles. A single SPIFFE
URI may coexist with service URIs; duplicate SPIFFE identities still fail.
The selected trust-domain bundle, complete certificate path, validity and
matching private key remain mandatory. This returns a local identity, not an
`IdentityState`; SVID reload sources and `opc-tls` retain their strict profile.

The strict SVID loader also now rejects a present EKU without both clientAuth
and serverAuth. Previously it checked only the server role. The regression
failed before correction; the role matrix and negative trust/key/time/SAN
cases are in [pki_profiles.rs](../crates/opc-identity/tests/pki_profiles.rs).

This separation follows the role-specific EKUs and service SANs in
[TS 33.310 V18.8.0 Table 6.1.3c.3-1](https://www.etsi.org/deliver/etsi_ts/133300_133399/133310/18.08.00_60/ts_133310v180800p.pdf)
and the single-URI and dual-EKU requirements in
[X.509-SVID §§2 and 4.4](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md).
The general helper is not a complete NF certificate-profile validator or a
replacement for peer authorization and revocation.

Diameter now offers explicit TLS 1.2 compatibility while preserving the TLS 1.3
default. The admitted TLS 1.2 suites use ECDHE-ECDSA or ECDHE-RSA with
AES-128/256-GCM, or DHE-RSA with AES-128-GCM and RFC 7919 FFDHE4096/2048.
Both roles require Extended Master Secret. [Wire regressions](../crates/opc-diameter-transport/tests/tls_tcp/tls12.rs)
exercise both roles, all five suites, bidirectional Diameter, in-band upgrade,
TLS 1.3 preference and material-loss retirement; the legacy strict policy still
rejects TLS 1.2 during the handshake. The pre-fix peer received a ProtocolVersion
alert. Follow-up DHE admission and missing-EMS policy regressions failed before
correction. All 306 affected TLS/transport tests/docs pass on macOS and Linux.
The fixed-exponent known answers agree independently with Python integer
arithmetic and LibreSSL 3.3.6. A separate OpenSSL 3.6.5 wire check verifies
mutual authentication and application bytes in both roles, client agreement
with FFDHE2048 and FFDHE4096 servers, server agreement with FFDHE4096, and
rejection of EMS omission in both roles. Its TLS 1.2 ClientHello omits the
supported-groups extension even with `-groups`; server fallback therefore
selects the preferred FFDHE4096 group.

[TS 33.210 V18.2.0 §6.2](https://www.etsi.org/deliver/etsi_ts/133200_133299/133210/18.02.00_60/ts_133210v180200p.pdf)
requires TLS 1.2 and 1.3 and restricts TLS 1.2 suites to AEAD with forward
secrecy. Static RSA key exchange is therefore not an interoperability fix for
that profile. The DHE-RSA suite is now supplied using the existing ring
signature/PRF/record algorithms and constant-time `crypto-bigint` arithmetic
with fixed 512-bit ephemeral exponents. Named safe-prime public-key checks
follow [RFC 7919 §§5.1–5.2](https://www.rfc-editor.org/rfc/rfc7919.html#section-5.1);
custom groups and sub-2048-bit groups are unsupported. This software path
makes no validated-module claim. DTLS cipher findings keep #1353 open.

## Diameter runtime work list #1358

The cited `src/apps/rfc7683.rs` and `src/routing.rs` do not exist in
`opc-proto-diameter`. The SWm typed messages already parse and preserve DOIC,
DRMP, and redirect AVPs. The actual
[peer runtime](../crates/opc-diameter-transport/src/runtime.rs) handles bounded
transport queues, correlated requests, watchdogs and disconnects. It does not
generate DOIC offers or implement realm routing, a DRMP scheduler or a redirect
cache. Those are documented application responsibilities, rather than a
reported routing table whose expiry is broken. The
[codec conformance scope](../crates/opc-proto-diameter/CONFORMANCE.md) and
[transport boundary](../crates/opc-diameter-transport/README.md) do not claim a
complete Diameter routing agent.

RFC 8583 defines Diameter load information; the DRMP specification is
[RFC 7944](https://www.rfc-editor.org/rfc/rfc7944.html). A runtime implementation
must separately apply [RFC 7683](https://www.rfc-editor.org/rfc/rfc7683.html)
overload reports and [RFC 6733 §6.1.7](https://www.rfc-editor.org/rfc/rfc6733.html#section-6.1.7)
redirect usage/cache scope. The documentation now explicitly requires an
application to supply abatement before advertising DOIC; the optional codec
fields do not assert a runtime capability. The SDK does not silently apply
new route selection or queue priorities to caller-owned traffic.

The existing [overload tests](../crates/opc-proto-diameter/tests/swm_diameter_eap_overload.rs)
verify request-conditioned negotiation and effective report bounds. The
[redirect tests](../crates/opc-proto-diameter/tests/swm_diameter_eap_routing.rs)
verify request/connection correlation, absent/DONT_CACHE semantics, and
required cache-time metadata. Together with agent-error and lifecycle cases,
**85 tests pass**. Both #1358 findings are scope dispositions backed by those
existing behaviors, pending review. No overload engine, priority scheduler,
redirect-cache implementation or full routing-agent qualification is claimed.

## SCTP work list #1351: Diameter stream admission

RFC 6083 section 4.4 permits sending application records solely on stream zero.
However, RFC 6733 section 2.1.1 requires Diameter receivers to accept messages
on any negotiated stream, including peer-selected unordered delivery. The
Diameter facade now applies that receiver contract in both sequential and
concurrent operation. Its selected-stream send method retains exact-generation
command admission. SCTP remains responsible for negotiating and enforcing the
available stream range; stream 65535 is rejected locally.

The existing bounded epoch/record-number correlation tracks authenticated
carrier metadata. Handshake, CCS and Alert records remain ordered on stream
zero. Cleartext, foreign PPIDs, malformed records, truncated metadata and
notifications still fail closed. The separately configured generic RFC 6083
ordered-stream policy retains its original restrictions. Default Diameter
sends and the concurrent runtime still choose ordered stream zero, with its
head-of-line blocking tradeoff; this change does not implement a stream scheduler.

The old implementation fails the new peer-stream regression. The fixed
selection passes 236 tests on each host and Linux, covering both roles and
both runtime forms, highest usable stream ID, unordered application delivery,
protected selected-stream sends and terminal metadata/control refusals. The
existing native Diameter qualification additionally sends in both directions
over negotiated streams 1, 7 and 15, preserving its original stream-zero and
reciprocal-close assertions. All 11 native RFC 6083 cases and Linux strict
all-target/all-feature Clippy pass.

Witnesses: [Diameter transport](../crates/opc-diameter-transport/src/dtls.rs),
[regressions](../crates/opc-diameter-transport/src/dtls_tests/diameter_streams.rs),
[native proof](../crates/opc-diameter-transport/src/dtls_tests.rs), and
[RFC 6733 section 2.1.1](https://www.rfc-editor.org/rfc/rfc6733.html#section-2.1.1).
The other #1351 lifecycle and optional-extension claims remain separately tracked.
