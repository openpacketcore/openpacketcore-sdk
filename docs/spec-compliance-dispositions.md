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

Wire ABORT remains open. The legacy `abort` handle closes local I/O using
SHUT_RDWR and must not be presented as a wire-ABORT API. An uncommitted
SCTP_ABORT-send prototype returned EINVAL on the native one-to-one association
and was removed. Linux explicitly rejects that flag for its TCP-style SCTP
sockets; a correct abort path must coordinate physical descriptor closure
and abortive linger without replacing an owned descriptor while registered.
RFC 6733 section 2.1 also requires wire abort when Diameter framing cannot be
recovered. This remaining requirement is not waived by the graceful-close proof.

Witnesses: [native close regression](../crates/opc-sctp/src/lib.rs),
[RFC 6083 sections 4.6–4.8](https://www.rfc-editor.org/rfc/rfc6083.html#section-4.6),
[RFC 6525 section 6.3.1](https://www.rfc-editor.org/rfc/rfc6525.html#section-6.3.1),
[RFC 6458 section 4.1.7](https://www.rfc-editor.org/rfc/rfc6458.html#section-4.1.7), and
[Linux one-to-one flag check and linger-based close](https://github.com/torvalds/linux/blob/v6.8/net/sctp/socket.c).
