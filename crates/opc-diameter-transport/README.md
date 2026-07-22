# opc-diameter-transport

`opc-diameter-transport` provides the mutually authenticated TLS/TCP transport
boundary for the experimental Diameter codec and peer state machine.

## Implemented boundary

- Direct TLS/TCP completes mutually authenticated TLS 1.3 before any Diameter
  byte is read or written.
- In-band TLS/TCP uses consuming typestates to permit one canonical CER/CEA
  exchange and then immediately upgrades that same unbuffered TCP stream.
- The authenticated certificate SPIFFE ID must exactly match the configured
  peer. `ExpectedPeerIdentity::new` rejects empty or non-ASCII `Origin-Host`
  and `Origin-Realm` configuration. Typed CER/CEA parsing and construction use
  the same nonempty-ASCII DiameterIdentity contract, with ASCII
  case-insensitive authorization comparison.
- Client `ServerName` is only ClientHello routing/SNI input. It is not
  authorization evidence and no DNS SAN is required; the SPIFFE verifier and
  exact `ExpectedPeerIdentity` authorize the peer.
- Diameter framing reads the exact 20-octet header before bounded allocation,
  strictly rejects reserved command bits before trusting its declared body
  length, honors one absolute operation deadline, and does not read ahead
  across an in-band TLS transition. The final opaque frame decode remains
  header-only so repeatable AVPs stay available to typed parsers; strict CER/
  CEA parsing separately rejects reserved AVP flags.
- Direct-mode connection methods own the capability roles: a connector builds
  and sends the canonical CER and accepts only its strictly parsed correlated
  CEA, while an acceptor receives the CER and prepares the sole canonical CEA
  through its bound `PeerSession`. Full non-success and minimal protocol-error
  CEA outcomes are returned as typed rejections only after the answer is
  delivered and the connection is failed closed. Generic frame methods cannot
  send or receive CER/CEA, watchdog, or disconnect procedures.
- A connection retains typed TLS version, cipher, credential epoch, peer
  identity, protection-sequence, and generation evidence. It exposes no raw
  stream escape that can bypass `PeerSession` command admission.
- Credential-source loss, an admitted epoch replacement, certificate-chain
  expiry, or the configured maximum authentication age retires an idle socket.
  A rejected candidate that retains the same usable epoch does not retire it.
  Every admission, I/O, and owned readiness/snapshot accessor synchronously
  reconciles the authoritative material status and hard deadline, so an
  immediate ready operation cannot race the background watcher. Dropping a
  healthy connection also issues synchronous full TCP shutdown.
- TLS resumption, tickets, early data, half-RTT data, and HTTP ALPN defaults are
  disabled for this Diameter boundary. Diameter has no negotiated ALPN here.
- Cipher allowlists filter the rustls provider before handshake advertisement;
  the negotiated evidence is checked again before admission.
- A TLS-1.2-only offer is therefore rejected inside rustls and reported as
  `TlsHandshake`; `ProtocolRejected` remains the defensive classification for
  a completed negotiation whose version or ALPN evidence violates policy.

All parser, TLS, identity, deadline, and write failures are represented by a
closed redaction-safe error set and terminally full-close the affected
connection. Cancelling a frame operation after it starts also synchronously
revokes the exact peer generation and full-closes TCP, so a retained handle
cannot resume a partially read or written frame.
Application policy and Diameter application state machines remain outside this
crate.

## Explicit limits

This crate currently implements TLS/TCP only. It does not implement DTLS/SCTP,
does not emit SCTP PPID 47, and does not claim simultaneous-open winner
election. Each candidate receives a monotonic `PeerSessionGeneration`, but the
consumer still owns winner election, listener/reconnect policy, backoff, realm
routing, and peer topology.

`DiameterTlsConnection` is a sequential connection handle in this slice:
`send_message` and `receive_message` both require exclusive mutable access. It
exposes only owned redaction-safe session snapshots/readiness after retirement
reconciliation, not a borrowed mutable `PeerSession`. These generic methods
are application-message-only after typed capability negotiation; connection-
owned watchdog/disconnect lifecycle methods are not yet present. The handle
does not yet provide an owned read/write split or actor, and an external mutex
must not be held across a blocked receive to emulate one. Consequently this is
not yet the normal long-lived full-duplex Diameter/watchdog runtime. The crate
is experimental and is not a complete RFC 6733 transport or deployment-
readiness profile.

## Verification

```bash
cargo test -p opc-diameter-transport
cargo clippy -p opc-diameter-transport --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc -p opc-diameter-transport --no-deps --all-features
```
