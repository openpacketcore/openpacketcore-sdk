# opc-diameter-transport

`opc-diameter-transport` provides the mutually authenticated TLS/TCP and
DTLS/SCTP transport boundary for the experimental Diameter codec and peer
state machine.

## Implemented boundary

- Direct TLS/TCP completes mutually authenticated TLS 1.3 before any Diameter
  byte is read or written.
- In-band TLS/TCP uses consuming typestates to permit one canonical CER/CEA
  exchange and then immediately upgrades that same unbuffered TCP stream.
- Direct DTLS/SCTP completes a mutually authenticated DTLS 1.3 (optionally
  1.2-compatible) handshake over the `SctpMessageIo` message seam before any
  Diameter byte is read or written. Exactly one DTLS record travels per SCTP
  user message, ordered on stream 0 with PPID 47 (RFC 6083 sections 4.1 and
  4.4; PPID 47 itself is registered by RFC 6733 section 11.5), and PPID 47 is
  emitted only through this attested association: the send side of the seam
  accepts only complete DTLS records. Any cleartext or foreign-PPID user
  message fails the association closed before, during, or after the
  handshake. The engine is the Sans-IO `dimpl` crate (pure-Rust `rust-crypto`
  provider; ECDHE-ECDSA AEAD suites only, no RSA/DHE/renegotiation). The
  peer's leaf certificate is validated by this crate, not the engine:
  trust-anchor chain scoped to the peer's SPIFFE trust domain plus validity
  window via rustls-webpki, plus an exact configured SPIFFE identity match.
  The in-band CER/CEA-before-DTLS sequence over SCTP and the RFC 6083
  section 4.8 SCTP-AUTH exporter key switch are not claimed (the engine
  exposes only the DTLS-SRTP export); the kernel-SCTP adapter for the seam
  is follow-up work in `opc-sctp`.
- Diameter frames over DTLS are bounded to the single-record plaintext
  budget: `DtlsSctpPolicy` rejects frame limits above
  `MAX_DTLS_SCTP_MESSAGE_BYTES` (2^14) at construction because the engine
  does not fragment application data across records.
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
- After successful CER/CEA, `DiameterTlsConnection::into_peer_runtime` consumes
  the sequential handle into one full-duplex owner. Independent persistent
  reader and writer tasks never cancel an in-progress frame merely to service
  the opposite direction. Separate bounded caller, priority-control, and
  inbound-application queues plus a configured maximum frame-write duration
  bound how long application load can delay DWA/DPA handling. Queue exhaustion
  on a peer-controlled lane fails closed. Once a first frame octet arrives, a
  separate completion timeout prevents slow partial frames from occupying a
  connection until credential expiry.
- The runtime automatically parses, identity-checks, admits, and answers DWR
  and DPR. Safely classifiable malformed requests receive request-bound typed
  RFC error answers before the connection closes. Caller-originated probes and
  disconnects retain both Diameter identifiers and accept only the exact
  correlated DWA/DPA. Answers with an unknown Hop-by-Hop identifier, including
  stale duplicates, are discarded as RFC 6733 requires. An answer reusing the
  exact Hop-by-Hop identifier with a different End-to-End identifier, a
  wrong-identity exact answer, and invalid control grammar fail closed.
- Application traffic remains admissible while an exact watchdog response is
  pending, as RFC 3539 permits. The caller supplies a validated base `Twinit`
  and schedules the initial attempt from the exposed inbound-activity clock
  using `DiameterWatchdogTwinit::sample_effective_interval`; the runtime
  applies fresh jitter on every reset. The first unanswered
  interval enters `SUSPECT` without retransmitting DWR, any received Diameter
  message resets Tw, and a second unanswered interval closes the connection.
  A locally initiated graceful disconnect supersedes an outstanding watchdog
  only after its DPR is flushed; the displaced watchdog completes with a typed
  non-terminal result while the exact DPR/DPA transaction owns shutdown.
  Inbound DPR is acknowledged with success only after the consumer explicitly
  declares its application transaction ledger quiescent; admitted application
  traffic clears that declaration. Cancelling an already-enqueued public
  operation synchronously shuts down the socket rather than leaving the caller
  uncertain whether a partial frame or side effect occurred.
- `elect_simultaneous_open` provides the transport-neutral RFC 6733 section
  5.6.4 Origin-Host comparison and a typed local survivor decision. Equal or
  case-only-equal identities fail closed instead of selecting divergent peers.
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

All parser, TLS, identity, and started frame-I/O failures are represented by a
closed redaction-safe error set and terminally full-close the affected
connection. Validation, deadline, and backpressure rejections that the enqueue
or writer path proves occurred before starting leave it active. An unproven
caller timeout after submission is terminal, as is cancelling a submitted
frame operation: both synchronously revoke the exact peer generation and
full-close TCP, so a retained handle cannot resume a partially read or written
frame.
Application policy and Diameter application state machines remain outside this
crate.

## Explicit limits

Each candidate receives a monotonic `PeerSessionGeneration`, and the SDK
exposes the simultaneous-open decision, but the consumer still owns candidate
orchestration, listener/reconnect policy, backoff, realm routing, peer
topology, base `Twinit` selection, initial watchdog scheduling, identifier
allocation, and all application state machines.

The DTLS/SCTP association currently integrates the sequential connection
methods (capability exchange and admitted application messages) but not yet
the bounded full-duplex peer runtime, the kernel-SCTP seam adapter, the RFC
6083 section 4.8 SCTP-AUTH exporter key switch, or the in-band
CER/CEA-before-DTLS sequence over SCTP. RFC 6083 section 4.5 (SCTP DATA
chunks authenticated per RFC 4895) is a separate unmet association-level
requirement owned by the future `opc-sctp` integration. Peer leaf
certificates only: the engine presents a single certificate and path
validation is called with an empty intermediate list, so peers chaining
through intermediate CAs fail closed. Exact negotiated-cipher evidence for
DTLS is limited by the engine's public API; the configured cipher allow-list
bounds what can be negotiated and the negotiated DTLS version is reported
exactly. Local private-key custody is engine-forced into a plain `Vec<u8>`
inside `dimpl`; the intermediate copy is zeroized and zeroizing custody is
tracked as follow-up.

The original sequential `DiameterTlsConnection` methods remain available for
capability setup and narrow integrations. Long-lived use should consume a
negotiated connection into the bounded runtime instead of wrapping that handle
in an external mutex. The crate remains experimental and does not make a
complete RFC 6733 deployment-readiness claim until the remaining DTLS/SCTP
boundaries above are implemented and qualified.

## Verification

```bash
cargo test -p opc-diameter-transport
cargo clippy -p opc-diameter-transport --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc -p opc-diameter-transport --no-deps --all-features
```
