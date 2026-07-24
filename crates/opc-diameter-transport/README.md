# opc-diameter-transport

`opc-diameter-transport` provides the mutually authenticated TLS/TCP and
DTLS/SCTP transport boundary for the Diameter codec and peer state machine.

## Implemented boundary

- Direct TLS/TCP completes mutually authenticated TLS 1.3 before any Diameter
  byte is read or written.
- In-band TLS/TCP uses consuming typestates to permit one canonical CER/CEA
  exchange and then immediately upgrades that same unbuffered TCP stream.
- Direct DTLS/SCTP completes mutually authenticated DTLS 1.2 before any
  Diameter byte. The in-band typestates permit exactly one canonical
  cleartext CER/CEA, seal that prelude, and complete DTLS on the same SCTP
  association before application traffic. Exactly one DTLS record travels
  per ordered stream-0 SCTP user message with PPID 47 (RFC 6083 sections 4.1
  and 4.4; PPID 47 is registered by RFC 6733 section 11.5). Any cleartext or
  foreign-PPID input after the prelude fails closed.
- The DTLS engine is the audited workspace-vendored `dimpl` fork, compiled
  only with its pure-Rust `rust-crypto` provider. The transport selects that
  provider explicitly, so a process-global `dimpl` default installed by
  unrelated code cannot replace its crypto authority. Its RFC 6083 profile
  is DTLS-1.2-only, disables datagram replay filtering and flight
  retransmission in favor of reliable ordered SCTP, and admits the typed
  ECDHE-ECDSA AES-GCM and ChaCha20-Poly1305 suites reported in connection
  evidence.
- Complete peer certificate chains are bounded, checked for leaf-to-root
  order, validated with rustls-webpki against trust anchors scoped to the
  expected SPIFFE trust domain, and required to contain the exact configured
  SPIFFE identity. The acceptor requires a non-empty client certificate, and
  the connector requires proof that the server sent `CertificateRequest` and
  authenticated its local certificate; a one-way-authenticated handshake
  cannot publish mutual-authentication evidence. Evidence expiry is the
  earliest expiry across each full local and peer chain. Invalid material
  updates retain the last known-good epoch; valid replacement retires old
  associations.
- `KernelSctpMessageIo` binds the record seam to an `opc-sctp` one-to-one
  association configured to authenticate DATA chunks. It converts into an
  opaque `DiameterDtlsSctpTransport`; the record and cleartext-prelude methods
  are not caller-accessible, so PPID 47 emission and the one-CER/one-CEA fence
  remain owned by the authenticated boundary. Its independently draining
  receive task has a bounded queue of at least 32 complete messages, matching
  the audited engine flight bound; loss or overflow is terminal. Each
  handshake derives the exact 64-byte RFC 5705
  `EXPORTER_DTLS_OVER_SCTP` value (no context), installs the next SCTP-AUTH
  key, waits for sender-dry, activates it before the protected Finished
  boundary, and retires the protocol-defined initial empty key only after
  peer confirmation. The empty initial key is a transition baseline, not
  peer-derived cryptographic authentication.
- Diameter frames over DTLS are bounded to the single-record plaintext
  budget: `DtlsSctpPolicy` rejects frame limits above
  `MAX_DTLS_SCTP_MESSAGE_BYTES` (16,347 bytes) at construction because the
  engine does not fragment application data across records.
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
- After successful CER/CEA, both `DiameterTlsConnection` and
  `DiameterDtlsSctpConnection` can be consumed into one full-duplex peer
  runtime. Independent persistent
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
  healthy connection also synchronously closes its TCP or SCTP transport.
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
full-close the underlying transport, so a retained handle cannot resume a
partially read or written frame.
Application policy and Diameter application state machines remain outside this
crate.

## Explicit limits

Each candidate receives a monotonic `PeerSessionGeneration`, and the SDK
exposes the simultaneous-open decision, but the consumer still owns candidate
orchestration, listener/reconnect policy, backoff, realm routing, peer
topology, base `Twinit` selection, initial watchdog scheduling, identifier
allocation, and all application state machines.

The SDK does not configure or attest an external IPsec deployment. A consumer
may select `CompatibilityUnprotected` only after applying its own separate
IPsec policy and evidence; the SDK still reports that association as
unprotected and it never satisfies protected-transport readiness.

The RFC 6083 profile deliberately rejects DTLS 1.3. RFC 6083's key transition
is defined around the DTLS 1.2 Finished boundary; this SDK does not substitute
the expired DTLS-over-SCTP-bis draft's different directional-key contract.
Local software credentials are imported into the DTLS provider as DER. Every
adapter and vendored-engine DER custody buffer is zeroized on drop, but
selecting an HSM/non-exportable signing provider remains outside this transport
API.

The kernel adapter requires a one-to-one association created with
`SctpAuthenticationConfig::data()` and a receive budget of at least
`MAX_DTLS_SCTP_RECORD_BYTES`. Its receive queue capacity must be between
`MIN_DTLS_SCTP_RECEIVE_QUEUE_MESSAGES` (32) and
`MAX_DTLS_SCTP_RECEIVE_QUEUE_MESSAGES` (4,096), inclusive. It rejects a
non-pristine SCTP-AUTH state instead of trying to adopt an association whose
key history it cannot prove. The live kernel loopback qualification test is
opt-in because it requires host kernel SCTP, SCTP-AUTH, and sender-dry
support; deterministic adapter and protocol tests run on every supported
build host.

The original sequential connection methods remain available for capability
setup and narrow integrations. Long-lived use should consume a negotiated
TLS/TCP or DTLS/SCTP connection into the bounded runtime instead of wrapping
that handle in an external mutex. The SDK owns transport framing,
cryptographic sequencing, exact peer authentication, readiness evidence,
bounded full-duplex I/O, and fail-closed retirement. Products still own peer
topology, listener/reconnect policy, external IPsec attestation, and Diameter
application state.

## Verification

```bash
cargo test -p opc-diameter-transport
cargo clippy -p opc-diameter-transport --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc -p opc-diameter-transport --no-deps --all-features
python3 scripts/check-vendored-dimpl.py
```
