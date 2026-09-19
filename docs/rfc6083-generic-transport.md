# Generic RFC 6083 transport: initial stream-zero profile

This partial implementation of #794 exposes the existing authenticated
DTLS/SCTP boundary without `PeerSession`, Diameter identities, CER/CEA, or
NGAP procedure state. It composes the transport completed under #348 and the
removal of PPID-only security claims under #347. It does not finish #794.

## Public contract

The API lives at `opc_diameter_transport::rfc6083`:

| Symbol | Authority and behavior |
| --- | --- |
| `PayloadProtocol` | Closed configuration choice: Diameter PPID 47 or NGAP-over-DTLS PPID 66. No plaintext PPID 60 or arbitrary integer constructor. |
| `ExpectedPeer` | Typed exact SPIFFE identity; no wildcard and redacted formatting. |
| `Policy` | `ordered_stream_zero` with plaintext limit 1–16,347 bytes inclusive; authenticated empty records are valid. Existing three ECDHE-ECDSA AEAD ciphers and finite maximum age (default one hour). |
| `Transport::from_sctp` | Consumes a pristine `SctpAssociation` configured for SCTP-AUTH DATA, record receive budget at least 18,445 bytes and queue capacity 32–4096. No public DATA methods or extraction of the association. Selecting a PPID does not authenticate it. |
| `Connector` / `Acceptor` | Immutable validated engine configuration, read-only `TlsMaterialController`, expected peer and policy. `connect`/`accept` consumes the carrier under one absolute deadline. Both certificate roles must authenticate. |
| `Connection` | Opaque, non-cloneable ownership of the authenticated engine and carrier. Sequential bounded `send` and `receive` carry opaque records; consuming `close` completes the sender-drained reciprocal protocol. No raw I/O escape. |
| `Evidence` | Borrowed, non-cloneable negotiated role, version, cipher, protected PPID, coherent material epoch, exact expected peer, and local/peer chain expiry. An observation cannot authorize another operation or connection. |
| `ApplicationMessage` / `Error` | Explicit payload extraction and closed, value-free error categories. Debug output contains no identity, record or key values. |

The numeric limits and cipher preference are SDK policy, not inferred standards
requirements. Each operation uses the earlier of the caller's absolute deadline
and the connection's material/certificate/age retirement deadline. The first
poll of `send`/`receive` arms terminal cancellation; dropping an unpolled borrowed
operation does nothing. Dropping a carrier, an unpolled establishment future,
an unpolled consuming close, or a connection closes the association.

Readback and successful application delivery synchronously reconcile the
material status and carrier terminal signal. The independent kernel receiver
sets that signal on terminal notifications, receive errors or queue exhaustion.
Once observed, previously queued plaintext is not delivered. This is not an
oracle for remote failures which the process has not yet observed.

## Reuse and protection boundary

Existing public inputs remain `TlsMaterialController`, `SpiffeId`,
`SctpAssociation` and its SCTP-AUTH configuration. The new API shares the
existing `DtlsSctpPolicy` engine configuration, chain verifier, external
handshake budget, exporter key transitions, retirement watcher, bounded kernel
receiver and reciprocal-close pump. The existing `KernelSctpMessageIo::new`
and Diameter connector/acceptor keep PPID 47 and their procedure admission.
The generic seam never constructs a fake Diameter peer session.

The vendored `dimpl` RustCrypto provider is selected explicitly. Only DTLS 1.2
is admitted. The verifier checks bounded, correctly ordered chains against
trust-domain-scoped anchors, the exact SPIFFE URI, certificate signatures,
validity and role EKU. A connector also requires the server to request and
verify its client certificate. Each association installs the 64-byte
`EXPORTER_DTLS_OVER_SCTP` secret, drains before ChangeCipherSpec, drains again
before activating the new SCTP-AUTH key for Finished, and retires the initial
empty key after peer confirmation. A selected PPID and synthetic fixture
`identity_verified` labels are never authentication evidence.

Credential/trust replacement, explicit source withdrawal, chain expiry and
maximum age retire the admitted epoch. Invalid candidates that retain the
same usable epoch follow the existing material-controller policy. The caller
must establish a fresh association after retirement; in-place rekey or
renegotiation is not exposed.

## Constructed and receive support

| Case | Outcome |
| --- | --- |
| Mutual DTLS 1.2, supported cipher, exact SPIFFE peer, pristine SCTP-AUTH DATA | Protected stream-zero connection on immutable PPID 47 or 66. |
| Opaque application bytes within the admitted bound, including empty record | One authenticated record per reliable ordered SCTP message. No Diameter parsing. |
| PPID 60, foreign protected PPID or plaintext input | Terminal rejection; no application delivery. |
| Nonzero stream, unordered delivery, truncated payload/control data | Terminal rejection. Nonzero stream pairs are not implemented. |
| Bad trust, identity, signature, time, role, missing material or non-mutual handshake | No protected connection. |
| Malformed record bounds | Terminal rejection before record processing. |
| TLS-shaped unsupported version record | No capability; the existing engine may discard it until the unchanged caller deadline. |
| Credential replacement/withdrawal, expiry/age, observed carrier termination | Readback and delivery reject; fresh association required. |
| Pending application data during consuming close, silent peer, cancellation | Bounded terminal failure; no false successful close. |

The profile does not claim complete TS 38.412 NGAP stream handling, 3GPP
TS 33.310 PKI, CRL/OCSP revocation, hardware key custody, DTLS 1.3, in-place
renegotiation, external interoperability, application readiness, or new SCTP
restart and multihoming guarantees. Existing path notifications are handled
by the shared carrier; the new live terminal test proves peer abort only.
The separate exact-record correlation change in #903 is not a dependency of
this stream-zero implementation. Multistream support must correlate the
actual decrypted record with authenticated SCTP metadata, not FIFO position.

## Evidence and reproduction

The contract above records the initial profile and is pinned by its lifecycle
fixtures. Optional later capabilities are documented in
[the current crate contract](../crates/opc-diameter-transport/README.md), including
[coordinated rekey](rfc6083-rekey-transport.md).

The fixture catalog now adds ten independently checked lifecycle families at
`rfc6083-stream-zero-lifecycle`: eight existing client-certificate cases plus
78 authored schedules for both endpoint roles. The lifecycle model pins the
contract above and the unchanged certificate TSV. It records expected labels,
lengths and transitions without importing the SDK or catalog writer. The Rust
replay uses real mutual DTLS at PPID 66 over the private in-memory carrier;
certificate cases also execute at PPID 47. Metadata fault tests preserve real
handshake/encrypted bytes and change only their stream, ordering, truncation,
notification or PPID metadata. No key or packet values enter the fixture log.

```sh
python3 scripts/n3iwf_dtls_lifecycle_reference.py --check
cargo test --locked -p opc-diameter-transport --lib independent_ngap_dtls_lifecycle
```

Reviewed fixture prerequisite: n2-dtls in #830, source
`b1570ed8dc03ca9aaa23bd0b281f8d3d13341a8d`, merge
`987246c8be773b19304f059231c39baa8d54d123`, subtree
`ab3dac0a55f2d4b1793c9a8856838bb2ce0c1d87`, `COMPLETION.json` SHA-256
`0251eb4b1ab722cbf1bfb8bd7bf3bbb8bf096a84bcc44bf7a55618ed9595821e`.
These synthetic headers and PPID octets exercise boundary rejection; they are
not live authentication or interoperability proofs. This change does not
modify the reviewed subset or depend on the unmerged N2-port fixture fix.

`tests/fixtures/rfc6083/certificates.py` uses Python cryptography 49.0.0, independent
of the Rust transport and certificate verifier, to generate deterministic
synthetic P-256 certificates. The eight committed vectors include a valid
client, wrong/missing identity, expired/future validity, wrong EKU, foreign
signer, and one flipped signature bit. Their public test keys have no production
use. A separate Python signature/URI/time/EKU classifier checks expectations;
the Rust test feeds the actual certificates through a real handshake. The
TSV SHA-256 is `f8dff321905c79f06c752b477bc56fc7f2d7a5e67acda40cc2a774bd708f416b`.

Deterministic tests cover both protected PPIDs and all three ciphers, opaque
record bounds, independent certificate negatives, non-mutual and disjoint
cipher handshakes, metadata rejection before and after authentication,
unpolled/blocked handshake cancellation, established send/receive/close
cancellation, handshake-budget saturation, deadlines, credential retirement,
reciprocal close, and terminal readback/queued-delivery rejection. The latter
retains a failing-before-fix detector: without the carrier signal, readback
incorrectly remained active after the peer closed. Compile tests also reject
construction of `Connection` from an ordinary association.

Four Linux kernel tests cover the existing Diameter path, generic protected
PPID 66 handshake/application/reciprocal close, abort-driven terminal readback,
and rejection of unauthenticated, undersized, previously keyed, previously
used or undersized-queue carriers. They require an isolated network namespace
with loopback up and `net.sctp.auth_enable=1`; ordinary test runs ignore these
explicitly. Independent in-memory tests do not establish Linux kernel or
external peer interoperability.

```sh
cargo +1.89.0 test --locked -p opc-diameter-transport --all-features
cargo clippy --locked -p opc-diameter-transport --all-targets --all-features -- -D warnings
python3 crates/opc-diameter-transport/tests/fixtures/rfc6083/certificates.py
# In a fresh privileged network namespace with SCTP-AUTH enabled:
cargo test --locked -p opc-diameter-transport --lib -- --ignored generic_kernel
cargo test --locked -p opc-diameter-transport --lib -- --ignored kernel_loopback
```

The PR records exact SDK base/head/tree, runtime fault-removal results,
independent adversarial mutation, live-kernel executable identity, and local
and hosted gate status. A passing round trip is not an interoperability claim.

## Standards

- [RFC 6083 sections 4–5](https://www.rfc-editor.org/rfc/rfc6083.html): DTLS record carriage, reliable SCTP transport, SCTP-AUTH key transition and drains.
- [IANA SCTP PPID registry](https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml): distinct PPIDs 47, 60 and 66.
- [TS 38.412 V18.1.0 clause 7](https://www.etsi.org/deliver/etsi_ts/138400_138499/138412/18.01.00_60/ts_138412v180100p.pdf): NGAP stream obligations beyond this initial stream-zero API.
- [TS 33.501 V18.12.0 clauses 9.1.2 and 9.2](https://www.etsi.org/deliver/etsi_ts/133500_133599/133501/18.12.00_60/ts_133501v181200p.pdf): N2 security obligations; the SPIFFE profile here does not replace the full referenced 3GPP PKI profile.
