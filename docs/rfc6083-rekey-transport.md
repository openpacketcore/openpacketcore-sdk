# Coordinated RFC 6083 rekey

`rfc6083::Policy::with_rekey` opts both peers into a fresh, mutually
authenticated DTLS 1.2 handshake on their existing SCTP association. Each
application explicitly calls `Connection::rekey(deadline)`: the connector
starts ClientHello and the acceptor waits. The upper layer coordinates this
decision as required by [RFC 6083 section 4.6](https://www.rfc-editor.org/rfc/rfc6083.html#section-4.6).
The default generic profile and Diameter API do not initiate renegotiation.

The initial handshake negotiates RFC 5746. Subsequent ClientHello binds to
the previous client Finished; ServerHello binds to both previous Finished
values. Missing, duplicate, malformed or mismatching bindings, and the
initial-handshake SCSV during rekey, are refused. Comparisons use constant
time equality. A protected rekey ClientHello does not enter the initial
stateless cookie reset, which would discard retained application records.
See [RFC 5746 sections 3.4–3.7](https://www.rfc-editor.org/rfc/rfc5746.html#section-3.4).

Rekey retains the exact expected SPIFFE peer, credential/trust epoch, CRL
publication when required, cipher and protected PPID. The existing bounded
chain verifier runs again. Credential or CRL replacement/withdrawal remains
terminal, including during a pending handshake. The original absolute
association lifetime can only shorten. Rekey cannot renew expired authority
or install a different credential epoch; those changes require a fresh
association. Every polled failure or cancellation closes the carrier.

## Record and SCTP key boundaries

Application writes pause during rekey. Already authenticated application
records and their exact stream correlations survive it. The engine buffers
new-epoch ciphertext that overtakes ChangeCipherSpec or Finished and releases
plaintext only after peer Finished verification. Retired epochs cannot
deliver new plaintext. DTLS epoch exhaustion refuses another handshake.
Old-key record sequence numbers and AEAD usage counts continue until the
transition; a new handshake does not reset an old key's encryption budget.

Each handshake derives a fresh 64-byte `EXPORTER_DTLS_OVER_SCTP` secret.
The existing SCTP-AUTH installation, sender-drain, activation and previous-key
retirement barriers run again: ChangeCipherSpec uses the previous key;
Finished starts the new epoch. The receive task drains the real SCTP socket
before publishing a received ChangeCipherSpec or alert. The new
`SctpAssociationReceiveHalf::recv_buffered` reports an empty buffer only after
a nonblocking receive returns `EAGAIN`; an already-started partial message
must finish first. Queues remain bounded and exhaustion closes the carrier.
These implement the cross-stream obligations in
[RFC 6083 sections 4.7–4.9](https://www.rfc-editor.org/rfc/rfc6083.html#section-4.7).

`Evidence::record_epoch` is the completed DTLS record epoch;
`Evidence::allows_rekey` is local policy. Neither is independent kernel key
inventory or external-peer interoperability evidence. No key material is
exposed by the public API or diagnostic formatting.

## Qualification

The vendored fork is checked with both its all-features and RustCrypto-only
profiles. Real mutual-handshake tests exercise all three admitted ciphers,
three successive rekeys, queued old records, fresh exporters, retired-epoch
rejection and new ciphertext arriving before peer Finished. SDK tests cover
stream correlation, cancellation, original age bounds and credential/CRL
withdrawal in both roles.

Independent Python generators under `vendor/dimpl/tests/dtls12` import no SDK
code. `rfc5746_binding_reference.py --check` verifies 100 extension fixtures
(five admissions), SHA-256
`5fd96cca2217123dbe4e9157761366882785557f18b1125ca6bdad27260f5d1e`.
`rfc5746_hello_reference.py --check` verifies 13 independently framed,
AES-GCM-protected Hello fixtures using the fixed record-test key schedule.
Their SHA-256 is
`c309c45f83cf4c442de014e29ad3049c10998daa1883866f5f6549a01b527ab0`.
These separate parser/binding evidence from real certificate handshakes.
Duplicate extensions are refused by the existing Hello parser before the
binding check; the SCTP operation deadline still bounds incomplete progress.

Nine production guard removals compile and fail their exact runtime tests:
both Hello binding call sites, binding equality, old-key AEAD accounting,
epoch exhaustion, queued plaintext retention, original lifetime retention,
operation cancellation and native SCTP key activation. A separate mutation
of an independent accepted binding also fails at runtime. Sources are restored
byte for byte before final qualification.

`ci/qualify-rfc6083-native.sh` explicitly resolves and executes ten native
cases; ordinary ignored tests do not qualify the native carrier. The rekey
case uses three real SCTP associations, all three ciphers and three rekeys
per peer, preserving unread records on streams 0, 1 and 15 and exchanging new
records on stream 2. A fresh nested network namespace excludes traffic from
earlier fault tests. `qualify-rfc6083-rekey-wire.py` independently captures
synthetic loopback traffic and retains a PCAP and JSON metadata. It requires
six directions, actual SCTP-AUTH key IDs 0 through 4 matching DTLS epochs,
old-key ChangeCipherSpec, a handshake record first under each new key, and
zero capture drops. Successful native receive additionally exercises kernel
authentication; the capture does not itself verify HMACs or key deletion.

The additional [named endpoint case](rfc6083-server-name.md) keeps the exact
SNI name and server DNS SAN constraint through rekey and protected delivery.

This increment supplies coordinated rekey within the existing ECDHE-ECDSA
and SPIFFE certificate profile. Full 3GPP PKI/profile coverage, remote CRL
retrieval, OCSP, DTLS 1.3, resumption and external-peer interoperability are
outside this contract. The older pinned fixture catalog keeps its original
scope. Tracking: #794, #784 and #795.
