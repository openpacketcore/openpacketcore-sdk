# RFC 6083 record correlation — partial #794

This change supplies a prerequisite for a reusable DTLS/SCTP transport. It
does not expose an NGAP protected connection, enable PPID 66 delivery, or
complete [#794](https://github.com/openpacketcore/openpacketcore-sdk/issues/794).

The existing `opc-diameter-transport` implementation from #348 owns mutual
certificate verification, the audited vendored `dimpl` engine, kernel SCTP
DATA authentication, sender-drain/key transitions, material retirement, and
bounded close. It fixes every record to ordered stream 0 and binds application
delivery to a Diameter `PeerSession`. The generic adapter must reuse those
mechanisms without requiring Diameter procedure state.

## Why record identity is necessary

[RFC 6083 section 4.4](https://datatracker.ietf.org/doc/html/rfc6083#section-4.4)
uses reliable ordered stream 0 for DTLS control records and permits other
streams for application data.
[TS 38.412 V18.1.0 clause 7](https://www.etsi.org/deliver/etsi_ts/138400_138499/138412/18.01.00_60/ts_138412v180100p.pdf)
requires distinct stream pairs for UE and non-UE signalling. The
[IANA registry](https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml)
assigns 60 to NGAP and 66 to NGAP over DTLS/SCTP; choosing 66 supplies no
cryptographic protection.

The reused engine sorts buffered DTLS 1.2 records by epoch and sequence.
It can also discard malformed or unauthenticated records. Its old
`Output::ApplicationData` exposes plaintext alone, so pairing outputs with
SCTP stream identifiers in receive order can assign a payload to the wrong
stream. For example, records arriving as sequence 3 on stream A followed by
sequence 1 on stream B can be released in the reverse order.

## Added engine boundary

`dimpl::Dtls::poll_output_with_record` returns the unchanged `Output` and an
optional `Rfc6083ApplicationRecord`. The record identity comes from the exact
decrypted queue entry that supplied the plaintext. Its private fields have
read-only `epoch()` and `sequence_number()` accessors and fully redacted
`Debug` output.

Only RFC 6083 DTLS 1.2 application output receives this metadata. Short-buffer
retries consume neither part; control events, ordinary DTLS 1.2, and DTLS 1.3
receive no identity. No cached public “last record” value can be mistaken for
a later output. The existing `poll_output` method discards the optional
metadata, retaining its signature, output variants, and record processing.
No engine, wire parser, crypto provider, cipher policy, or key-copy path is
added. The Diameter transport source remains unchanged.

This number is scoped to one receive direction of one DTLS connection. It
does not identify an SCTP stream, authenticate a certificate identity, or
authorize traffic. A future adapter must correlate it with SCTP-authenticated
metadata under the same exclusive association and bound the correlation
storage. It must retire that storage on failure, close, or association
replacement. Receive-order matching and cross-association reuse are invalid.

## Evidence and limits

The new record tests use six fixed AES-128-GCM records independently generated
by Python `cryptography`, without loading SDK code. The fixed synthetic key
schedule is a record-layer test context. The vector file is
`vendor/dimpl/tests/dtls12/rfc6083_record_reference.tsv`, SHA-256
`2968c49701cfa773d047801c27821a95ed15ec1583bcc449a33a7850110f372f`.
Its script documents the TLS PRF, EMS, AEAD, and record-header sources.

Tests cover reversed buffered records, sequences from zero through
`2^48 - 1`, empty plaintext, short-buffer retry, mixed old/new polling,
pending duplicate handling, and ciphertext/header/tag corruption. Public
engine tests exercise both endpoint roles. These are engine-level checks,
not kernel SCTP stream, mutual certificate policy, or external NGAP
interoperability evidence. Existing Diameter and retained vendor suites
remain required validation.

Reproduce the reference and retained engine/consumer checks from the repository
root (Python `cryptography` is needed only to regenerate/check the oracle):

```sh
python3 vendor/dimpl/tests/dtls12/rfc6083_record_reference.py --check
cargo test --locked --manifest-path vendor/dimpl/Cargo.toml --all-features --all-targets
cargo test --locked --manifest-path vendor/dimpl/Cargo.toml --all-features --doc
cargo test --locked --manifest-path vendor/dimpl/Cargo.toml --no-default-features --features rust-crypto --all-targets
cargo test --locked --manifest-path vendor/dimpl/Cargo.toml --no-default-features --features rust-crypto --doc
cargo test --locked -p opc-diameter-transport --all-features
```

The existing ignored
`dtls_tests::kernel_loopback_completes_real_rfc6083_handshake_and_reciprocal_close`
test additionally requires a private Linux network namespace with loopback up,
SCTP support, and `net.sctp.auth_enable=1`. It exercises the unchanged Diameter
adapter; passing it does not establish NGAP stream or PPID 66 support.

The reviewed **n2-dtls** fixture prerequisite was merged through #830: source
`b1570ed8dc03ca9aaa23bd0b281f8d3d13341a8d`, merge
`987246c8be773b19304f059231c39baa8d54d123`, fixture subtree
`ab3dac0a55f2d4b1793c9a8856838bb2ce0c1d87`, completion SHA-256
`0251eb4b1ab722cbf1bfb8bd7bf3bbb8bf096a84bcc44bf7a55618ed9595821e`.
Those fixtures remain unchanged. This prerequisite adds an independent
record oracle; it does not claim to pass their transport scenarios.

Remaining #794 work includes the generic protected connector/acceptor,
stream-aware kernel carriage and authenticated correlation, PPID separation,
certificate/trust and revocation policy, association restart and multihoming
behavior, rotation/rekey policy, and bounded cancellation/close evidence.
`TlsMaterialController` already offers read-only access to source-published
epochs and the shared external-handshake budget; it needs no duplicate
credential authority. The current SPIFFE certificate policy does not establish
the full 3GPP certificate profile referenced by
[TS 33.501 V18.12.0 clause 9.2](https://www.etsi.org/deliver/etsi_ts/133500_133599/133501/18.12.00_60/ts_133501v181200p.pdf).
