# Ordered application streams for RFC 6083 transport

`rfc6083::Policy::ordered_streams(protocol, maximum_plaintext_bytes,
stream_count, pending_record_capacity)` extends the original
[generic transport](rfc6083-generic-transport.md) with an explicit application
stream range. Pass the policy to either endpoint role, including the
[required-CRL constructors](rfc6083-crl-transport.md). The original stream-zero
constructor and the Diameter procedure APIs keep their existing profile.

## Public contract

`stream_count` is an exclusive local upper bound, from 2 through 65,535.
`Connection::send_on_stream` sends on a selected stream in that range;
`send` selects stream zero. `ApplicationMessage::stream_id` returns the stream
of the exact decrypted record. Its byte accessors and redacted formatting
remain unchanged. Readback reports the configured range and correlation
capacity, not a negotiated stream count. The caller must configure SCTP
appropriately; the kernel separately enforces the negotiated send range.
NGAP UE/non-UE stream assignment and procedure admission remain caller-owned.

Every application record is one reliable ordered SCTP user message with the
selected protected PPID, 47 or 66. Ordering is within each SCTP stream; no
global application ordering is promised across streams. Handshake, CCS and
alert records always use reliable ordered stream zero, as required by
[RFC 6083 section 4.4](https://www.rfc-editor.org/rfc/rfc6083.html#section-4.4).
Nonzero control records, unordered delivery, foreign PPIDs, truncation,
notifications, out-of-range streams and non-exact record framing are terminal
errors. The existing 16,347-byte maximum application payload and empty-record
support remain. Each policy may select a smaller positive payload bound.

This profile uses DTLS 1.2 classic headers. Protected records must carry
`fe fd`, the version in
[RFC 6347 section 4.1](https://www.rfc-editor.org/rfc/rfc6347.html#section-4.1).
The engine's initial-handshake DTLS 1.0 compatibility does not authorize that
version on protected records. DTLS 1.3 unified headers are refused. This
adapter check does not change the vendored engine or the original stream-zero
framing policy. Certificate authentication and cipher negotiation remain
DTLS 1.2 in all these profiles.

## Correlation and lifetime

The sealed carrier consumes a pristine real SCTP association configured for
authenticated DATA. SCTP-AUTH protects the stream metadata, while the DTLS
engine authenticates and decrypts the record. Before feeding a record to the
engine, the association retains its epoch/48-bit-sequence-to-stream mapping.
Application output must carry the engine-issued record identity from the
[record-correlation seam](rfc6083-record-correlation.md); only that exact key
can remove and return the retained stream. Receive order, the most recently
seen stream and application payload contents never determine the stream.
A duplicate pending key cannot replace its original stream.

`pending_record_capacity` is 1 through 4,096. It independently bounds retained
correlation entries and queued plaintexts. A record the engine discards can
retain an entry until the connection closes; exhausting either bound fails
the connection. This finite resource budget is not a replay window and does
not change the RFC 6083 engine's replay policy. SCTP supplies reliable
per-stream delivery. No correlation state is shared across associations,
persisted across restart, or reused by a replacement connection.

The existing exclusive connection, absolute deadlines, operation cancellation,
post-operation checks, sender drains and SCTP-AUTH transitions remain in
force. Material or required-CRL replacement/withdrawal retires the connection
before queued plaintext can be returned. Invalid local stream selection also
fails the connection. Readback never revives it. Close uses authenticated
stream-zero alerts and the existing reciprocal sender-drained shutdown.

## Qualification and limits

`crates/opc-diameter-transport/tests/fixtures/rfc6083/streams.py` independently
classifies RFC framing obligations and the explicit local profile rules. It
imports no SDK code. Run it with `--check` to compare the checked-in TSV. The
18,560 cases include 92 framing admissions and 18,468 refusals; SHA-256 is
`9d6bf635d944770d97d6577691cf9a5cbebf4287c015dbfad87f085f9a9b7369`.
These are synthetic framing shapes, not valid ciphertext or peer
interoperability evidence. Engine authentication is tested separately.

Runtime tests use real mutually authenticated DTLS connections in both roles,
all three allowed ciphers, both protected PPIDs, empty and maximum payloads,
and boundary streams. Deliberately reversed encrypted-record buffering must
retain the exact stream, including empty plaintexts. Other tests cover pending
key collisions, both capacity bounds, missing correlations, control-stream
refusal, material withdrawal, cancellation, and mutations of authentic record
headers, ciphertext and tags. The original runtime gap detector fails on the
feature base before the new policy and correlation implementation.

The ignored `generic_kernel_multistream_preserves_payload_streams_and_close`
test must be run explicitly in an isolated Linux SCTP-AUTH network namespace.
It qualifies interleaved streams 0, 1, 2 and 15 in both directions, within-stream
ordering, empty/maximum payloads, authentication readback and reciprocal
close. Ordinary passing tests with this case ignored do not supply native
carrier evidence. The existing native generic, CRL and Diameter cases remain
required regression evidence.

This increment supplies transport streams, not complete NGAP stream ownership
or procedure handling. Full 3GPP PKI, network CRL retrieval, OCSP, in-place
renegotiation, persistent restart and multihoming qualification remain outside
its scope. The older pinned stream-zero fixture schedules keep their original
meaning. Tracking: #794, #784 and #795; their remaining acceptance criteria
are not claimed complete by this profile.
