# Vendored `dimpl` patch

This directory is based on the `dimpl` 0.7.2 source archive published on
crates.io from <https://github.com/algesten/dimpl>.

- crates.io archive SHA-256:
  `ba6aa42b0c64c3e5311a2afad224b32db1ee129d21c63daaaf8ea747b846cdbc`
- upstream Git commit recorded by the archive's `.cargo_vcs_info.json`:
  `37f950984af1d0c2f86ef21b940c672fb27cd7c7`
- upstream package: `dimpl` version `0.7.2`
- upstream repository: <https://github.com/algesten/dimpl>

The upstream code is dual-licensed under MIT or Apache-2.0; the original
license texts are retained alongside the source. To re-establish provenance
before a rebase, download the exact crate archive and compare:

```sh
curl --fail --location \
  https://static.crates.io/crates/dimpl/dimpl-0.7.2.crate \
  --output dimpl-0.7.2.crate
printf '%s  %s\n' \
  ba6aa42b0c64c3e5311a2afad224b32db1ee129d21c63daaaf8ea747b846cdbc \
  dimpl-0.7.2.crate | sha256sum --check
tar -xOf dimpl-0.7.2.crate dimpl-0.7.2/.cargo_vcs_info.json
```

OpenPacketCore carries a security-scoped patch with the following intentional
changes:

- The explicit mutual-certificate SCTP profile supports a bounded RFC 6066
  server name. It emits and validates a single host_name/empty acknowledgement,
  keeps the configured name through rekey, and rejects missing, malformed,
  duplicate, unsolicited or mismatched negotiation. The embedding SDK adds
  independent certificate DNS SAN checks; the engine's SNI alone is not peer
  authentication. Names and errors are redacted. Independent extension and
  protected-Hello fixtures exercise both production receive call sites.
  See [named SDK endpoints](../../docs/rfc6083-server-name.md).

- Explicitly armed RFC 6083 rekey uses RFC 5746 previous-Finished bindings,
  retains old record keys/sequence/AEAD budgets through ChangeCipherSpec,
  derives fresh handshake keys and exporters, and buffers new-epoch records
  until peer Finished. The opt-in profile requires mutual certificates.
  Independent extension and protected-Hello fixtures exercise both Hello
  validation call sites; real handshake tests cover successive transitions,
  queued old plaintext, old-epoch rejection and cross-stream reordering.
  See [the SDK rekey contract](../../docs/rfc6083-rekey-transport.md).

- DTLS 1.2 RFC 6083 mode disables record replay detection and DTLS flight
  retransmission, fixes the DTLS record budget at 16,384 bytes, and rejects
  configurations that retain any DTLS 1.3 cipher suite. Every output SCTP
  message contains exactly one DTLS record; RFC 5764 `use_srtp` is neither
  advertised nor selected, and an unsolicited server selection fails closed.
- The DTLS 1.2 exporter returns exactly 64 bytes using
  `EXPORTER_DTLS_OVER_SCTP` with no context and zeroizes intermediate and
  returned keying buffers.
- Explicit output barriers order inactive SCTP-AUTH key installation,
  sender-dry, ChangeCipherSpec under the old key, sender-dry plus activation,
  and Finished as the first record under the new key. Graceful reciprocal
  `close_notify` has a corresponding sender-dry barrier.
- Certificate handling retains and emits the full leaf-to-root peer chain,
  serializes configured intermediate certificates, enforces eight
  certificates/64 KiB per certificate/256 KiB aggregate DER bounds, and
  zeroizes configured private-key bytes on drop. Both DTLS versions retain
  retry-safe borrowed `PeerCert` evidence for a singleton and emit an owned
  `PeerCertChain` for multiple certificates.
- Mutual certificate authentication is explicit in both directions:
  `require_client_certificate` rejects an empty client Certificate and
  `require_server_certificate_request` rejects a server that omits
  CertificateRequest. The client policy is default-off and incompatible with
  PSK authentication.
- Cryptographic providers are validated with known-answer tests before
  `ConfigBuilder::build` returns, provider installation failures are typed, and
  both built-in backends implement the same validation surface, including
  every supported DTLS 1.2 AEAD suite and its exact record metadata. The
  infallible `Config::default` construction path is removed so no public
  constructor can bypass provider validation.
- DTLS 1.2 AES-GCM explicit nonces are the exact epoch-plus-48-bit-sequence
  value on the wire. Sequence and configured per-key AEAD limits are
  preflighted before encryption, transcript mutation, retransmission queue
  mutation, or sequence consumption.
- Pooled and temporary cryptographic buffers, PRF workspaces, traffic keys,
  IVs, PSKs, pre-master/master secrets, cookie secrets, and queued local
  keying-material events are wiped or held in zeroizing custody.
- Parsers, buffer handling, cryptographic state transitions, sequence-number
  limits, and public endpoint state fail closed with typed errors or safe
  no-output behavior instead of production `unwrap`, `expect`, or `panic`.
- Diagnostic formatting redacts PSK identities and hints, RNG seeds, session
  identifiers, cookies, certificates, application data, and exported keying
  material.
- `Dtls::poll_output_with_record` pairs RFC 6083 application plaintext with
  its exact decrypted DTLS epoch and 48-bit sequence. The record number is
  taken from the same queue entry as the plaintext, after the output-capacity
  check. Control events and other DTLS profiles return no identity. The
  existing `poll_output` API discards the optional metadata and preserves its
  output shape and behavior. This enables later SCTP stream correlation;
  neither the record number nor the engine alone attests peer certificate
  policy or authenticated SCTP delivery (Refs SDK #794).
- The vendored manifest is marked `publish = false`, adds `zeroize`, and keeps
  the upstream integration-test targets and development dependencies.

RFC 6083 behavior is deliberately DTLS 1.2-only. The DTLS 1.3 implementation
retains shared certificate, provider-validation, parsing, error, and redaction
hardening, but contains no RFC 6083 exporter or output-barrier path.

The archive's complete `tests/` tree is retained: no integration target or test
is removed. Twelve upstream test files carry only mechanical compatibility
changes, and `tests/dtls12/rfc6083.rs` adds the profile integration proof:

- ten `DtlsCertificate` literals add an empty `intermediates` field;
- uses of the removed `Config::default` API build and validate the default
  configuration explicitly; and
- integration modules disabled without `rcgen` allow their otherwise-unused
  imports, keeping the RustCrypto all-target lint gate warning-free; and
- `tests/ossl/io_buf.rs` uses `Vec::clear` for compatibility with the current
  all-target Clippy gate.

Inspect those adapters after extracting the archive:

```sh
tmpdir="$(mktemp -d)"
tar -xf dimpl-0.7.2.crate -C "$tmpdir"
diff -qr "$tmpdir/dimpl-0.7.2/tests" vendor/dimpl/tests
```

The expected changed paths are `tests/auto/main.rs`, `tests/dtls12/common.rs`,
`tests/dtls12/crypto.rs`, `tests/dtls12/edge.rs`,
`tests/dtls12/fragmentation.rs`, `tests/dtls12/handshake.rs`,
`tests/dtls12/main.rs`, `tests/dtls12/ossl.rs`, `tests/dtls12/psk.rs`,
`tests/dtls12/retransmit.rs`, `tests/dtls12/rfc6083.rs`, and
`tests/dtls13/main.rs`, plus `tests/ossl/io_buf.rs`.

The additional `tests/dtls12/rfc6083_record_reference.py` and `.tsv` contain
six synthetic record-layer vectors reproduced with Python `cryptography`
AES-GCM, independent of the Rust providers. They initialize the same fixed
test key schedule as the engine unit tests; they are not certificate or
SCTP-AUTH handshake evidence. Regenerate with the Python script, or pass
`--check` to detect drift. See the SDK's
[`RFC 6083 record-correlation scope`](../../docs/rfc6083-record-correlation.md)
for the remaining generic-transport work.

Packaging and repository-development metadata that does not participate in the
vendored build is deliberately omitted: `.cargo/`, `.github/`, `.vscode/`,
`.gitignore`, `.taplo.toml`, `.cargo_vcs_info.json`, `AGENTS.md`, `CHANGELOG.md`,
`Cargo.toml.orig`, `cargo_deny.sh`, `clippy.toml`, and `deny.toml`. The archive
checksum and embedded Git commit above preserve their
provenance; workspace formatting, lint, test, and dependency-policy gates
replace the omitted project-local tooling.

Because a root `[patch.crates-io]` table is not honored when this repository is
itself consumed as a Git dependency, the non-publishable workspace consumer
must use an exact direct path dependency (`version = "=0.7.2"` plus
`path = "../../vendor/dimpl"`). The provenance gate must confirm that Cargo
metadata reports `source: null` for `dimpl` rather than a registry source.

## Verification gates

`ConfigBuilder::build` validates the selected cryptographic provider before it
can be used. The validation covers SHA-256/SHA-384 hashes, TLS 1.2 PRF,
HMAC-SHA256, ECDSA verification, every supported DTLS 1.2 AEAD,
DTLS 1.3 AEAD encryption/decryption, record-number protection, and supported
key-exchange agreement. The AEAD and record-number vectors are identified in
source by their NIST or RFC origin. The PSK_AES128_CCM_8 vector was
independently reproduced with Python `cryptography`'s
`AESCCM(tag_length=8)` using the exact source key, nonce, AAD, and plaintext.
The RFC 6083 exporter also has a fixed 64-byte RFC 5705/P_SHA256 vector computed
independently with Python's `hmac`/`hashlib`, rather than comparing only the two
DTLS endpoints.

Run formatting, both built-in providers, every retained integration target,
all-target linting, production panic lints, and the source-level invariant
gates after every vendor change:

```sh
cargo fmt --manifest-path vendor/dimpl/Cargo.toml --all --check
cargo test --manifest-path vendor/dimpl/Cargo.toml \
  --all-features --all-targets
cargo test --manifest-path vendor/dimpl/Cargo.toml \
  --all-features --doc
cargo test --manifest-path vendor/dimpl/Cargo.toml \
  --no-default-features --features rust-crypto --all-targets
cargo test --manifest-path vendor/dimpl/Cargo.toml \
  --no-default-features --features rust-crypto --doc
cargo clippy --manifest-path vendor/dimpl/Cargo.toml \
  --all-features --all-targets -- -D warnings
cargo clippy --manifest-path vendor/dimpl/Cargo.toml \
  --no-default-features --features rust-crypto --all-targets -- -D warnings
cargo clippy --manifest-path vendor/dimpl/Cargo.toml --all-features --lib -- \
  -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
cargo clippy --manifest-path vendor/dimpl/Cargo.toml \
  --no-default-features --features rust-crypto --lib -- \
  -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
! rg -n '\b(unreachable!|unimplemented!|todo!)' vendor/dimpl/src
! rg -n 'Rfc6083|rfc6083' vendor/dimpl/src/dtls13
! rg -n 'impl Default for Config|Config::default\(\)' \
  vendor/dimpl/src vendor/dimpl/tests vendor/dimpl/README.md
```
