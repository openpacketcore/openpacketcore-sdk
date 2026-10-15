# Initiator admission and independent composition checks

`sa_init_initiator.rs` exercises construction, offer retention, response
correlation, exact transform selection, nonce and KE constraints, COOKIE
replacement, typed retry outcomes, malformed messages and redaction.

`composition.rs` runs against the committed
`../vectors/ikev2_initiator_reference.json`. The reference generator is
`../vectors/ikev2_initiator_reference.py`: it imports no SDK code and invokes no
SDK process. Python `hashlib`/`hmac` implement HMAC-SHA256 and PRF+; cryptography's
OpenSSL backend supplies P-256 ECDH and AES-GCM. Its pinned environment is Python
3.14.6, cryptography 49.0.0 and OpenSSL 3.5.7 (9 June 2026). The generator checks
these versions before calculating or comparing the output.

All inputs are synthetic and public: P-256 private scalars 1 and 2, ascending
byte sequences for SPIs, nonces, the PSK and EAP MSK, `example.test` identities,
and explicit IV counters 1–3. The JSON records that recipe and the versions.
It contains expected wire requests and responses, DH output, SKEYSEED, every
SK value, AUTH with the PSK and EAP MSK, and protected messages in both
directions. The PSK and EAP transcripts are independent alternative fixtures;
their fixed keys and counters must never be used for live traffic.

The EAP transcript covers transport composition and final AUTH with a
key-generating EAP method's synthetic 64-byte MSK. EAP method cryptography,
responder certificate authentication, Child SA negotiation and peer policy
remain caller responsibilities. This fixture is not wire interoperability
evidence and does not claim to implement a complete EAP/IKE state machine.

Run from the repository root, using the repository's prescribed build profile
and a stable worktree-local target directory:

```sh
python3 crates/opc-proto-ikev2/tests/vectors/ikev2_initiator_reference.py --check
cargo test --locked -p opc-proto-ikev2 --test sa_init_initiator --test sa_init_initiator_composition
cargo run --locked --manifest-path crates/opc-proto-ikev2/tests/sa_init_initiator_consumer/Cargo.toml
```

Use `--write` only when intentionally regenerating the independently reviewed
vector. The standalone consumer compiles the same composition source with an
isolated Cargo dependency graph and `opc-proto-ikev2` default features disabled.
Its resolved IKEv2 feature list is empty. This is necessary because the main
crate's integration-test graph enables `testkit` through a dev dependency.

The public API is `build_ike_sa_init_request`, `Ikev2SaInitRequest::message`,
`Ikev2SaInitRequest::with_cookie` and `admit_ike_sa_init_response`. Admission
returns `Ikev2SaInitResponse::Accepted`, `Cookie`, `InvalidKePayload` or
`NoProposalChosen`. An accepted response exposes the profile, SPIr, KEr, Nr
and status notifications. The caller retains its live DH key and the exact
wire transcript, then composes `agree`, `derive_ike_sa_init_key_material`,
protected-payload seal/open and `compute_ike_auth_shared_key_mic` as the test
demonstrates. Errors and wrapper diagnostics retain no wire or key bytes.
