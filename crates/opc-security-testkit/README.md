# opc-security-testkit

Internal security fixtures for identity, TLS, and KMS tests.

## Purpose

`opc-security-testkit` provides fake but protocol-shaped security services used
by SDK tests. It is for exercising callers of `opc-identity`, `opc-tls`,
`opc-key`, and `opc-crypto` without requiring SPIRE or a production KMS.

## API Shape

- `short_unix_socket_path(name)` creates a short `/tmp` socket path safe for
  Linux `sun_path` limits.
- `FakeCa::new(trust_domain)` creates a test CA. `sign_spiffe_id` returns PEM
  certificate/key material for a SPIFFE ID and expiry.
- `SvidUpdateMsg` is the length-prefixed JSON update payload consumed by the
  fake SPIRE socket and identity watcher tests.
- `FakeSpire::new(socket_path, initial).await` starts a Unix-socket SVID
  source. `rotate(next)` publishes a new update.
- `KmsBehavior` injects delay, unavailable responses, simulated errors,
  truncated/oversized responses, and malformed key hex.
- `FakeKms::new_tcp` and `FakeKms::new_unix` start fake KMS endpoints and
  expose helpers such as `endpoint`, `set_behavior`, `insert_key`, and
  `set_active_key`.

```rust,no_run
use opc_security_testkit::{short_unix_socket_path, FakeCa};

let ca = FakeCa::new("example.org");
let (cert_pem, key_pem) = ca.sign_spiffe_id(
    "spiffe://example.org/tenant/t/ns/default/sa/amf/nf/amf/instance/i-1",
    3600,
);
assert!(cert_pem.contains("BEGIN CERTIFICATE"));
assert!(key_pem.contains("BEGIN PRIVATE KEY"));
let _socket = short_unix_socket_path("spire");
```

## Relationships

- Supports tests for `opc-identity`, `opc-tls`, `opc-key`, `opc-key-vault`, and
  integration crates.
- Implements the fake JSON KMS protocol expected by `opc-key::KmsKeyProvider`.

## Status Notes

- `publish = false`.
- Fixtures use generated test certificates and fake KMS material only.
- `short_unix_socket_path` asserts that names are filename-safe and no more
  than 44 bytes.
- Do not use this crate in production binaries.

## Roadmap

- Keep fake protocols aligned with the SDK clients they test.
- Add fault modes only when a production client has a fail-closed behavior to
  verify.
- Keep the crate unpublished and test-only.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, and security integration tests.
- Run with: `cargo test -p opc-security-testkit`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
