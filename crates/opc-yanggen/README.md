# opc-yanggen

YANG ingestion and Rust artifact generator for OpenPacketCore management models.

This crate ingests supported YANG source, lowers it into an internal
representation, emits deterministic schema metadata, and generates Rust support
for config models and management protocol bindings. It is not a general-purpose
YANG compiler.

## API Shape

Library API:

- `compile` and `compile_with_diagnostics`.
- Diagnostics:
  `Diagnostic`, `DiagnosticCode`, and `YangSourceLocation`.
- Emission helpers:
  `emit_fixture`, `emit_fixture_from_canonical`, `emit_stack_metadata`,
  `schema_digest`, `schema_digest_from_canonical`, `fnv1a64`,
  `format_constraint_expr`, `CanonicalInput`, `GenerationInput`,
  `PreScanResult`, and `MAX_CANONICALIZATION_NODES`.
- Public modules:
  `diagnostic`, `emit`, `ir`, `lower`, `source`, and `rust`.
- Rust generation:
  `generate_rust`, `normalize_for_rust_generation`, and
  `RustGenerationError`.

CLI commands:

```sh
opc-yanggen validate-source --input input.json --yang model.yang
opc-yanggen ingest-source --profile cnf-profile --yang model.yang
opc-yanggen generate-rust --profile cnf-profile --yang model.yang --out-dir generated
```

`generate-rust` also supports `--check` and `--prune`; those modes are mutually
exclusive. CLI output is JSON and includes status, schema digest, generated
files, or structured diagnostics.

## Generated Artifact Shape

The Rust generator can emit:

- Config model types and serde support.
- Path constants and changed-path metadata.
- Patch and validation helpers.
- Redaction metadata.
- Schema-registry implementations.
- gNMI JSON/Get and Set support.
- NETCONF XML render and edit support.
- Stack metadata fixtures.

### Keyed-list boundary guarantees

Generated RFC 7951 deserialization treats YANG list keys as an integrity
boundary. Every single or composite key leaf must be present, and a repeated
key is rejected instead of replacing the earlier row in the generated
`BTreeMap`. Both failures use stable diagnostics that never include key
values.

Key leaves with a non-public `opc:data-class` remain available to serde,
ordering, lookup, gNMI, and NETCONF projections, but generated `Debug`
implementations redact them. A sensitive single key uses the generated
`SensitiveKey<T>` wrapper; borrowed `String`/`str` lookup remains available,
while explicit map insertion wraps the owned key with `.into()` or
`SensitiveKey::new`. Its `Debug` and `Display` implementations are redacted;
authorized generated protocol/path code accesses the inner value explicitly.
Composite key diagnostics redact individual sensitive fields. Calling
`redact_sensitive()` continues to hash the map key and corresponding row leaf
together.

## Relationships

- Emits implementations consumed by `opc-config-model`,
  `opc-mgmt-schema`, `opc-gnmi-server`, and `opc-netconf-server`.
- Test fixtures are shared with config, NACM, and management protocol crates.
- Management protocol crates should depend on generated artifacts, not on parser
  internals.

## Status And Limits

Current scope:

- Deterministic ingestion, validation, canonicalization, and Rust generation for
  the supported OpenPacketCore YANG subset.
- Absolute `leafref` validation for both scalar leaves and leaf-lists. Generated
  leaf-list checks validate every element against the referenced target set and
  identify the unresolved element and its index without changing scalar-leaf
  behavior. Empty leaf-lists require no matching target value.
- Fail-closed diagnostics for unsupported or unsafe constructs.

Known constraints:

- `deviation`, arbitrary `extension`, and unresolved `if-feature` usage are
  reported through diagnostics rather than silently accepted.
- Relative `leafref` paths are outside the supported subset and must be modeled
  with an absolute schema path.
- Generated behavior is bounded by the supported subset and should be validated
  with generated tests before production use.

## Roadmap

- Expand YANG feature coverage only when generated config, gNMI, NETCONF,
  redaction, and schema-registry behavior can be produced coherently.
- Keep generated output deterministic so schema digests remain meaningful.

## Verification

Run:

```sh
cargo test -p opc-yanggen
```
