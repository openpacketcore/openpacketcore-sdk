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

### Integer widths, names, and string restrictions

All eight YANG integer types are supported with exact ranges through `u64::MAX`.
Generated `YangInt64` and `YangUint64` wrappers encode RFC 7951 JSON values as
strings; smaller integers encode as numbers. XML uses decimal text. Declared
ranges are checked during JSON load, syntax validation, patches, gNMI Set, and
NETCONF edits, including list keys, leaf-lists, and resolved leafrefs.
In models using the new scalar constructs, malformed integer values and JSON
structures receive fixed reasons that never include a supplied value. Subtree
merges validate their typed JSON before applying fields. Models that use any of
the added integer widths compare integer operands in an `i128` domain, including
public constraint IR constants outside a leaf's storage range and chained
references.

Containers and lists with a shared local name receive deterministic names
qualified by their parents, with stable suffixes for remaining collisions.
Composite-key names and generated helper functions use the same name index.
Case-distinct paths have separate pattern caches; references reuse the cache of
their resolved scalar declaration.
Previously valid models using none of the new constructs retain every generated
file byte for byte.

String `length` uses Unicode scalar counts and supports disjoint intervals,
`min`, and `max`. Multiple `pattern` statements are combined with AND; each
matches the whole value using XSD semantics, with `modifier invert-match`
negating that one pattern. Defaults must satisfy the restrictions. Generated
JSON load, direct syntax validation, patches, gNMI Set, and NETCONF edits enforce
them on leaves, leaf-lists, keys, and leafrefs. Failed writes are atomic and
return the existing typed error with a fixed reason that includes no value.

The supported XSD grammar includes grouping, alternation, bounded and unbounded
repetition, character ranges and subtraction, negated classes, Unicode general
categories, and XSD whitespace/digit/word escapes. `^` and `$` are literal
characters. XML-name escapes (`\i`, `\c` and complements) and Unicode-block
escapes (`\p{Is...}`) are explicitly rejected as unsupported; malformed patterns
and constructs from other regex dialects are rejected at generation time.

Pattern matching uses `regex` 1.13.1 (MIT OR Apache-2.0), already present in the
workspace lockfile and now a direct dependency of `opc-mgmt-schema`. A bounded
XSD translator prevents the engine's different syntax from changing semantics.
Each pattern is limited to 4,096 source bytes, 64 nesting levels, and 1 MiB each
for compiled automaton and DFA cache; a string type may declare at most 64
patterns. Generated `OnceLock` storage compiles each declared pattern once and
shares it with leafrefs. No regex dependency is added to generated manifests.

`NumericRangeInterval` in the generator IR now uses `i128` bounds; callers with
typed `i64` bounds must convert them with `.into()`. New `TypeRef` variants cover
the additional integer widths and restricted strings, so exhaustive matches
must handle them. Runtime registries add `integer_ranges()`/`integer_range()`
with `i128` bounds while preserving the legacy `i64` numeric-range API.

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
