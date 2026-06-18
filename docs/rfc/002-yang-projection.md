# OPC-SDK-RFC-002: YANG-to-Rust Projection and Codegen Engine

**Status**: Draft for Implementation  
**Version**: 2.0.0  
**Date**: 2026-05-19  
**Audience**: SDK implementers, YANG model authors, NF teams, operator authors

## 1. Abstract

This RFC defines how OpenPacketCore projects YANG models into Rust data
structures, validators, serializers, patch applicators, metadata tables, and
operator-facing schemas. The generated code must preserve YANG semantics,
support RFC 7951 JSON encoding, avoid stack blowups on large configurations,
and provide deterministic APIs for the management substrate in RFC 001.

The key correction from the initial draft is that code generation MUST NOT rely
on ad hoc recursive traversal or direct translation of arbitrary XPath strings
into Rust closures. The SDK must compile YANG into a typed intermediate
representation with bounded validation behavior, stable metadata, and
differential tests against a reference YANG engine.

## 2. Scope

### 2.1 In Scope

- YANG 1.1 module loading and schema resolution.
- RFC 7951 JSON serialization and deserialization.
- Rust type generation for config and state trees.
- Validation for type constraints, `must`, `when`, `leafref`, `unique`,
  `min-elements`, `max-elements`, `mandatory`, and defaults.
- gNMI/NETCONF patch application metadata.
- Secret/redaction metadata for RFC 001 and RFC 003.
- Runtime schema metadata consumed by gNMI, NETCONF, NACM, audit, and operator
  policy helpers.
- Conformance tags for RFC 006.

### 2.2 Out of Scope

- Runtime session state schema. See RFC 004.
- Protocol wire codecs. See RFC 005.
- UI form generation.
- Go/Kubernetes CRD generation. Product operators own their API shape and may
  consume the generated Rust schema/policy metadata through RFC 009 helpers.
- Support for proprietary YANG extensions unless explicitly registered in the
  extension registry defined here.

## 3. Design Goals

### 3.1 Security

- Generated deserializers must reject unknown, ambiguous, duplicate, or
  malformed fields unless the relevant protocol explicitly allows them.
- Secret leaves must use secret-aware generated types and redaction metadata.
- Generated validators must not panic on hostile input.
- Generated code must avoid `unsafe` unless an RFC-specific exception is
  approved and fuzzed.

### 3.2 Performance

- Validation must be linear or near-linear in the size of the config for common
  cases.
- Large lists must validate through generated indices, not repeated global
  depth-first searches.
- Generated root structs must keep stack footprint bounded.
- Patch application must avoid full-tree clone when structural sharing is
  enabled.

### 3.3 Maintainability

- Code generation must be deterministic for identical inputs.
- Generated files must have stable names, stable item order, and stable
  formatting.
- Constraint lowering must go through a typed IR that can be inspected, tested,
  and rendered.
- Generated APIs must be boring and consistent across all NFs.

### 3.4 Functionality

- Support canonical YANG schema features required by 3GPP and IETF models.
- Preserve presence, default, namespace, ordering, and key semantics.
- Emit enough metadata for NACM, audit, gNMI paths, and conformance mapping.
- Support schema migrations between SDK releases.

## 4. Inputs and Outputs

### 4.1 Inputs

The code generator consumes:

- YANG module files.
- A module lockfile containing exact module names, revisions, and checksums.
- A generation profile.
- Optional extension registry.

### 4.2 Outputs

For each generation unit, the tool emits:

- Rust structs, enums, newtypes, validators, serializers, and patch applicators.
- Static schema metadata tables.
- Path constants and path parser helpers.
- Redaction and NACM metadata.
- Property test fixtures.
- `schema-digest.json` for runtime compatibility checks.
- `conformance-tags.json` for RFC 006.

Generated output MUST be reproducible from the lockfile and profile.

## 5. Schema Resolution Pipeline

### 5.1 Frontend

The frontend MUST parse YANG 1.1 and preserve:

- Module and submodule identity.
- Revision.
- Namespace and prefix.
- Imports and includes.
- Extension statements.
- Source locations for diagnostics.

The implementation MAY use `libyang2` through a safe wrapper or a native Rust
parser. In either case, the SDK MUST include differential tests against at least
one reference YANG implementation for supported constructs.

### 5.2 Middle-End

The middle-end MUST produce a flattened schema IR by resolving:

- `typedef`
- `grouping` and `uses`
- `augment`
- `deviation`
- `refine`
- `feature` and `if-feature`
- `identity` inheritance
- module prefixes and namespaces

The flattened model MUST retain enough source mapping to produce diagnostics
that point back to the original YANG module and line.

### 5.3 Backend

The backend emits Rust and schema metadata. It MUST:

- Sort emitted items deterministically.
- Use stable generated filenames.
- Run generated Rust through `rustfmt`.
- Fail generation if generated code does not compile.
- Emit compile-time size checks.

## 6. Rust Type Mapping

### 6.1 Scalar Leaves

| YANG Type | Rust Representation | RFC 7951 JSON Notes |
| :--- | :--- | :--- |
| `int8`, `int16`, `int32` | `i8`, `i16`, `i32` | JSON number |
| `uint8`, `uint16`, `uint32` | `u8`, `u16`, `u32` | JSON number |
| `int64`, `uint64` | `i64`, `u64` | JSON string to avoid precision loss |
| `decimal64` | generated fixed-scale newtype or `rust_decimal::Decimal` | JSON string |
| `string` | `String` or generated constrained newtype | JSON string |
| `boolean` | `bool` | JSON boolean |
| `empty` | generated unit marker | RFC 7951 `[null]` |
| `enumeration` | generated Rust enum | renamed variants preserve YANG names |
| `bits` | generated bitflags/newtype | space-separated string |
| `binary` | `bytes::Bytes` or `Vec<u8>` | base64 string |
| `identityref` | generated enum or `IdentityRef` newtype | namespace-qualified string when needed |
| `instance-identifier` | `YangInstanceIdentifier` | namespace-aware path string |
| `leafref` | generated newtype over target type | encoded like target leaf |
| `union` | generated ordered enum | parse order follows YANG union member order |

Generated constrained newtypes MUST enforce range, length, and pattern
constraints during deserialization and validation.

### 6.2 Containers

YANG containers map to Rust structs. The generator must distinguish:

- Presence containers.
- Non-presence containers.
- Optional generated fields.
- Mandatory generated fields.

Large or optional containers SHOULD be boxed. The generator MUST box a field if
embedding it would make the parent exceed the configured stack budget.

Default stack budget:

```text
max_size_of_root = 4096 bytes
max_size_of_any_struct = 1024 bytes
```

Budgets are profile-configurable. Generated code MUST include compile-time
assertions for these limits.

### 6.3 Lists

YANG list projection depends on key and ordering:

| YANG List Kind | Rust Representation |
| :--- | :--- |
| keyed, `ordered-by system` | `BTreeMap<Key, Value>` |
| keyed, `ordered-by user` | `Vec<Value>` plus generated key index |
| unkeyed config list | `Vec<Value>` with min/max validation |
| `config false` operational list | `Vec<Value>` or backend-specific iterator |

The key type MUST be a generated struct when there are multiple key leaves.
Duplicate keys MUST be rejected during deserialization and patch application.

### 6.4 Leaf-Lists

Leaf-lists map to `Vec<T>` plus generated validation for:

- `min-elements`
- `max-elements`
- uniqueness, when required by YANG semantics
- user ordering
- default values

Generated code SHOULD build a temporary set for uniqueness checks rather than
performing O(n^2) comparisons.

### 6.5 Choices and Cases

`choice` maps to a generated enum. The generator MUST preserve:

- default case
- mandatory choice behavior
- `when` conditions on cases
- removal of sibling case data when a different case is selected

Patch application MUST enforce case exclusivity.

## 7. Presence and Defaults

YANG requires distinguishing absent, defaulted, and explicitly set values. The
generator MUST NOT collapse these states into plain `Option<T>` when protocol
semantics require the distinction.

Generated fields SHOULD use a profile-selected representation such as:

```rust
pub enum LeafPresence<T> {
    Absent,
    Defaulted(T),
    Explicit(T),
}
```

For ergonomic NF logic, generated structs MAY expose helper accessors:

```rust
impl UpfInterface {
    pub fn mtu(&self) -> u16;
    pub fn mtu_presence(&self) -> LeafPresence<&u16>;
}
```

RFC 7951 serialization MUST follow the selected output mode:

- `ExplicitOnly`: omit defaults unless explicitly set.
- `WithDefaults`: include effective defaults.
- `Operational`: include state and effective values.

## 8. RFC 7951 Encoding Requirements

The serializer/deserializer MUST handle:

- Namespace-qualified member names where required.
- 64-bit integers as strings.
- `decimal64` as strings.
- `empty` as `[null]`.
- Base64 for `binary`.
- Identity names with module prefixes when the identity is not in the parent
  namespace.
- Instance identifiers with namespace-aware path segments.
- Duplicate JSON object member rejection.
- Unknown field handling according to protocol profile.

Round-trip tests MUST cover all scalar mappings.

## 9. Constraint IR and Validation

### 9.1 Constraint IR

The generator MUST lower `must`, `when`, range, length, pattern, and other
constraints into a typed IR:

```rust
pub enum ConstraintExpr {
    Path(PathExpr),
    Literal(Literal),
    Function(FunctionCall),
    Compare { op: CompareOp, left: Box<ConstraintExpr>, right: Box<ConstraintExpr> },
    Boolean { op: BooleanOp, terms: Vec<ConstraintExpr> },
}
```

Direct string-to-Rust closure generation is forbidden because it is difficult
to audit, hard to fuzz, and prone to semantic drift.

### 9.2 Supported XPath Profile

The initial SDK profile MUST support the XPath subset required by OpenPacketCore
YANG models and selected IETF/3GPP dependencies. Unsupported expressions MUST
fail generation with a clear diagnostic, not become runtime warnings.

The supported function list must be versioned. Each function implementation
MUST have:

- Unit tests.
- Source-location diagnostics.
- Differential tests against the reference YANG engine.

### 9.3 Validation Engine

Generated validation MUST be split:

- `validate_types`
- `validate_cardinality`
- `validate_choices`
- `validate_when`
- `validate_must`
- `validate_leafrefs`
- `validate_unique`
- `validate_semantics` hook for NF-owned logic

Validators MUST return structured errors:

```rust
pub struct ValidationError {
    pub path: YangPath,
    pub code: ValidationCode,
    pub message: String,
    pub source: Option<YangSourceLocation>,
}
```

Messages MUST be safe for northbound clients and MUST NOT expose secrets.

## 10. Leafref and Indexing

The initial draft required a depth-first search for each `leafref`. That is not
acceptable for large configs.

The generator MUST create validation indices for referenced lists and leaves:

```rust
pub struct ValidationIndices<'a> {
    pub interfaces_by_name: BTreeMap<&'a str, &'a Interface>,
    pub slices_by_s_nssai: BTreeMap<SNssaiKeyRef<'a>, &'a Slice>,
}
```

Validation flow:

1. Build indices in deterministic order.
2. Reject duplicate keys.
3. Validate all `leafref` constraints using the indices.
4. Drop indices before publication.

Index building MUST be iterative and bounded by the configured validation memory
budget.

## 11. Memory Safety and Stack Discipline

Generated code MUST be safe Rust by default.

### 11.1 Stack Budget

The generator MUST calculate `size_of::<T>()` for generated root and nested
types through compile-time tests. Any type exceeding budget must be boxed,
interned, or represented through a collection.

### 11.2 Traversal

Generated validation and serialization MUST avoid unbounded recursive traversal.
Implementations SHOULD use explicit stacks:

```rust
let mut work = Vec::with_capacity(initial_capacity);
work.push(NodeRef::Root(root));
while let Some(node) = work.pop() {
    // validate node and push children
}
```

The SDK MUST define a maximum schema depth and maximum instance depth. Exceeding
either MUST fail parsing or validation with a structured error.

### 11.3 Drop Behavior

Generated models MUST NOT create recursive self-referential types. If future
extensions introduce recursive structures, the generator must provide iterative
drop or arena ownership to avoid stack overflow.

### 11.4 Large Configs

The generator MUST support configs with:

- 100,000 list entries in a single keyed list.
- 1,000,000 scalar leaves across the tree in stress tests.
- Deep but valid schemas up to the configured maximum depth.

Stress tests must verify no stack overflow and bounded peak memory.

## 12. Patch Application

Generated patch applicators MUST support:

- gNMI `Update`
- gNMI `Replace`
- gNMI `Delete`
- NETCONF `merge`
- NETCONF `replace`
- NETCONF `create`
- NETCONF `delete`
- NETCONF `remove`

Patch behavior MUST be generated from schema metadata, not hand-written per NF.

Patch application MUST:

- Validate path existence and key predicates.
- Preserve YANG default semantics.
- Enforce list key immutability.
- Enforce choice/case exclusivity.
- Track changed paths for NACM and audit.
- Avoid mutating `running`; only `candidate` may be modified.

## 13. Secret and Redaction Metadata

The generator MUST mark fields as secret when indicated by:

- `opc:secret`
- `tailf:display-hint "password"`
- configured extension registry entries
- explicit projection profile overrides

Generated secret fields SHOULD use a secret-aware type:

```rust
pub struct SecretLeaf<T> {
    inner: secrecy::SecretBox<T>,
}
```

Generated `Debug`, audit, telemetry, and error rendering MUST redact these
values. Serialization for persistence may include encrypted secret values only
through the RFC 001/RFC 003 envelope.

## 14. Operator Schema Boundary

The generator MUST expose enough Rust schema metadata for operator policy code to
validate compatibility, migrations, admission, and config-apply decisions without
hand-maintained side schemas.

Generated schema metadata MUST include:

- canonical YANG paths and module identity;
- config/state classification;
- list-key ordering;
- NACM action mapping;
- redaction data classes;
- schema digest data for compatibility checks.

The SDK does not generate Go structs or Kubernetes CRD fragments from
`opc-yanggen`. Product operators own their Kubernetes API shape and may use the
Rust `operator-lifecycle`, `operator-controller`, and `operator-lifecycle-cli`
contracts to bridge those APIs into the SDK policy surface. Large NF configs are
therefore split, referenced, or summarized by the product operator rather than by
the YANG generator.

## 15. Schema Migration

Generated code MUST include schema digest metadata. On startup, RFC 001 uses the
digest to determine whether persisted config can be loaded directly or requires
migration.

Migration support MUST provide:

```rust
pub trait ConfigMigration {
    fn from_schema(&self) -> SchemaDigest;
    fn to_schema(&self) -> SchemaDigest;
    fn migrate(&self, input: serde_json::Value) -> Result<serde_json::Value, MigrationError>;
}
```

Migrations MUST be deterministic and tested with golden inputs.

## 16. Implementation Contracts

To keep the generated system modular and reviewable, every generated module
MUST follow this layout:

```text
generated/<module_name>/
  mod.rs
  types.rs
  paths.rs
  serde.rs
  validate.rs
  patch.rs
  metadata.rs
  redaction.rs
  tests/
    roundtrip.rs
    validation.rs
    patch.rs
```

Rules:

- Hand-written code MUST NOT edit generated files.
- Generated files MUST contain a header with generator version and schema
  digest.
- Public generated APIs MUST be documented with YANG path and source module.
- Each generated validation function MUST be small enough for review and have a
  stable name derived from the YANG path.
- Conformance tags for RFC 006 MUST be emitted near the generated item that
  implements the requirement.

## 17. Testing Requirements

### 17.1 Generator Tests

- Deterministic output for identical inputs.
- Stable schema digest.
- Unsupported YANG feature fails generation.
- Differential validation against reference YANG engine.
- Source-location diagnostics.

### 17.2 Generated Code Tests

- RFC 7951 round trips for every scalar type.
- Presence/default serialization modes.
- Leafref validation with large lists.
- `must` and `when` validation.
- Choice/case exclusivity.
- Patch operation matrix.
- Secret redaction.
- Stack size compile-time checks.

### 17.3 Fuzzing

Fuzz targets MUST include:

- RFC 7951 JSON deserialization.
- Path parsing.
- Patch application.
- Constraint evaluator.

Fuzz failures MUST be minimized and committed as regression tests.

### 17.4 Performance Gates

Minimum gates for a generated carrier profile:

- Deserialize 10 MiB RFC 7951 config without stack overflow.
- Validate 100,000 keyed list entries with leafrefs in O(n log n) or better.
- Patch a single leaf in a large config without full serialization.
- Generated root `size_of` below configured budget.
- No unbounded recursion in validation or serialization paths.

## 18. Extension Registry

The SDK MUST maintain a versioned extension registry:

```toml
[[extension]]
name = "opc:secret"
behavior = "secret"

[[extension]]
name = "tailf:display-hint"
value = "password"
behavior = "secret"
```

Unknown extensions default to `ignore-with-warning` only if the generation
profile allows it. Carrier profiles SHOULD fail generation for unknown
extensions that affect config, security, or validation behavior.

## 19. Acceptance Criteria

This RFC is implemented when:

1. Generated Rust preserves YANG presence, defaults, ordering, keys, and
   namespace semantics.
2. RFC 7951 round trips pass for all supported types.
3. Large config validation is bounded and does not use unbounded recursive DFS.
4. Unsupported XPath/YANG constructs fail generation with diagnostics.
5. Generated patch applicators support gNMI and NETCONF operation semantics.
6. Secret metadata integrates with audit redaction and persistence.
7. Operator policy helpers can consume generated schema metadata without a
   hand-maintained side schema or generated Go/Kubernetes projection.
8. Output is deterministic and suitable for parallel implementation.
