# opc-schema-validate

Lightweight JSON Schema validation for SDK-owned schemas.

## Purpose

`opc-schema-validate` validates the JSON Schema subset used by the
OpenPacketCore evidence and testbed schemas. It is intentionally not a
general-purpose JSON Schema implementation.

## API Shape

- `validate(schema, instance)` validates an instance and ignores `format`.
- `validate_with_format(schema, instance, path, format_validator)` lets callers
  supply a callback for `format` names.
- Errors are human-readable `String` values with JSON-path context.

```rust
use serde_json::json;

let schema = json!({ "type": "string", "minLength": 1 });
let instance = json!("amf");
opc_schema_validate::validate(&schema, &instance).unwrap();
```

## Supported Schema Subset

Supported validation keywords include:

- `type` for single JSON types.
- `required`, `properties`, and `additionalProperties`.
- `items` with a single item schema and `minItems`.
- `minLength`, `minimum`, `const`, `enum`, `oneOf`, and `anyOf`.
- `format` through the caller-supplied callback.
- Annotation keywords such as `$comment`, `$id`, `$schema`, `$defs`, `default`,
  `definitions`, `deprecated`, `description`, `examples`, `readOnly`, `title`,
  and `writeOnly`.

Unsupported keywords fail closed, including `$ref`, `allOf`, `not`,
`if`/`then`/`else`, `multipleOf`, `uniqueItems`, `patternProperties`,
`contains`, dependencies/dependent keywords, `propertyNames`, tuple-item
keywords, `maxLength`, `pattern`, `maxItems`, `maximum`, and exclusive bounds.

## Relationships

- Used by `opc-testbed` for RFC 012 scenario DSL validation.
- Used by evidence/schema tests that need a small deterministic validator.

## Status Notes

- Safe Rust only.
- Array-of-types JSON Schema syntax is not implemented.
- There is no remote reference resolution.
- This crate should not be substituted for a full JSON Schema validator outside
  the SDK-owned schema subset.

## Roadmap

- Add keywords only when SDK-owned schemas require them.
- Keep unsupported keywords fail-closed so schemas do not appear validated when
  they are not.
- Keep `format` validation caller-owned.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, and tests.
- Run with: `cargo test -p opc-schema-validate`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
