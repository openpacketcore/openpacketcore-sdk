# Opc Yanggen

YANG-to-Rust type projection, RFC 7951 JSON serde, iterative semantic constraint validation, and patch applicator.

## Status

**Production-ready**

## Source YANG consistency gate

`opc-yanggen` can validate that one or more source `.yang` modules match a
hand-built or generated `GenerationInput`:

```rust,no_run
use opc_yanggen::{
    validate_generation_input_yang_sources, GenerationInput, YangSource,
};

fn validate(input: &GenerationInput, source_text: String) -> Result<(), opc_yanggen::Diagnostic> {
    let sources = [YangSource::new("openpacketcore-example.yang", source_text)];
    validate_generation_input_yang_sources(input, &sources)
}
```

The gate preserves `SchemaModule::source_text` for NETCONF `<get-schema>` and
checks module metadata, imports, node paths, child relationships, list keys,
config/state flags, type references, defaults, presence markers, ordered-by,
data classes, unique constraints, and the source-derived schema digest. It
supports multiple modules/imports in the API shape.

For downstream CI, the crate also provides:

```sh
opc-yanggen validate-source --input generation-input.json --yang module.yang [--yang import.yang ...]
```

`opc-yanggen ingest-source --profile PROFILE --yang module.yang ...` emits a
starter `GenerationInput` JSON for the supported IR subset.

## Rust artifact generation

Downstream CNFs can generate committed Rust projection artifacts directly from
source YANG without maintaining local wrapper scripts:

```sh
opc-yanggen generate-rust --profile PROFILE --yang module.yang [--yang import.yang ...] --out-dir src/generated
```

The command reads the source modules through the same YANG ingestion path,
canonicalizes the derived `GenerationInput`, and writes the Rust files returned
by `opc_yanggen::rust::generate_rust` into the output directory. The directory
is created when missing. Generated filenames are preserved exactly.

The writer fails closed if the output directory contains stale top-level `.rs`
files that are not part of the current generator output:

```sh
opc-yanggen generate-rust --profile PROFILE --yang module.yang --out-dir src/generated --prune
```

Use `--prune` in write mode to remove stale generated `.rs` files before
writing the current output.

For CI drift detection, use check mode:

```sh
opc-yanggen generate-rust --profile PROFILE --yang module.yang [--yang import.yang ...] --out-dir src/generated --check
```

Check mode does not modify the filesystem. It fails if a generated file is
missing, differs byte-for-byte, or if a stale top-level `.rs` file exists in the
output directory. `--prune` is rejected with `--check`.

Successful generate/check output is structured JSON containing `status`,
`schema_digest`, and the generated `files`; check mode also includes
`"mode": "check"`. Failures use the standard diagnostic JSON envelope.

This first source path is intentionally fail-closed. Constructs not represented
by the current IR, such as `must`, `when`, `uses`, `augment`, deviations, and
extensions other than `*:data-class`, return `DiagnosticCode::UnsupportedYangFeature`
instead of being silently dropped. Documentation/comment-only source changes do
not affect the schema digest.

Deferred: YANG cardinality statements such as `mandatory`, `min-elements`, and
`max-elements` are accepted by the parser for current source skeletons but are
not represented in `GenerationInput` yet, so they are not part of the
consistency comparison or digest contract.

## Reference

[RFC](https://github.com/openpacketcore/openpacketcore-sdk/blob/main/docs/rfc/002-yang-projection.md)

## Quick start

```rust,no_run
use opc_yanggen::...;

fn main() {
    // See the crate documentation for full API usage.
}
```

## License

This crate is licensed under the [Apache License, Version 2.0](../../LICENSE).
