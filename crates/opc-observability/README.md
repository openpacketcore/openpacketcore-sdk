# opc-observability

Reloadable tracing initialization with redacted field formatting.

## Purpose

`opc-observability` installs the SDK tracing subscriber used by binaries that
want a consistent `RUST_LOG`/CLI directive model and redaction-safe field
formatting.

## API Shape

- `init(cli_directive)` installs a global subscriber when this crate owns
  initialization. Directive precedence is explicit CLI value, `RUST_LOG`, then
  `DEFAULT_DIRECTIVE`.
- `set_directive(directive)` hot-swaps the tracing `EnvFilter`.
- `current_directive()` returns the active directive string.
- `ObservabilityError` reports invalid directives, initialization failures,
  reload failures, and use before initialization.
- `DEFAULT_DIRECTIVE` is `info`.

```rust,no_run
use opc_observability::{current_directive, init, set_directive};

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    init(Some("info,opc_runtime=debug"))?;
    set_directive("warn")?;
    assert_eq!(current_directive()?, "warn");
    Ok(())
}
```

## Relationships

- Uses `opc-redaction` to sanitize sensitive field names and values before they
  reach formatted tracing output.
- Optionally used by `opc-runtime` behind its `observability` feature.

## Status Notes

- Bad initial directives fall back to the default directive instead of
  panicking.
- Bad runtime directives return an error and leave the current filter in place.
- Regex matching is disabled in tracing filters.
- Sensitive field names such as SUPI/IMSI/password/token/key variants are
  redacted.

## Roadmap

- Keep initialization idempotent for binaries that compose SDK crates.
- Add exporters only behind explicit features and deployment requirements.
- Keep redaction behavior shared with `opc-redaction`.

## Verification

- Source checked: `Cargo.toml`, `src/lib.rs`, and tests.
- Run with: `cargo test -p opc-observability`.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
