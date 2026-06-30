# Operator Lifecycle

Kubernetes production-readiness lifecycle foundation, config-apply, admission, and drain/upgrade planning.

## Status

**Production-ready**

Lifecycle conditions serialize as Kubernetes-style JSON: condition field names
are camelCase, and `lastTransitionTime` is an RFC3339 string.

## Reference

[RFC](https://github.com/openpacketcore/openpacketcore-sdk/blob/main/docs/rfc/009-operator-lifecycle-upgrade.md)

## Quick start

```rust,no_run
use operator_lifecycle::...;

fn main() {
    // See the crate documentation for full API usage.
}
```

## License

This crate is licensed under the [Apache License, Version 2.0](../../LICENSE).
