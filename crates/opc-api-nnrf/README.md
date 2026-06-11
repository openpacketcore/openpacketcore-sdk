# opc-api-nnrf

Generated Rust types for the 3GPP TS 29.510 NRF service-based interface —
**experimental pilot** for OpenAPI-to-Rust code generation in the
OpenPacketCore SDK.

## Purpose

Hand-writing the TS 29.5xx request/response models is repetitive and
error-prone; this crate pilots generating them from the published 3GPP
OpenAPI definitions instead. It currently covers `NfProfile`, `NfService`,
their supporting structs, and the `NfType`/`NfStatus`/`NfServiceStatus`
enumerations (each with a forward-compatible `Other(String)` catch-all),
wired to `opc-types` identifiers (`NfInstanceId`, `PlmnId`, `Snssai`)
rather than redundant string wrappers.

## Regenerating

`src/types.rs` is committed; cargo builds never run the generator. To
regenerate (requires Python 3.9+ and PyYAML):

```bash
make generate-api
```

Inputs are pinned by SHA-256 content hash and cached under
`target/api-codegen-cache/`; a hash mismatch aborts generation. Output is
deterministic — regenerating from unchanged inputs is a no-op diff.

See [CONFORMANCE.md](CONFORMANCE.md) for exact coverage and known gaps
versus the hand-written `opc-sbi` discovery subset.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
