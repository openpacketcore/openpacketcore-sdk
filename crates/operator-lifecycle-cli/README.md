# operator-lifecycle-cli

## Purpose

`operator-lifecycle-cli` is an internal binary that exposes Rust lifecycle
contracts to non-Rust operators over JSON stdin/stdout. It is intended for Go
controller-runtime controllers that need the SDK admission, compatibility,
config-apply, or dataplane preflight logic without reimplementing it.

## API Shape

The binary accepts one subcommand:

- `version`: prints `contractVersion` and `crateVersion`; no stdin required.
- `admission`: reads an `AdmissionRequest` plus `expectedContractVersion` and
  returns `AdmissionResponse`.
- `compatibility`: reads `CompatibilityRequest` plus
  `expectedContractVersion` and returns `CompatibilityDecision`.
- `config-apply`: reads `ConfigApplyRequest` plus `expectedContractVersion`
  and returns `ConfigApplyDecision`.
- `preflight`: reads `PreflightRequest` plus `expectedContractVersion` and
  returns `DataPlanePreflightReport`.

All JSON responses include `contractVersion` on success. Errors are sanitized
and also include `contractVersion` when available.

## Usage

```sh
cargo run -p operator-lifecycle-cli -- version
```

```sh
printf '%s\n' '{
  "expectedContractVersion": 1,
  "uid": "example",
  "runtime_mode": "lab",
  "claims_ha": false,
  "config_backend": "sqlite",
  "session_backend": "fake",
  "admin_auth": {"token_enabled": false, "admin_token": null},
  "identity": {"kms_enabled": false, "spiffe_enabled": false}
}' | cargo run -p operator-lifecycle-cli -- admission
```

## Relationships

- Wraps `operator-lifecycle` decisions.
- Uses `opc-node-resources` to build production preflight reports from CLI
  resource-profile and node-capability JSON.
- Used by integration tests through Cargo's `CARGO_BIN_EXE_operator-lifecycle-cli`
  path.

## Status And Limits

- Unpublished binary crate (`publish = false`).
- `expectedContractVersion` is required on stdin for every subcommand except
  `version`.
- Exit code `0` means success, `1` means JSON/validation/runtime command
  error, and `2` means missing or mismatched contract version.
- Stdin is capped at 1 MiB.
- The CLI does not watch Kubernetes resources, run a server, or persist state.

## Roadmap

- Add subcommands only for stable pure-Rust contracts.
- Bump `operator-lifecycle::CONTRACT_VERSION` when request/response envelope
  compatibility changes.
- Keep CLI error text sanitized because controller logs often persist it.

## Verification

```sh
cargo test -p operator-lifecycle-cli
cargo run -p operator-lifecycle-cli -- version
```
