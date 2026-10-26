# opc-tokio-fd-sys

`AsyncOwnedFd` consumes an `OwnedFd` and registers it with Tokio's Unix reactor.
It exposes shared readiness operations and descriptor borrowing, with no
mutable or owning access to the inner registration. Tokio deregisters before
closing the descriptor. Callers supply a nonblocking descriptor supported by
the reactor; raw descriptor integers and generic `AsRawFd` implementations are
not accepted. No descriptor is duplicated.

This is the narrow registration exception described in
[ADR 0017](../../docs/adr/0017-sctp-transport-ffi-boundary.md), addressing the
lifetime contract in [RUSTSEC-2026-0386](https://rustsec.org/advisories/RUSTSEC-2026-0386.html).
The API is Unix-only. Socket readiness/drop tests run on macOS and Linux;
compile-fail tests reject descriptor replacement, extraction and raw integers.
SCTP and timer consumers retain their platform-specific qualification.
