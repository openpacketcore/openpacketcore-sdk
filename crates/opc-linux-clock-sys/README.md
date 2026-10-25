# opc-linux-clock-sys

## Purpose

`opc-linux-clock-sys` is the narrow unsafe boundary for reading the Linux
kernel's clock-adjustment state. It answers one question for the safe
`opc-session-net` authentication-time source: does the kernel currently report
its realtime clock as synchronized, and what are the kernel's maximum and
estimated realtime error bounds?

It does not implement NTP, time synchronization, clock policy, authentication
decisions or wall-clock fallbacks.

## API Shape

- `read_kernel_clock_adjustment()`: one read-only
  `clock_adjtime(CLOCK_REALTIME)` query (`modes == 0`); never modifies the
  clock and never requests a capability.
- `KernelClockAdjustment`: an immutable snapshot with
  `is_synchronized()`, `max_error_microseconds()` and
  `estimated_error_microseconds()`.
- Unsupported platforms compile to a stub whose read fails with
  `io::ErrorKind::Unsupported`; an unsynchronized Linux clock is a successful
  read with `is_synchronized() == false`, not an error.

The kernel's `timex.maxerror` is a maximum error, while `timex.esterror` is an
estimate. Callers that need a bounded authentication interval must use the
maximum and apply their own fixed acceptance budget; they must not widen that
budget on retry.

## Platform contract

- Linux only. The read is unprivileged (`modes == 0` does not adjust anything);
  a seccomp filter, LSM policy or hardened container runtime that refuses the
  syscall surfaces as a typed `io::Error` and callers must fail closed.
- The values are the kernel NTP state, not a portable wall-clock quality
  signal. A node that runs no synchronization daemon typically reports
  `STA_UNSYNC` or the boot-default large error bound; callers must treat that
  as unavailable, not as a wide-but-trusted bound.
- The kernel state is host-global and not namespaced per container, so every
  container observes the same underlying clock state.

## Status And Limits

- Unpublished workspace crate (`publish = false`).
- Contains the syscall `unsafe` allowed only here by its local lint
  configuration; ADR 0017's mechanical boundary gate
  (`scripts/check-management-plane-policy.py`) allow-lists this crate and
  requires an adjacent `SAFETY:` comment on every `unsafe` token.
- Non-Linux or `opc_linux_clock_sys_force_unsupported` builds compile to
  unsupported stubs.
- Does not detect a synchronization daemon that has exited without updating
  the kernel state; supervising the daemon remains a deployment duty.

## Roadmap

- Keep the surface to the one read the safe authentication-time source needs.
- Add layout/ABI tests in this crate before exposing another kernel clock
  structure.

## Verification

```sh
cargo test -p opc-linux-clock-sys
```
