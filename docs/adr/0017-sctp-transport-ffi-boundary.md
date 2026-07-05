# ADR 0017: SCTP Transport Strategy and Unsafe-FFI Sys-Crate Boundary

## Status

Accepted

## Date

2026-06-13

## Context

ADR 0014 §8 states `unsafe_code = "forbid"` is workspace-wide and
"non-negotiable, which also rules out FFI-based protocol libraries (see ADR
0013)." ADR 0013 rejected Option C — FFI to the srsRAN/OAI **C NGAP codec** —
because foreign C code parsing attacker-controlled bytes turns memory-safety bugs
into SDK security issues.

`opc-sctp` is required for CNFs that terminate
N2/NGAP or other SCTP interfaces. Unlike NGAP, SCTP is not a codec — it is an
**OS transport**. Linux implements SCTP in the kernel (lksctp); a userspace
program reaches it through SCTP sockets:
`socket(AF_INET, SOCK_STREAM|SOCK_SEQPACKET, IPPROTO_SCTP)`, SCTP `setsockopt`
options, `sendmsg`/`recvmsg` with SCTP control messages, and, where necessary,
thin `libsctp` helper calls such as bind/send/receive variants over the same
kernel SCTP UAPI. Rust's `std` and `tokio` expose **no** SCTP socket API, so
reaching kernel SCTP requires `libc`/UAPI FFI, which is `unsafe`. ADR 0014 §8 was
written for protocol *codec* libraries and did not anticipate an OS-transport
syscall surface.

The distinction is decisive:

- **ADR 0013's rejected FFI** links a large foreign **C parser** (thousands of
  lines) that consumes attacker-controlled wire bytes. The attack surface is the
  C code itself.
- **SCTP FFI** is a thin wrapper over **kernel socket UAPI** and optional
  `libsctp` helper functions that themselves configure or call the kernel SCTP
  stack. The SCTP protocol implementation is the kernel — already trusted,
  exactly as for TCP/UDP. This is the *same* category of `unsafe` that
  `tokio`/`mio` already use internally for socket I/O in the workspace. The
  "foreign C parsing attacker bytes" risk ADR 0013 guarded against simply is not
  present.

## Options

- **A. Kernel SCTP behind a narrow `opc-libsctp-sys` sys crate.** Thin
  `libc`/SCTP-UAPI FFI in one crate, including `libsctp` helpers only where the
  Linux SCTP API requires them; a safe `opc-sctp` wrapper above it. Linux-only.
- **B. Userspace SCTP stack (pure Rust).** Reimplement the SCTP transport
  protocol with no FFI. Rejected: a from-scratch transport-protocol
  implementation is large and security-sensitive (association state machine,
  retransmission, multihoming, chunk bundling) and is *more* likely to harbor
  exploitable bugs than thin syscall FFI over the hardened kernel stack; no
  maintained pure-Rust SCTP stack exists to adopt.
- **C. Omit SCTP from the SDK.** Ship no SCTP transport. Acceptable only if the first
  production CNF does not terminate N2/NGAP or any SCTP interface; it blocks
  N2-terminating CNFs.

## Decision

Amend ADR 0014 §8 to permit a **narrow, explicitly allowlisted** unsafe
exception pattern for Linux kernel UAPI sys crates, and adopt **Option A** when
an SCTP-terminating CNF is in scope:

1. **`opc-libsctp-sys`** provides thin FFI over Linux SCTP socket UAPI and
   minimal `libsctp` helpers where required. It is the **only SCTP workspace
   crate** permitted to contain `unsafe`; follow-on Linux kernel UAPI exceptions
   such as `opc-linux-xfrm-sys` and `opc-linux-gtpu-sys` must be separately and
   explicitly allowlisted by the same mechanical gate. It does **not** inherit
   `[workspace.lints]` (so the workspace-wide `unsafe_code = "forbid"` stays in
   force for every other crate); it sets its own local crate policy
   (`unsafe_code = "allow"` plus `unsafe_op_in_unsafe_fn = "deny"`, or
   equivalent crate attributes) that allows `unsafe` *only there*, with a
   `// SAFETY:` comment required on every allowed `unsafe` token (`unsafe`
   block, `unsafe fn`, `unsafe impl`, `unsafe trait`, or unsafe extern block).
2. **`opc-sctp`** (the public crate) is `#![forbid(unsafe_code)]` and exposes
   only safe async abstractions (associations, messages, events) over the sys
   crate, integrated with `tokio::io::unix::AsyncFd` (the spec's async model).
   Its manifest must declare the tokio features it relies on, including `net`,
   instead of relying on feature unification from unrelated workspace crates.
3. **Boundary is enforced mechanically.**
   `scripts/check-management-plane-policy.py --check` token-scans OpenPacketCore
   workspace crate sources and asserts `unsafe` appears only in explicitly
   allowlisted Linux UAPI sys crates (`opc-libsctp-sys` and later, reviewed
   kernel-UAPI boundaries such as `opc-linux-xfrm-sys` and
   `opc-linux-gtpu-sys`); the same gate also rejects each allowed sys crate if it
   inherits `[workspace.lints]`, rejects it if it lacks the required local unsafe
   lint policy, and requires each allowed `unsafe` token in that sys crate to be
   documented by an adjacent `SAFETY:` comment. The CI job runs this gate, so the
   exception cannot silently spread or become undocumented.
4. **ABI safety.** Every C struct crossing the boundary has a struct-layout
   (size/alignment/offset) test; the sys crate builds on Linux in CI and
   compiles to a clean "unsupported platform" stub elsewhere.
5. **This exception pattern does not reopen ADR 0013.** It authorizes FFI only
   to explicitly reviewed **trusted Linux kernel UAPI** boundaries such as SCTP
   socket/XFRM netlink calls and minimal helper calls that wrap those UAPIs. FFI
   that links a foreign **C protocol codec** (parsing attacker-controlled bytes
   — NGAP/NAS/etc.) remains rejected; those stay pure-Rust per ADR 0013/0015.
6. SCTP is implemented per Option A behind this boundary, never as scattered
   `unsafe` and never as a userspace reimplementation without revisiting this
   ADR.

## Consequences

- The workspace gains small, auditable OpenPacketCore Linux UAPI sys crates
  containing `unsafe`; downstream carrier auditors review those explicitly
  allowlisted sys crates rather than a diffuse unsafe surface, and
  `unsafe_code = "forbid"` remains true everywhere else.
- The CI gate from point 3 exists, mirroring the "policy must be mechanically
  enforced" lesson of ADR 0014.
- `opc-sctp` uses the non-inheritance mechanism and `AsyncFd` model described
  by this ADR. Its README and tests record the current capability profile.
- NGAP-over-SCTP wiring (PPID 60) is separate integration work and is not
  authorized to use FFI for the NGAP codec itself.
