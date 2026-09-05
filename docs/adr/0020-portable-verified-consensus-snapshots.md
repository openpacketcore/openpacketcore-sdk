# ADR 0020: Portable Verified Consensus Snapshots

## Status

Accepted for implementation; qualification is not yet complete.

## Date

2026-09-05

## Context

Fixed membership and immutable snapshot consumption are separate contracts.
The fixed durable-quorum opener currently also requires Linux fs-verity. On
an unsupported filesystem a pristine store can open successfully and later
stop its Raft engine when the first snapshot requires sealing. Fixed quorum
membership does not intrinsically require a particular filesystem.

Removing sealing without replacing its protection is unsafe. A checksum scan
followed by a read from a mutable descriptor does not establish that the bytes
consumed are the bytes verified. A read-only file descriptor, chmod, an
advisory lock, and SQLite's `immutable=1` URI flag do not close that race.

## Decision

- Keep the fixed membership, identity, fencing, publication, and recovery
  checks unchanged. Make the local snapshot integrity mechanism an explicit,
  separate SDK construction policy.
- Retain the existing fixed opener's fs-verity contract for compatibility.
  Add an explicit-policy opener with a portable verified choice. There is no
  automatic fallback from explicitly selected fs-verity to portable mode.
- For portable snapshots, capture an SDK-owned, process-local SHA-256 block
  digest index from the pinned descriptor and validate the existing envelope
  against its authoritative expected checksum. All later transport,
  extraction, and SQLite reads must consume owned buffers checked against
  that retained index. Never reconstruct the index from a changed artifact
  inside a publication or consumption operation.
- Use a bounded adaptive block size: 64 KiB normally, up to 2 MiB for the
  largest supported images, with at most 16 MiB of digests per pinned image.
  Clones share the index. The file remains file-backed; this is not a
  whole-snapshot in-memory copy. Full-file indexing runs outside the primary
  consensus SQLite lock. A process-wide 128 MiB reservation bounds all digest
  indices, capture/cache replacement buffers, and pending transport buffers.
  Exhaustion rejects work before allocation; detached workers retain their
  reservation until completion. Each transport handle has at most one pending
  64 KiB read, including across cancellation and seek.
- Keep the existing durable envelope and checksum format. The index is
  reconstructed and authenticated on reopen, not a second durable authority
  or an unauthenticated sidecar. Explicit portable selection can consume an
  existing sealed image. An old strict reader cannot reopen a newly written
  unsealed image: rollback must preserve a compatible reader or use a
  separately qualified, explicit conversion on capable storage.
  A pending released strict reseed journal must be completed under fs-verity
  before changing policy; portable mode cannot reinterpret that journal's
  sealed-candidate deletion authority.
- A strict deployment must probe its selected snapshot filesystem during
  admission, before the Raft engine serves operations. Runtime storage
  corruption continues to fail closed in either policy.
- Qualification-node configuration also selects the policy explicitly.
  Ordinary foundation and mTLS candidate consumers use portable verification;
  omitted historical settings retain fs-verity and its canonical bytes. An
  explicitly configured external fs-verity campaign keeps that strict policy
  and namespace; it rejects portable selection.
  Configuration digests bind explicit policy choices without reclassifying
  portable results as fs-verity release evidence.

## Narrow amendment to ADR 0017

The existing `opc-sqlite-file-control-sys` allowlist additionally permits one
non-default, read-only snapshot VFS. It exposes a safe owned registration and
bounded read callback, not borrowed SQLite handles. Registered opaque names
resolve only to retained SDK sources; they are never filesystem authority.
Writes, deletes, journals, WAL, temporary opens, and mmap bypasses are rejected.
All snapshot bytes are verified in safe Rust before SQLite consumes them.
Descriptor inspection remains restricted to the existing file controls.

This does not authorize a general-purpose VFS, a new C parser, additional
file-control opcodes, unsafe code in session-store, or a process-default VFS
change. Every FFI token still needs a safety justification and layout tests;
the existing management-plane policy gate remains mandatory.

## Qualification required before completion

- Preserve the non-fs-verity snapshot creation RED and demonstrate build,
  transfer, install, restart, and recovery with fixed membership unchanged.
- Reject same-inode writes, truncation, path replacement, corrupt envelopes,
  and corruption after validation but before SQLite or transport consumption.
- Cover seek/retry/cancellation, descriptor and registration lifetimes,
  short-read zero filling, disabled mmap, read-only enforcement, and bounded
  digest allocation at the exact physical image ceiling.
- Prove indexing does not hold the primary SQLite lock and measure the
  portable read/index overhead with representative snapshot sizes.
- Keep strict fs-verity qualification and add admission-failure coverage on
  unsupported storage. Run portable qualification on ordinary XFS and ext4.
- Exercise application-independent fixed-quorum recovery. Single-host
  filesystem qualification does not establish multi-host HA or performance.

## References

- [SDK issue 771](https://github.com/openpacketcore/openpacketcore-sdk/issues/771)
- [SDK PR 732](https://github.com/openpacketcore/openpacketcore-sdk/pull/732)
- [SQLite I/O methods](https://www.sqlite.org/c3ref/io_methods.html)
- [SQLite VFS contract](https://www.sqlite.org/c3ref/vfs.html)
- [Linux fs-verity](https://docs.kernel.org/filesystems/fsverity.html)
