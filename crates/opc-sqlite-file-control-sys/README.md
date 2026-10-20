# opc-sqlite-file-control-sys

This private workspace crate exposes the audited SQLite file controls used by
`opc-session-store` to fail closed when an admitted file moves and, on Linux,
to duplicate the exact main, named-database, or WAL/journal descriptor behind
the bundled Unix VFS. The file-control opcodes are limited to
`SQLITE_FCNTL_HAS_MOVED`, `SQLITE_FCNTL_VFSNAME`,
`SQLITE_FCNTL_FILE_POINTER`, and `SQLITE_FCNTL_JOURNAL_POINTER`.

ADR 0020 additionally permits one non-default, read-only snapshot VFS on
Linux. Its safe `RegisteredSnapshot` handle binds an opaque process-local URI
to an owned `VerifiedSnapshotSource`. Every SQLite read goes through that
source's bounded authenticated-read method; cryptographic verification stays
in safe session-store code. No OS pathname is resolved. Writes, deletes,
journals, WAL, temporary files, and mmap bypasses are rejected. At most 256
sources can be registered, and each I/O callback accepts at most 2 MiB. Last
registration drop prevents new opens; live SQLite handles retain their source
until close. The VFS never becomes the process default.

An opt-in test-only feature registers one non-default VFS that rejects unnamed
temporary opens and delegates every named open to the bundled default VFS. It
exists solely to prove snapshot compaction does not rely on a process-global
temporary path.

The crate exposes typed file controls, owned snapshot registrations and narrow
file-inspection callbacks. It does not expose raw SQLite handles or a general
purpose FFI surface. Unsupported platforms fail closed. Raw descriptor
duplicates remain available for immutable artifacts and WAL data files; they
must not be used for temporary inspection or retention of a live main inode.

The crate is source-build only and is not published independently.

The optional `borrowed-file-identity` feature provides full-width main and
named-database identities, including on i686, without opening, duplicating or
closing descriptors. `with_main_file` also permits filesystem UUID, persistent
file-handle and attribute checks through a synchronous borrowed file. Both Unix
VFS and verified snapshot sources preserve their moved-file and generation
fences. Callers retain the owning connection for as long as they retain a
same-process inode identity; persistent recovery still needs UUID and handle
identity.

`RetainedSqliteFile` first pins a regular inode with `O_PATH`, then opens only
that exact descriptor through `/proc/self/fd`. It never resolves the descriptor
back to a caller-controlled pathname. Clones share one reader, and a final name
fence rejects substitution. Failed admission uses the same coordinated close.

Final close follows the bundled SQLite 3.53.2 Unix VFS's global-then-inode mutex
order and joins its deferred-close queue whenever a native connection retains
POSIX locks. A shared, private, unqueried connection to the kernel-owned
`/proc/self/stat` entry anchors the native inode list only while pins exist.
Queue storage is reserved before the readable open and uses SQLite's allocator;
SQLite frees queued descriptors after its final lock ends. Queued readers cannot
be reused as native database handles. The boundary checks the exact bundled ABI
and requires runtime mutexes; unsupported versions/configurations fail closed.
No SQL, checkpoint, writable directory, temporary link, process-wide VFS change
or descriptor duplication is used. The store enables the feature in its
production Unix dependency as well as test controls.
