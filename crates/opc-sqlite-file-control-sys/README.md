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

The crate exposes only owned descriptor duplicates, owned snapshot
registrations, and bounded typed results. It does not expose SQLite's borrowed
handles or a general-purpose FFI surface, and unsupported platforms fail closed.

The crate is source-build only and is not published independently.
