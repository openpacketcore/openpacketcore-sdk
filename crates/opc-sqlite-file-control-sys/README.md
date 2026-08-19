# opc-sqlite-file-control-sys

This private workspace crate exposes one audited, value-free SQLite file-control
probe used by `opc-session-store` to fail closed when an admitted journal file
moves. It does not expose raw SQLite handles, paths, journal contents, or a
general-purpose FFI surface.

The crate is source-build only and is not published independently.
