# Resumable retained configuration provisioning

The request-based Linux local SQLite profile creates a new authority with an
explicit 32-byte request identifier, exact retained binding, and audit key.
The existing constructors derive their request identifier from that binding and
key; their new `begin_resume_config_authority` and
`begin_resume_config_member_repair` operations repeat exactly that authorization.
Provision requires independently authorized unused storage. Resume repeats that
same request; ordinary reopen never completes provisioning. A request identifier
is scoped to the admitted destination, not a distributed uniqueness service.
The caller's retained backing and key authorities remain trusted, as with the
existing retained configuration profile.

## Publication protocol

1. Acquire a private unnamed file on the destination filesystem and take its
   exclusive `flock`. Write a
   versioned HMAC-authenticated intent containing the request, topology/backing/
   key binding, disposition, parent identity, and lock identity. Sync the file
   and link it at the retained admission name
   without replacement. Sync the parent directory.
2. Construct the empty configuration database in memory using the SDK's exact
   schema and consensus initialization. Its authenticated binding includes the
   intent lock and the unnamed destination database inode. Serialize only the
   complete database, write it to that unnamed inode, and sync it.
3. Publish the database with a no-replacement link, sync the parent, and run the
   normal bounded retained admission checks on a private copy.
4. Write the authenticated database binding into another unnamed file, sync it,
   publish it at `.opc-retained-complete` without replacement, and sync the
   parent. Only then return authority. Live SQLite uses the unchanged WAL,
   synchronous-EXTRA, and busy-timeout profile.

Unlinked files disappear automatically on process exit. A published intent with
no database is a valid resumable prefix. A published database is complete before
it becomes visible; retry validates it without initializing or replacing it.
Ordinary reopen requires the completion record. Resume may publish a missing
completion only after validating the exact existing database. A completion
record without its database is established storage loss and is refused; it
cannot trigger fresh initialization. The completion inode is also pinned and
checked throughout admission and use.
Foreign, truncated, mismatched, or unauthenticated files are never deleted or
adopted. A conflicting request cannot take over a published intent. The intent
lock remains held through the returned connection's actual close and closure of
every extra database descriptor, including cancelled blocking work and unclaimed
successful opens.

## Bounds and assumptions

The existing admission byte limit and absolute operation deadline apply. Intent
and completion encodings have fixed lengths. The initial database contains only bounded SDK
schema and the supplied bounded topology. Cancellation cannot interrupt a
kernel storage operation. `RetainedConfigOpen` retains worker and disposal
ownership; cancelled waits cannot later return authority, and callers join to
observe retirement. An indeterminate result remains indeterminate after join.

The filesystem must support Linux unnamed temporary files, atomic no-replacement
hard-link publication, `flock`, and truthful file and directory synchronization.
The procfs mount at `/proc/self/fd` is required to reopen and publish pinned files.
Unsupported filesystems fail closed. No namespace cleanup, node reboot, or
operator intervention is required for an interrupted operation. Loss or coherent
rollback of the admitted backing or key authority remains outside local proof.
Removing both the database and its completion record is indistinguishable from
rolling the destination back to an incomplete intent; independently retained
request authorization must not be reused to recover lost established authority.
Process-exit testing establishes recovery ordering, not power-loss durability.

All retained provisioning entry points use this publication protocol. Explicit
request APIs are `begin_provision_config_transaction`,
`begin_resume_config_provision`, and `begin_reopen_config_transaction`.
The admission encoding replaces the earlier one-shot format. Crossing this
storage boundary requires a fresh installation. No compatibility reader or
in-place conversion is provided; a differently sized admission record returns
`RecoveryRequired` without opening the original database.
