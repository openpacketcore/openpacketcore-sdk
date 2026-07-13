# Session-store stable-ID migration

This runbook is the mandatory transition from arbitrary legacy
`SessionKey::stable_id` bytes to the production `StableId` contract. It applies
to every session-store SQLite file, Openraft state-machine image, retained
SQLite snapshot, replication log, restore source, and replay source that can
become authoritative.

The production invariant is exactly 1 through 64 opaque bytes. Valid legacy
values preserve their exact JSON, wire, SQLite BLOB, ordering, and digest input
bytes. The SDK does not silently truncate, hash, normalize, delete, or rewrite
an invalid value.

## Privacy profile

Raw SUPI and GPSI values are forbidden. Products derive subscriber identities
with `StableId::derive_hmac_sha256` using:

- a 16-through-64-byte tenant-specific privacy key obtained from the
  deployment KMS/HSM;
- one versioned, product-defined canonical subject representation containing
  1 through 256 bytes;
- the SDK `openpacketcore/session-stable-id/hmac-sha256/v1` domain;
- unsigned 64-bit big-endian length prefixes for tenant and canonical subject;
  and
- the complete 32-byte HMAC-SHA256 output.

Do not truncate the digest. Do not reuse one privacy key across tenants. Key
rotation changes the durable identity unless the product supplies an explicit
dual-read/rekey design, so it must not be inferred from ordinary HKMS payload
key rotation.

## Pre-upgrade audit

1. Stop admission and drain session traffic.
2. Stop every writer and verify that no old or new process can mutate the
   fleet. Take one coherent fleet-wide backup, including SQLite WAL/SHM files
   as required by the SQLite backup procedure and all retained snapshots.
3. Size explicit budgets for the complete file and run:

   ```text
   opc-session-store-audit identity-invariants \
     --database /path/to/session-store.db \
     --max-rows N \
     --max-entry-json-bytes N \
     --max-total-json-bytes N
   ```

4. Repeat the audit for every retained SQLite snapshot or restore/rebuild image
   that could be installed. Accept only report version 3, `status = compliant`,
   and exit 0.

The report is count-only. `invalid_stable_id_fields` counts relational values
whose SQLite type is not BLOB or whose length is outside 1 through 64 bytes.
`invalid_replication_entries` includes nested stable IDs rejected by bounded
Serde/domain validation. No database path, row identity, tenant, stable-ID
bytes, owner, transaction, payload, or raw JSON is emitted.

`violations_found`, `incomplete`, or `error` blocks the rollout. An incomplete
audit is never partial proof; increase the approved budgets and rerun it.

## Remediation

A compliant fleet needs no data conversion. Upgrade all SDK consumers together
because the Rust field type changes from `Bytes` to `StableId`; runtime readers
and writers then preserve the existing bytes exactly.

An invalid opaque value cannot be migrated generically: the SDK does not know
its canonical subscriber identity, privacy-key version, or product ownership
semantics. Choose one reviewed product procedure while the fleet remains
drained:

- For reconstructible or expired state, remove the entire coherent session and
  all of its record, lease, fence, log, snapshot, restore, and replay copies,
  then let the authoritative product source rebuild it under a valid key.
- For state that must survive, run an application-owned offline migration from
  the old release. Resolve the canonical source identity, derive one valid
  replacement deterministically, and rewrite every occurrence atomically in a
  shadow copy. Preserve generation, fence, encryption envelope/AAD semantics,
  committed ordering, and Openraft snapshot lineage. A row-only key rewrite is
  invalid because logs, fences, encrypted AAD, and snapshots would disagree.
- If those semantics cannot be proven, keep the fleet closed and restore or
  replace the whole store through the product's session recovery procedure.

Never edit a live PVC. Never repair one quorum member independently. Never
install or retain a non-compliant snapshot after the transition. Run the strict
decoder and version-3 audit over the complete shadow result before promotion.

## Cutover verification

1. Start the coordinated new fleet with traffic still closed.
2. Require every file and candidate snapshot to produce a compliant version-3
   audit report.
3. Verify exact 1-byte and 64-byte records through local SQLite, restore,
   replication/rebuild/watch, cache, Openraft, and authenticated session-net
   paths. Verify hostile empty and 65-byte JSON/raw-row fixtures fail before
   dispatch or retained mutation and expose no bytes.
4. Require fresh Openraft durable readiness and authoritative reads on every
   serving member.
5. Take and validate a fresh compliant snapshot, then reopen traffic.

## Rollback

The audit is read-only and valid in-profile bytes are unchanged, so a rollout
that performed no remediation can roll back by draining the fleet and
restarting the previous binaries against the same coherent store. Keep the
pre-upgrade backup until the new fleet and fresh snapshot are qualified.

After an application-owned rekey or deletion, do not start old writers against
the transformed fleet unless that product explicitly supports the new mapping.
Rollback instead restores the coherent pre-upgrade backup (accepting or
reconciling every post-checkpoint mutation) or runs a reviewed reverse
migration across every record, lease, fence, log, snapshot, restore, and replay
copy. Payload-key/HKMS rotation and stable-ID privacy-key rotation are separate
lifecycles; neither is rolled back by changing only the session-store binary.
