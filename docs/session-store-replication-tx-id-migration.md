# Session-store replication transaction-ID migration

This runbook is the mandatory transition from arbitrary
`ReplicationEntry::tx_id` strings to the bounded `ReplicationTxId` contract.
It applies to every session-store SQLite file, committed application journal,
Openraft state-machine image, retained SQLite snapshot, rebuild source, watch
source, and operator-recovery checkpoint that can become authoritative.

The accepted persisted representation is an opaque UTF-8 string containing 1
through 128 bytes. Existing values in that range remain valid and preserve
their exact bytes. They are never trimmed, case-folded, parsed as numbers, or
otherwise normalized because two distinct values identify a fork while an
exact repeat identifies an idempotent redelivery. New Openraft coordinator
writes use the canonical 32-byte lowercase hexadecimal encoding of the
committed 16-byte consensus request ID.

Canonical form is a writer rule, not a legacy-reader rewrite rule. A valid
non-canonical legacy ID remains distinct and needs no conversion.

## Pre-upgrade audit

1. Stop admission, drain session traffic, and stop every process that can
   write a session store.
2. Take one coherent fleet-wide backup. Follow the SQLite backup procedure for
   database, WAL, and SHM state, and retain every snapshot, rebuild source, and
   operator-recovery checkpoint that could later be installed.
3. Size explicit budgets for each complete file and run:

   ```text
   opc-session-store-audit identity-invariants \
     --database /path/to/session-store.db \
     --max-rows N \
     --max-entry-json-bytes N \
     --max-total-json-bytes N \
     --expiry-reference 2026-07-13T18:00:00Z
   ```

4. Repeat for every retained SQLite image. Accept only report version 4 with
   the recorded `expiry_reference`, `status = compliant`, and exit 0.

Report version 4 retains `invalid_replication_tx_id_fields` from version 3 and
adds the expiry reference/count required by #148. The transaction-ID field
counts a relational `tx_id` that is empty, over 128 UTF-8 bytes, not SQLite `TEXT`, or
whose `entry_json` lacks an exactly matching valid typed ID.
`invalid_replication_entries` separately counts malformed JSON, invalid nested
domain values, or a stored/encoded sequence mismatch. The audit retrieves at
most 128 transaction-ID bytes per row and emits counts only; it never returns
the database path, row identity, transaction ID, JSON, key, owner, or payload.

`violations_found`, `incomplete`, and `error` all block rollout. An incomplete
audit is not partial proof. Increase the approved budgets and run it again.

## Remediation

A compliant store needs no data rewrite. The JSON, session-net, and SQLite
encoding remains the same string representation, including for non-canonical
legacy IDs.

The SDK deliberately provides no automatic rewrite for an invalid ID. A
generic trim, truncation, case conversion, numeric conversion, or hash could
collapse two fork identities or make an old retry look like a different
transaction. While the complete fleet remains drained, choose one reviewed
operator procedure:

- Restore or re-seed the complete store from a coherent authoritative source
  whose IDs pass report version 4.
- If application ownership can prove a one-to-one replacement, use an offline
  legacy-capable decoder with explicit input and work limits. Rewrite the
  relational `tx_id` and the matching `entry_json` together in a shadow copy,
  preserve sequence, operation, timestamp, committed ordering, and snapshot
  lineage, and rewrite every retained copy that can become authoritative.
  Prove that no old request carrying the replaced identity can be retried.
- If those semantics cannot be proven, keep the fleet closed and replace the
  entire coherent store. Do not repair one quorum member independently.

After remediation, run report version 4 over every shadow database and
retained snapshot. Promote only complete compliant results. Keep the original
backup immutable until cutover and rollback verification finish.

## Coordinated cutover

1. Recompile every Rust consumer for the source-breaking field change from
   `String` to `ReplicationTxId`.
2. Upgrade all session-store, cache, encryption-wrapper, consensus, recovery,
   and session-net participants together while traffic remains closed. This
   change does not make a rolling mixed-version deployment a qualified #143
   profile.
3. Start the complete fleet and require fresh Openraft durable readiness. Bind
   success, cached capabilities, or a local SQLite read is not sufficient.
4. Verify representative journal reads, rebuilds, watches, and snapshot
   validation. Confirm exact same-ID redelivery is idempotent and an
   alternate case or other distinct representation at the same sequence is
   rejected as divergent.
5. Restart the fleet once with traffic still closed. Re-run report version 4
   against every candidate image and require fresh durable readiness again.
6. Take a new coherent compliant snapshot before reopening traffic.

New SQLite databases enforce `TEXT` plus the 1-through-128-byte width check.
Existing databases retain their DDL and rely on the pre-upgrade audit and
bounded hydration checks. Runtime reads, Openraft snapshot admission, and
operator recovery fail closed on an invalid or relational/JSON-inconsistent
ID without rewriting it.

## Mixed-version and rollback rules

In-profile value encoding is backward-readable: canonical 32-byte IDs and
valid legacy IDs are ordinary JSON/SQLite strings. That does not make the Rust
API, audit schema, exact session-net profile, recovery schema validation, or
fleet behavior rolling-compatible.

The safest rollback is a coordinated drain followed by restoration of the
coherent pre-upgrade backup and the previous full binary set. If rollout made
no data remediation, a same-store rollback is allowed only when the previous
release has been explicitly qualified against the resulting SQLite DDL,
snapshots, and exact transport profile. Never mix old and new writers.

After any application-owned ID replacement, restore the pre-upgrade backup or
run a reviewed reverse migration over every journal, snapshot, rebuild,
recovery, and replay copy before starting old writers. After any rollback,
run report version 4 again before a later re-upgrade because an old writer can
mint an arbitrary string.

## Consensus, recovery, and encryption boundaries

- #127 mints new journal IDs only after committed Openraft apply, from the
  fixed 16-byte consensus request identity.
- #128 current-format reconciliation and snapshot install validate the typed
  ID and the exact relational/JSON match before accepting state.
- #129 legacy recovery rejects invalid IDs during bounded inspection; it does
  not invent replacement identities.
- #171 implements the separate log-range cursor and retention contract. This
  migration does not redefine that contract.
- Transaction IDs remain journal metadata. The change does not move payload
  encryption into Openraft, call HKMS, alter session envelope AAD, expose raw
  keys, or weaken encryption-at-rest qualification. Errors and debug output do
  not include rejected transaction-ID bytes.
