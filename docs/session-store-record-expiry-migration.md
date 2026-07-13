# Session Record Expiry Migration

This runbook is the operator-safe admission and migration procedure for the
absolute `StoredSessionRecord::expires_at` invariant introduced by #148. It
applies to every SQLite replica, retained checkpoint, restore source, and
replayable compatibility replication log that can become authoritative.

The runtime invariant is:

- a finite expiry may be in the past, equal to the mutation authority time, or
  at most `MAX_SESSION_TTL` (exactly 365 days) after it;
- the forward clock-skew allowance is
  `MAX_RECORD_EXPIRY_CLOCK_SKEW = Duration::ZERO`;
- `expires_at = None` is valid for `AuthoritativeSession`, `DataplaneLookup`,
  `ReplicatedDr`, and `TelemetryDerived` records;
- `expires_at = None` is invalid for `EphemeralProcedure`, whose profile
  requires per-key expiry to collect abandoned procedure state; and
- invalid input returns the fieldless `StoreError::InvalidRecordExpiry`.

Past records are valid encoded history even though normal reads prune or hide
them. Do not classify a past deadline as corruption merely because it is no
longer live.

## Clock and commit authority

For a standalone Fake or SQLite backend, the backend's injected clock supplies
one reference timestamp for the complete direct mutation or batch. A forwarding
wrapper may use that exact delegated reference but must not substitute its own
wall clock.

For the production quorum profile, the elected OpenRaft leader captures the
command logical time and validates the proposal before it enters the log.
Followers and apply/replay paths repeat the check against that immutable
command time; follower wall clocks never decide admission. The authenticated
consensus identity, term/membership rules, log commitment, and applied index
provide the coordinator authority. Legacy `ReplicationEntry` compatibility
uses the entry's immutable `timestamp` as its only reproducible reference; it
does not make that path production consensus authority.

Deployments must synchronize coordinator clocks. There is deliberately no
forward skew grace that could silently extend retained state. A caller whose
clock is ahead must retry with a deadline derived from the current coordinator
time or choose a shorter product TTL.

## Pre-upgrade audit

1. Close readiness and traffic gates. Drain every writer and stop every replica
   that can mutate the store.
2. Take an immutable, restorable backup of every database, checkpoint, and
   recovery source before modifying anything.
3. Record one UTC RFC 3339 reference timestamp for the campaign. Run the
   count-only audit against each drained SQLite file with explicit budgets and
   that same reference:

   ```text
   opc-session-store-audit identity-invariants \
     --database /path/to/session-store.db \
     --max-rows N \
     --max-entry-json-bytes N \
     --max-total-json-bytes N \
     --expiry-reference 2026-07-13T18:00:00Z
   ```

4. Preserve the complete version-4 JSON report with the backup. Confirm that
   its `expiry_reference` is the campaign timestamp. Accept only
   `status = compliant` and exit 0. `violations_found`, `incomplete`, and
   `error` all block startup.
5. `invalid_record_expiry_fields` counts relational `session_records` whose
   expiry/profile is invalid at the pinned reference. Invalid nested
   compatibility CAS entries are included in `invalid_replication_entries`
   because their deadline is checked against the containing entry timestamp.
   The report is count-only and never reveals keys, owners, payloads,
   timestamps from rejected rows, or raw log JSON.

Omitting `--expiry-reference` uses the audit process's current UTC time. That
is convenient for a one-off check, but a recorded explicit value is required
for a reproducible migration campaign.

## Resolving violations

There is no automatic clamp or rewrite. A year-9999 record might mean an
intentional non-expiring product object, a bad clock, or corrupt input; the SDK
cannot infer which meaning is correct.

For a standalone legacy store, use a reviewed product exporter that can decode
the old representation while the fleet remains drained. Re-author each invalid
record through the current SDK and current lease/fence rules:

- use `None` only when the state-class policy above intentionally permits
  non-expiring state;
- otherwise choose a finite deadline no later than the campaign reference plus
  `MAX_SESSION_TTL`;
- assign a finite deadline to every immortal `EphemeralProcedure`; and
- delete expired or abandoned state only when the product's retention and
  recovery policy independently authorizes deletion.

Rebuild any compatibility journal from the accepted authoritative export. Do
not patch JSON, clamp timestamps blindly, preserve an invalid entry under a new
transaction ID, or discard history without the product's recovery authority.

For an OpenRaft store, never edit `session_records`, OpenRaft logs, vote,
membership, snapshots, committed journal rows, or applied indexes in place.
Use the supported whole-fleet recovery/rebootstrap procedure to construct a
new coherent state from a reviewed, re-authored export, then commit/install it
through the OpenRaft recovery authority. A follower-local repair cannot change
committed semantics and is not a migration.

Audit every resulting SQLite file again at the recorded reference (or record a
new reference for a new campaign). Then start the complete exact-profile fleet
while traffic remains gated, verify authenticated handshakes, OpenRaft
readiness, representative reads and writes, restore/log paths, and only then
restore traffic.

## Protocol transition and rollback

The bounded authority preflight changes the exact compatibility contract to
`opc-session-net/5`, wire-schema revision 6, error-set revision 8, and the
dedicated consensus contract to `opc-session-consensus/2`, transport/wire
revision 2, error-set revision 4. Drain and upgrade all clients, servers,
wrappers, and consensus members together. Mixed versions or revisions fail
before dispatch; this is not a rolling transition.

If audit, migration, startup, or verification fails, keep traffic gated and
restore the complete immutable pre-upgrade checkpoint for the whole authority
set. Do not combine old logs with new rows or roll back only one consensus
member. Once new-profile writes commit, binary rollback requires either a
coherent fleet-wide checkpoint restore that accepts loss/reconciliation of
post-checkpoint changes or a separately reviewed reverse migration whose old
decoder can read the selected target state before old writers restart.

The expiry rule changes only record metadata admission. It does not change the
encrypted payload, envelope format, AAD, key ID, HKMS/KMS provider placement,
or encryption-at-rest boundary. A crypto wrapper around a standalone backend
delegates the backend-clock verdict before provider work. A wrapper above a
remote or consensus coordinator MUST obtain the bounded, payload-free
authenticated authority preflight before cache invalidation, provider/HKMS
work, sealing, or backend dispatch. The actual authenticated CAS/batch path
repeats the preflight before idempotency admission. Invalid input and
preflight timeout/unavailability perform no provider work or requested state
mutation; callers may retry because only a consensus logical-time floor may
have committed.
