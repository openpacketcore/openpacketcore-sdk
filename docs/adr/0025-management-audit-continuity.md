# ADR 0025: Management audit continuity outside the database restore domain

## Status

Implementation contract for SDK #798, extending the replicated authority in
#797. Qualification is recorded separately. The local `ManagementAudit` and
`DurableAuditSink` APIs keep their documented local-only guarantees; they do not
acquire fleet continuity by opening a sink on each voter.

## Decision and trust

Use the existing configuration `ConsensusConfigStore` and its state-machine
transaction for signing-key transitions, export acknowledgements and retention.
`open_with_audit_continuity` requires a bounded `AuditKeyRing` and an
`AuditCheckpointPort`. The application supplies authenticated callers, recipient
authorization, policy limits and approved providers. It does not implement the
cryptographic format or merge independently written chains.

Once continuity keys are attached, every clone of that backend requires the
explicit continuity constructor and checkpoint provider. An ordinary open
cannot downgrade it, including after a failed open or shutdown. Opening a
fresh backend over retained continuity state also requires the complete
profile; missing keys or external authority refuse startup.

The platform owns strongly consistent, monotonic checkpoint persistence and
authorization outside the configuration database's restore domain. The SDK
authenticates the complete checkpoint and independently reads back each CAS,
including an `Applied` response. An unavailable/ambiguous write is never proof
of acknowledgement. A copied checkpoint file beside the SQLite database does
not satisfy this contract. No production checkpoint platform is implemented by
the synthetic test provider.

Management signing keys are distinct from the configuration integrity/operation
handle key and the privacy projection key. The admitted signing keyring rejects
duplicate epochs, duplicate material and configuration-key reuse. Signing uses
the SDK's existing domain-separated HMAC primitive, not a new cryptographic
algorithm. Offline verifiers therefore need trusted secret verification
material: this is authenticated export, not public-key non-repudiation. Keys
are not exported with pages, manifests, transitions or checkpoints.

## Epochs and interruption

Mount overlapping keys on every voter before activation. One through eight
epochs may be mounted; mounting does not change the ledger's authenticated
active epoch. A transition advances exactly one epoch and carries both the old
and new key proofs over the fleet, prior sequence/anchor and both key identities.
Consensus appends the transition under the old epoch and activates the new one
atomically. An unrelated append at the prepared prefix invalidates the proof.
Missing/wrong material refuses verification. It never starts a new empty chain.

Keep and retry the exact prepared transition after response loss. Its retained
ledger entry makes activation idempotent across leaders; a new transport attempt
does not activate twice. Pruning and checkpoint acknowledgement likewise check
their exact target against the current ledger. Each maintenance invocation has
its own bounded request-cache identity so a definite earlier rejection does not
permanently reject a prefix after its handles expire. This changes neither the
configuration-mutation retry identity nor operation-handle authority.

Retire a live signing epoch only after an acknowledged export/checkpoint covers
it, every dependent operation is terminal and expired, and its rows/transition
are pruned. The remaining floor/rows and external checkpoint must verify with
the surviving key set. Archived exports may still require separately retained
historical verifier keys. Removing live key material is an explicit provider
change and reopen, not a silent key swap. Configuration integrity and operation
handles retain their separate existing key; this decision does not rotate it.

## Frozen complete-range export

An export freezes the entire current retained range. Its authenticated manifest
binds fleet, authorized recipient, predecessor/floor, ordered row count, terminal
anchors, signing epochs, random session identity and fixed expiry. Requesting a
past floor returns `Pruned`; requesting a future floor is invalid. Neither
silently advances the caller's boundary.

Each page contains at most 256 projected rows and an authenticated exact next
offset. The offline streaming verifier checks every row, both chains, every key
transition, manifest binding and final completeness. Omission, repetition,
reordering, substitution, truncation, mixed exports and altered cursors fail.
A failed page poisons that verifier. Only a successful `finish` constructs the
SDK's non-forgeable `VerifiedAuditExport`; counters or a last-page flag cannot.

The configured one through eight local sessions are reserved before freezing.
Each holds at most the ledger's 4096-row/16-MiB representation bound. Pages and
decoders are independently bounded. Session expiry is fixed at 1 through 3600
seconds; backward time before issuance also refuses use. Expiry does not erase
the caller-owned object: the owner must drop it to reclaim its capacity. A
frozen session remains immutable during live append or pruning. It is not
restored after process loss; the consumer must start a newly verified export.

## External checkpoint and safe retention

Fresh provisioning initializes an authenticated empty ledger and provisions an
external genesis checkpoint. Until that checkpoint is read back and recorded
through consensus, audit readiness/admission is unavailable. A crash between
these steps may resume only that empty provisioning state. Existing history
cannot adopt this profile or reset its external row implicitly.

Startup, authoritative audit reads/admission and export verify the external
checkpoint against the retained local prefix. An external mark ahead of the
local chain detects coherent database rollback. A missing required mark,
unknown key, altered anchor, mark below the retained floor, or external rollback
behind the locally acknowledged mark fails closed. This protects only through
the last externally acknowledged prefix: an uncheckpointed suffix is not
claimed resistant to coordinated whole-database rollback. A faulty or hostile
external authority that rolls back together with the database violates the
required independent trust boundary.

A reopened authority also refuses a checkpointed configuration-mutation intent
whose authoritative outcome is absent from the retained ledger. A commit may
have existed in a lost suffix, so expiration cannot classify that intent as
rejected. This is explicit recovery-required state; preserve the database and
external checkpoint and recover the authoritative outcome. A retained committed
or rejected outcome can still reopen and finish its terminal obligation. This
guard does not supply automatic per-mutation checkpoint advancement or protect
an intent that was never independently checkpointed; those ordering guarantees
remain separate from export-prefix acknowledgement.

After complete export verification, acknowledgement verifies the same prefix,
CAS-advances the external checkpoint, reads it back and commits that exact value
locally. A newer independently verified checkpoint may subsume an older export.
Competing equal-sequence exports reconcile to the already established mark;
they cannot replace it. Lost external or consensus acknowledgements retain an
uncertain result until readback/retry succeeds.

Explicit prefix pruning requires that acknowledged checkpoint, no unresolved
operation, no operation crossing the cut, and expiry of every included handle.
The same consensus transaction removes complete operations, advances the
authenticated floor/epoch and preserves the remaining ordered rows. A pruned
expired handle cannot use an old cached success as new admission. Full history
refuses new work while preserving reserved outcome/terminal capacity. There is
no automatic discard, unbounded spill, or second persistence owner.

## Representation and compatibility

Configuration command/RPC revision 6 adds these continuity commands. Revisions
1 through 5 keep their original semantics and ordinal encodings; the earlier
audit commands still require revision 5. Configuration storage/snapshot
representation 4 authenticates the additional continuity state. Earlier storage
representations are refused, without a decoder fallback, silent reset or
automatic migration. Preserve retained state and use an explicitly reviewed
cutover before deployment. These revisions do not change session WAL or the
Durable/Async session persistence modes.

The protocol-server/ConfigBus composition under #796 remains a separate slice.
Enabling this ledger on an adapter that still uses unaudited configuration writes
will refuse those writes. The API alone is not an end-to-end management claim.

## Evidence

Synthetic model tests exercise cross-epoch authentication, malformed exports,
wrong/missing keys, coherent rollback and protected retention. Real consensus
tests cover lost activation acknowledgement, leader replacement, checkpoint
outage and acknowledgement loss, retained reopen, deliberate database rollback,
early-prune rejection followed by eligible retry, key retirement and old-handle
replay. They make no production platform or performance claim.
