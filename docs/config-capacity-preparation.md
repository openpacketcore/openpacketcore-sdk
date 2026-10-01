# Configuration preparation ownership

This implementation provides the explicitly selected `ConfigCapacityProfile::BoundedV1`
with a 1,572,864-byte logical configuration limit. Complete qualification remains
tracked in #957 and the draft bounded configuration RFC. Legacy stores keep their
existing 1 MiB complete-command admission fence. Preparation ownership alone does
not select a profile or establish the proposed per-operation and aggregate memory
limits; the complete larger-profile acceptance matrix remains open.

`ConfigPreparationPool::bounded_v1()` provides eight nonwaiting preparation
slots. A store keeps its own pool private. A reservation from another pool has
no authority in that store, even if its caller supplies identical store IDs.
The separate eight accepted-proposal slots and all operation deadlines remain
unchanged.

For a supported bounded store, obtain a reservation through
`ConsensusConfigStore::try_reserve_config_preparation` before allocating SDK
plaintext. The encrypting datastore delegates this request to its exact sealed
datastore. A nonlegacy datastore that has no reservation implementation refuses
preparation. Legacy stores return `None` and retain their existing behavior.

`encrypt_reserved_bounded_config_envelope` consumes a reservation before key
provider access. The envelope, its aliases, and its single encryption claim
share that one reservation. The attested commit consumes the claim only after
checking exact ciphertext and plaintext digest equality. Extracting the claim
does not make its sealed reservation usable for another encryption. Failed or
cancelled encryption releases capacity when its last owner drops. The original
SDK envelope storage still counts once toward that reservation while any of
these aliases remains live, including an envelope retained after its claim was
consumed. Shared aliases do not create independent ciphertext allocations.

Ordinary prepared commits remain non-cloneable. Audited prepared values share
immutable ciphertext and ownership when cloned. Equality, legacy JSON and
postcard encodings depend only on the original deterministic fields. Retained
commands, Raft entries, recovery handles and snapshots contain no process-local
reservation. They have separate resource obligations.

Aliases of a reserved audited preparation admit at most one active SDK
`encode()` call and one active mutation submission. These guards are
nonwaiting. Read-only recovery remains available. The encoder counts exact JSON
expansion before allocating output. The current SDK encoding output remains
part of mutation working memory until it is returned. Once a raw output Vec is
returned to an application, that application must bound retained copies. If SDK
code retains the result or reborrows it for another SDK operation, it must
count that actual storage for the full overlapping lifetime. A caller-supplied
serde serializer likewise owns its output; it does not acquire a preparation
reservation merely by serializing a prepared value.

Once Openraft accepts a proposal, its supervisor keeps preparation and proposal
ownership until that exact work completes, even if the client cancels or loses
the response. A forwarded attempt holds the sender's ownership through its
in-flight transport and original deadline. The receiving store independently
reserves before decoding and holds ownership through accepted completion.
Replication, snapshots and read-only recovery do not wait for a preparation
slot. A later resource rejection cannot erase an earlier uncertain outcome.

Generic `PreparedAuditedMutation::decode` does not create a reservation.
`ConsensusConfigStore::decode_prepared_audited_mutation` reserves first and
authenticates the original handle and effect. It grants no audit receipt or
caller identity. Bounded append decoding requires an authenticated size proof
for the original logical and replay lengths before attaching local preparation
ownership. Backend reads check the immutable local profile and authenticate
retained proofs; they do not interpret bounded history as legacy history.

Remaining qualification includes complete allocation lifetimes and capacities,
forwarded cancellation and receiver exhaustion, stopped-node release, maximum
membership fan-out, combined retained recovery, snapshot transfer/restore, and
the full larger-configuration acceptance matrix. The component fixtures and native
singleton control do not establish those results.

Refs #957.
