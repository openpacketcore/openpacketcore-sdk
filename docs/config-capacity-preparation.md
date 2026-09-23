# Configuration preparation ownership

The larger configuration profile remains unavailable. Its proposed logical
limit and complete qualification are tracked in #957 and the draft bounded
configuration RFC. Preparation ownership alone does not enable that profile,
increase the existing 1 MiB complete-command admission fence, or establish the
proposed per-operation and aggregate memory limits.

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
cancelled encryption releases capacity when its last owner drops.

Ordinary prepared commits remain non-cloneable. Audited prepared values share
immutable ciphertext and ownership when cloned. Equality, legacy JSON and
postcard encodings depend only on the original deterministic fields. Retained
commands, Raft entries, recovery handles and snapshots contain no process-local
reservation. They have separate resource obligations.

Aliases of a reserved audited preparation admit at most one active SDK
`encode()` call and one active mutation submission. These guards are
nonwaiting. Read-only recovery remains available. The encoder counts exact JSON
expansion before allocating output; returned bytes and output produced by a
caller-supplied serde serializer belong to the caller. Callers must separately
bound retained copies of those bytes.

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
caller identity. Bounded append decoding remains refused until retained size
proofs can authenticate the original logical and replay lengths. Backend reads
also check the immutable local profile and refuse to treat unsupported bounded
history as legacy history.

Remaining qualification includes complete allocation lifetimes and capacities,
forwarded cancellation and receiver exhaustion, stopped-node release, maximum
membership fan-out, retained size proofs, snapshot transfer/restore, and the
full larger-configuration acceptance matrix. The component fixtures and native
singleton control do not establish those results.

Refs #957.
