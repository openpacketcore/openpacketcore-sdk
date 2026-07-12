# opc-consensus

`opc-consensus` is the shared consensus substrate for OpenPacketCore SDK
durable state machines. It exact-pins and re-exports the SDK's supported
Openraft engine and owns stable cluster, configuration, node, request, digest,
codec, and authenticated transport identities.

Consumers retain their own deterministic state-machine commands, durable
storage adapter, and domain errors. They must use this crate for election,
term, vote, replication, commit, membership, linearizable-read, and snapshot
authority instead of implementing a parallel quorum algorithm.

Session payload encryption remains outside this layer. The session-store
composition seals payloads before they enter consensus, so this crate never
receives plaintext session payloads, HKMS/KMS provider handles, or encryption
key material. This is payload-envelope protection; filesystem and database
metadata confidentiality requires a separately qualified storage or volume
encryption layer.

The public SDK boundary is intentionally small. Openraft is exposed only
through `opc_consensus::engine`, allowing every production consensus consumer
to share one exact engine version while keeping Openraft details out of
domain-facing wire and storage APIs.
