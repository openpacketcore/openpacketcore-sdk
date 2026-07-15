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

`DURABLE_CONSENSUS_TIMING_PROFILE` is the sole timing authority for both
durable domains: AppendEntries/Openraft read-index and heartbeat 2,000 ms,
Vote 5,000 ms, elections `[5,000 ms, 8,000 ms)`, InstallSnapshot/forwarded
mutation/consumer ReadBarrier and operation default 10,000 ms, and listener
idle/handler ceilings 30,000 ms. The 1,500 ms DNS/TCP/mTLS/bootstrap cold cap is
contained inside the selected family deadline, never added to it.

`DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS` fixes both durable adapters at
eight concurrent proposal paths. Admission is obtained inside the original
operation deadline. Once `client_write_ff` returns an accepted-result
receiver, a detached supervisor retains that permit until Openraft resolves
the exact proposal, even if the caller disconnects, times out, or is cancelled.
This bounds accepted and pre-accept work without adding a second sequencing or
commit authority.

`EnsureLinearizableSupervisor` admits every fresh read-index or mutation
preflight through exactly one supervisor-owned Openraft check per node and at
most 64 total callers across the active and waiting cohorts. Callers collected
before dispatch may share that exact result; later callers await a subsequent
check under their original deadlines.
Once dispatched, caller cancellation or timeout cannot cancel the check or
start an overlapping one. Openraft still supplies every quorum proof; this is
not a cached lease or alternate authority.

## Interim source-build gate

Issue #143 remains open and the HA profile remains experimental. The workspace
pins `https://github.com/openpacketcore/openraft` at the full verified revision
`f607e636406b16bd0ad7925dbb631da1b7a4cd96` (signed tag
`opc-v0.9.24-election-resampling-1`) because registry Openraft 0.9.24 does not
resample an election timeout for each campaign. The pin is by `rev`, never a
branch or tag.

Crates that contain this engine or have a transitive normal dependency path to
it are source-build only: `opc-alarm`, `opc-alarm-k8s`, `opc-alarm-testkit`,
`opc-alarm-yang`, `opc-amf-lite`, `opc-amf-lite-testkit`, `opc-config-bus`,
`opc-consensus`, `opc-gnmi-server`, `opc-ipsec-lb`, `opc-mgmt-authz`,
`opc-mgmt-transport`, `opc-netconf-server`, `opc-persist`, `opc-runtime`,
`opc-sa-mirror`, `opc-sbi`, `opc-sdk`, `opc-sdk-integration`,
`opc-session-cache`, `opc-session-net`, `opc-session-store`,
`opc-session-testkit`, `operator-controller`, `operator-lifecycle`, and
`operator-lifecycle-cli`. This exact 26-crate closure is mechanically checked;
the other 51 workspace crates are unaffected. Exact-name crates.io searches on
2026-07-13 found none of the 26. Cargo/git CNF consumers remain supported;
crates.io publication is disabled because a published manifest cannot preserve
the fork revision.

Remove this gate only after an official stable Openraft release contains the
fix, the workspace uses a registry pin and checksum, and the full issue #143
qualification is rerun. Changing the consensus engine does not move payload
sealing or key ownership: session and configuration ciphertext boundaries,
HKMS/KMS provider handles, and at-rest encryption responsibilities remain
outside Openraft exactly as described above.
