# Kubernetes session-HA campaign foundation

This renderer creates the deterministic deployment foundation needed to run
the private `opc-session-quorum-node` from an immutable release image. It is
not production qualification evidence and it does not change
`qualification_complete` or `experimental` in the session-HA profile.

Render either supported topology with an exact OCI digest:

```console
cargo run --locked -p opc-session-testkit \
  --bin opc-session-kubernetes-manifest -- \
  --members 3 \
  --namespace session-ha-qualification \
  --image registry.example/opc-session-quorum-node@sha256:<64-lowercase-hex> \
  --trust-domain qualification.example \
  > session-ha-3.json
```

Run the same command with `--members 5` for the five-voter topology. The
output is a Kubernetes `List` and can be checked without changing a cluster:

```console
kubeconform -strict -summary session-ha-3.json
kubectl apply --server-side --dry-run=server -f session-ha-3.json
```

The image boundary accepts only an explicit lower-case registry authority: the
exact `localhost` name, a DNS/IP name containing `.`, or a host with an
explicit numeric port. It also requires normalized OCI repository components
and a lower-case SHA-256 digest. Bare first components, tags, implicit default
registries, malformed separators, and tag-plus-digest aliases are rejected.
The immutable ConfigMap name is derived from the complete sorted
node-configuration data, so any configuration change selects a new object and
cannot silently reuse stale immutable data.

Before applying it, provision one Secret per member named
`opc-session-ha-node-N-svid`. Each Secret must contain `tls.crt`, `tls.key`, and
`ca.crt`; its leaf URI SAN must equal the exact SPIFFE ID in that member's
rendered node configuration. The renderer never accepts or emits certificate
or private-key bytes. Each one-replica StatefulSet projects only its own Secret
and retains its own RWO PVC. Required pod anti-affinity prevents two voters
from sharing a Kubernetes host.

The headless Service gives member `N` the canonical route
`opc-session-ha-N-0.opc-session-ha-peer.<namespace>.svc.cluster.local:7443`.
The foundation pins the Service to an IPv4 single stack so each per-pod FQDN
has the same address family as the `0.0.0.0:7443` listener. The node resolves
only that manifest-bound endpoint for outbound connections; mTLS still
authenticates the exact manifest SPIFFE identity. Plaintext remains unavailable
outside the explicit loopback test feature.

The egress NetworkPolicy permits DNS only to pods labelled `k8s-app=kube-dns`
in the namespace labelled `kubernetes.io/metadata.name=kube-system`, over TCP
or UDP port 53. A qualification cluster must provide and prove that exact DNS
path; NodeLocal DNS or differently labelled resolvers require an explicitly
reviewed manifest variant. Kubernetes NetworkPolicy cannot restrict DNS query
names, so this is a resolver/port boundary, not an FQDN allow-list. Canonical
manifest endpoints plus mTLS and exact SPIFFE membership remain the peer
authorization boundary.

The process does not request interactive stdin. It listens at the exact private
`/var/lib/opc-session-qualification/control/node.sock` path instead. The node
creates `control` as a `0700` child of the existing workspace `emptyDir`,
publishes the socket as `0600`, accepts one bounded typed command and reply per
connection, removes its exact socket on clean shutdown, and replaces only a
refused stale socket after an unclean exit. The socket is neither a container
port nor part of the state PVC or projected identity volume.
The StatefulSets select `kubernetes.io/os: linux`, which is the scheduling
constraint required for this Unix-domain control transport in mixed-OS
clusters.

An authorized operator can invoke the same image as a one-shot client:

```console
printf '%s\n' '{"command":"probe"}' | kubectl exec -i POD -- \
  opc-session-quorum-node --control-client \
  /var/lib/opc-session-qualification/control/node.sock
```

The bounded external runner automates the deployed sequential lease/fence/CAS
slice plus fresh readiness sampling:

```console
cargo run --locked -p opc-session-testkit \
  --bin opc-session-kubernetes-campaign -- \
  --namespace session-ha-qualification \
  --members 3 \
  --rounds 120 \
  --interval-ms 1000 \
  --history-id candidate-readiness-001 \
  --output-directory /var/lib/opc-qualification/candidate-readiness-001
```

`--history-id` is a run nonce, not a reusable campaign label. Supply a unique
value for every attempt, including retries after cancellation or uncertain
delivery. The runner derives a domain-separated bounded scope from it and
namespaces every durable key, owner, schedule/history ID, operation ID, and
lease handle. This keeps retained PVC contents and a still-running node's local
handle table disjoint across attempts without exposing the source identifier in
the v1 durable workload.

The destination must be a new absolute direct child of an existing canonical
directory and use the same bounded identifier alphabet for its final name. The
runner writes a private, atomically published `transcript.jsonl`,
`schedule-v1.jsonl`, `history-v1.jsonl`,
`readiness-v3-fragment.jsonl`, and digest-binding `summary.json`; it never
overwrites a prior run. It first requires one complete fresh all-member
readiness baseline. It then executes the same frozen 15-operation schedule as
the local multiprocess foundation: lease expiry and reacquisition, explicit
lease handoff, fenced CAS generations, cross-Pod reads, one expected stale
fence rejection, and final release/read. Every operation runs on its
schedule-designated Pod and is followed by a complete all-member readiness
sample. `--rounds` retains the configured number of complete fleet sampling
rounds (including the baseline); the 15 post-operation rounds are additional
and included in the global 10,000-sample bound.

The deployed long lease is not the local foundation's 60-second value. It is
checked from the admitted serialized subprocess envelope: after op 8 returns,
the five-member op-8-through-op-14 path contains 66 bounded `kubectl` calls at
50 seconds each. Two additional command-deadline windows provide explicit
margin for acquisition-response delivery, scheduler overhead, and the bounded
cancel-and-reap path, while a hard sequential-phase deadline admits only the
exact post-acquisition envelope. The three-member calculation uses the same
formula. Both remain below `MAX_SESSION_TTL`; the 1.2-second expiry and
1.6-second wait used by the opening expiry/reacquisition proof are unchanged.

Each command invokes the same-binary client through `kubectl exec`. A mutating
command is sent once only: timeout, cancellation, malformed output, or any
other missing terminal reply is recorded as `indeterminate`, aborts the
campaign, and is never retried. Readiness samples admit only the exact typed
Openraft barrier report for that Pod's stable local identity and the complete
rendered voter-ID set, then patch only the custom Pod condition through the
status subresource. A listener, successful exec, or process liveness is never
sufficient. The runner resets all conditions before the first sample, latches
and aborts on the first missing, malformed, contradictory, oversized,
timed-out, or failed reply, then attempts an all-false final cleanup. A later
sample can never republish `True` after a failure.

Before the final Pod-condition cleanup, the runner sends one typed idempotent
process-local `forget_lease` command for every acquisition command it invoked,
including an acquisition whose reply was ambiguous. This drops only the local
guard handle; it does not release, retry, or otherwise mutate the durable
lease. Cleanup ambiguity is recorded once, never retried, and fails the
campaign. Consequently successful retained-process campaigns return the local
handle table to its pre-run cardinality instead of consuming the fixed 1,024
handle bound. If a runner or host dies before cleanup, the node reclaims expired
handles before the next acquisition and retains only the newest four released
handles needed by the fixed stale-fence schedule, so crash residue cannot grow
without bound.

The custom condition is an external evidence gate, not the freshness
authority. Kubernetes combines it with the container's generated exec
readiness probe. Every five seconds kubelet runs the same binary as a silent
`--readiness-client` against the private UDS, with the Pod's exact stable
Openraft ID and full voter-ID set rendered as arguments. The store operation,
client, and kubelet deadlines are respectively 10, 11, and 12 seconds;
`failureThreshold` and `successThreshold` are both one. A quorum loss, hung
probe, missing socket, invalid identity set, or terminated container therefore
makes the Pod unready locally even if an uncatchable runner/host failure leaves
the external condition stale. A stale custom `True` cannot override a failed
container readiness probe.

The caller must have narrowly audited `get` access for `pods`, `create` access
for `pods/exec`, and `patch` access for `pods/status` in the qualification
namespace. Those grants remain outside the rendered tokenless ServiceAccount
and manifest. The runner does not add a network control port, controller
token, ClusterRole, or ClusterRoleBinding.

Normal completion, failure, Ctrl-C, and Unix SIGTERM all attempt to set the
custom condition to `False` on every member. Cancellation wakes interval waits
and terminates and reaps an active local `kubectl` before bounded final cleanup.
Each subprocess, output stream, cleanup command, round count, and artifact is
bounded. An uncatchable process or host failure can interrupt that final
cleanup, so a deployment owner must still reset the external evidence gate
before reusing a fleet; safety does not depend on that cleanup because kubelet's
local UDS probe independently self-expires container readiness.

The emitted v1 schedule/history pair is directly consumable by
`scripts/check-session-ha-history.py`; its history contains only digest-safe
keys, owners, and values. Artifact publication does not trust an in-memory
status or completion flag: it reconstructs the scoped canonical schedule,
replays the exact sequential transcript into the history builder, validates
the contiguous prefix and every readiness/cleanup phase, and derives status
and completion before creating the destination. Empty, reordered, duplicated,
substituted, or mismatched evidence fails closed. The v3 file remains
deliberately a readiness-only fragment. It must be combined with real batch,
watch, and restore operations from the same campaign and have its full
operation count rebound before the independent v3 checker is run. The summary
keeps `experimental`,
`qualification_complete`, and `counts_for_production` fixed to `true`,
`false`, and `false`. This sequential slice therefore does not claim the
remaining #143 fault, concurrency, platform, HKMS, alerting, or signed-release
acceptance by itself.

## Candidate v5 concurrent adapter

The additive `qualification_kubernetes_concurrent_v5` API reuses the same
shell-free `KubectlQualificationKubernetesCampaignPort` and private UDS client.
It provides the deployed operation adapter that the pure v5 collector lacks:

- reset the external Pod condition fail-closed on every voter;
- pre-acquire two history-scoped leases and prove the derived restore scope is
  empty before opening the retained campaign window;
- sample exact-identity concurrent readiness on all voters in parallel;
- register a real watch, send one protected partial-success batch once only,
  and observe its common committed application-journal head;
- disable all member consensus-RPC gates, conservatively remove all schedule
  pairs at the earliest disable dispatch, boundedly require all-member
  fail-closed samples, restore the gates, and expose full schedule reachability
  only after the latest enable acknowledgement;
- retain one-second recovery samples for at most 35 seconds and require every
  voter to regain durable authority at the same terminal journal head;
- finish the watch and terminal restore concurrently on distinct Pods, then
  feed the typed observations and acknowledged fault boundaries to the frozen
  v5 collector; and
- on every exit, restore the idempotent gates, abort the watch, forget local
  lease handles, and clear the Pod condition with a fresh cleanup token.

Every attempt requires a new bounded `history_id` and a dedicated fleet with an
exclusive application-journal window. The adapter never retries an acquisition
or batch with an ambiguous reply. Its fixed fifteen-minute lease covers the
eight-minute retained campaign bound and remains durable until normal expiry;
cleanup intentionally does not fabricate a release after the evidence window.
The condition patch and control invocations use the same narrowly audited
`pods/status` and `pods/exec` permissions described above.

Per-member gate command intervals are part of the in-memory campaign input to
the schedule builder. Readiness sampling begins only after the complete
disable or enable actuation, so no observation crosses an uncertain boundary.
Any partial/ambiguous gate actuation, non-converging transition, cancellation,
or deadline withholds history and runs the same all-gates-available cleanup. A
`Ready` reply after the complete disable actuation is a contradictory result
and fails immediately rather than being filtered from candidate evidence.

The separate `opc-session-kubernetes-concurrent-v5-campaign` executable now
provides the candidate-only retained-artifact mode around this adapter. Before
any Kubernetes mutation it validates a new absolute destination whose complete
configured ancestry is root/effective-user-owned and not group/world-writable,
pins the parent device/inode, descriptor-pins and digest-checks the trusted
Python interpreter, probes it through procfs, and verifies both expected
embedded-program digests. Reusable-API callers supply those expected digests;
the CLI binds the exact programs in the invoked binary and supplies no
independent provenance trust root. Only a `Passed`, cleanup-complete result with
history proceeds to private descriptor-relative staging. The atomic bundle
contains:

- `concurrent-history-v5.jsonl`;
- `fault-schedule-v5.json`;
- `workload-schedule-v5.json`;
- `candidate-evidence-v5.json`;
- the exact `check-session-ha-concurrent-history-v5.py` bytes;
- the exact additive
  `check-session-ha-kubernetes-concurrent-v5-workload-v1.py` bytes;
- bounded exact `checker-output-v5.json`;
- bounded exact `workload-verifier-output-v1.json`; and
- `summary.json` with all retained digests and serialized
  interpreter/path/version/digest identity.

Both verification programs are launched directly with Python `-I -B -S`,
without a shell, and have a 30-second deadline, 64-KiB stdout and 16-KiB stderr
bounds. Interpreter and verifier inputs use descriptor-pinned
`/proc/<publisher-pid>/fd/<fd>` paths
while retaining `CLOEXEC`, so procfs access to the publisher's own descriptors
is an explicit Linux preflight requirement. Root/effective-user ownership is
the trust boundary; pre/post digest checks detect persistent same-inode
changes, while immutable/fs-verity-backed interpreter deployment is
operator-owned when the trusted owner itself is in the threat model.
Cancellation, launch/reap failure, timeout, oversized output, stderr, a
nonzero/non-pass result, any digest change, or publication failure attempts
private-staging cleanup and withholds the destination before the commit point.
Group termination is attempted only while the direct child remains unreaped;
normal success never signals its old numeric process-group identifier. The
trusted interpreter and verifiers must not daemonize or escape their process
group; this is not cgroup containment.
Linux publication re-resolves the pinned parent immediately before
descriptor-relative `renameat2(NOREPLACE)`; unsupported platforms fail
explicitly. A final
parent-sync failure is outcome-unknown because the complete directory may
already be visible. The SDK supplies no authenticated receipt or acceptance
verifier: quarantine it, never accept/count/replace it, and use a separate
audited operator inspection/removal procedure. `summary.json` self-consistency
is not provenance. A cleanup-unknown result likewise quarantines the parent.

The included fake-port tests prove both three- and five-member adapter output
against that checker, and artifact tests prove private atomic visibility,
no-replace races, explicit cancellation, artifact-phase future abort,
same-group process cleanup on timeout/cancellation, hostile verifier output,
and untrusted-parent rejection. API callers must cancel through the supplied
token and await to obtain typed campaign and publication cleanup status. A
combined-future drop during the deployed campaign cannot run the adapter's
asynchronous cleanup and requires audited operator recovery of gates, watch,
lease handles, and Pod condition. During the later artifact phase, future abort
performs a cleanup attempt, but an abort racing the atomic rename can leave a
destination and only stable outcome-unknown logging; callers must inspect for
and quarantine both staging and destination paths after any unacknowledged
abort, never accept/count/overwrite them.

These tests are not live Kubernetes evidence. Source/artifact metadata is
caller-asserted, `exact_release_artifact` is always false, and does not prove a
release image or platform inventory. The adapter
controls only the existing qualification RPC fault gate; it does not claim
NetworkPolicy, packet impairment, process/host/PVC failure, remote-HKMS,
rotation, soak, or production qualification coverage. Every v5 evidence and
summary maturity field remains experimental and false for production credit.

The rendered ServiceAccount remains tokenless and the manifest grants no RBAC
or controller identity. Kubernetes authorization to use `pods/exec` for this
client is nevertheless node-administrator-equivalent qualification authority:
the protocol includes fault, initialization, mutation, reauthentication, and
shutdown operations. Limit and audit that authority outside this manifest. A
real CNF `cnfctl` must still own durable-readiness gating, fault injection,
rotation ordering, history/evidence collection, and clean shutdown. Pods fail
closed behind the AND of kubelet's locally fresh UDS barrier and the custom
`opc.openpacketcore.io/durable-quorum-ready` evidence gate; `cnfctl` must set or
clear that Pod condition from a fresh durable barrier, not merely from listener
availability. Release qualification must also prove the real cluster's node and
volume failure-domain identities,
projected-Secret update behavior, DNS behavior, storage class durability,
NetworkPolicy enforcement, alert firing/clearing, and three/five-node fault and
rotation schedules. The current qualification node still uses its documented
`MemoryKeyProvider` wrapper, so this manifest is not remote-HKMS evidence.

A controller retaining a candidate run must emit the closed
`qualification/v4/session-ha-candidate-manifest.schema.json` contract. It must
digest-bind the exact profile, source revision, release binary and OCI image,
feature/configuration/environment inventories, fault and workload schedules,
bounded diagnostic/resource manifests, v1 sequential history and checker
output, and v3 concurrent evidence/history and checker output from the same
campaign. The renderer alone satisfies none of the eight v4 acceptance gates;
each remains `unproven` unless separately collected candidate evidence is
bound. Even a complete candidate manifest remains explicitly experimental and
cannot count as production qualification.
