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

The bounded external runner automates only the fresh readiness-probe slice:

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

The destination must be a new absolute direct child of an existing canonical
directory and use the same bounded identifier alphabet for its final name. The
runner writes a private, atomically published
`transcript.jsonl`, `readiness-v3-fragment.jsonl`, and digest-binding
`summary.json`; it never overwrites a prior run. Each sample invokes the
same-binary client through `kubectl exec`, admits only the exact typed
Openraft barrier report for that Pod's stable local identity and the complete
rendered voter-ID set, and patches only the custom Pod condition through the
status subresource. A listener, successful exec, or process liveness is never
sufficient. The runner resets all conditions before the first sample, latches
and aborts on the first missing, malformed, contradictory, oversized,
timed-out, or failed reply, then attempts an all-false final cleanup. A later
sample can never republish `True` after a failure.

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

Normal completion, failure, and Ctrl-C all attempt to set the custom condition
to `False` on every member. Each subprocess, output stream, round count, and
artifact is bounded. An uncatchable process or host failure can interrupt that
final cleanup, so a deployment owner must still reset the external evidence
gate before reusing a fleet; safety does not depend on that cleanup because
kubelet's local UDS probe independently self-expires container readiness.

The v3 file is deliberately a readiness-only fragment. It must be combined
with real batch, watch, and restore operations from the same campaign and have
its full operation count rebound before the independent v3 checker is run.
The runner produces no v1 sequential workload history and its summary keeps
`experimental`, `qualification_complete`, and `counts_for_production` fixed to
`true`, `false`, and `false`. It therefore closes no #143 acceptance gate by
itself.

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
