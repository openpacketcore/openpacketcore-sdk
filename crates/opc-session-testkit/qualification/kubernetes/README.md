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

The rendered ServiceAccount remains tokenless and the manifest grants no RBAC
or controller identity. Kubernetes authorization to use `pods/exec` for this
client is nevertheless node-administrator-equivalent qualification authority:
the protocol includes fault, initialization, mutation, reauthentication, and
shutdown operations. Limit and audit that authority outside this manifest. A
real CNF `cnfctl` must still own durable-readiness gating, fault injection,
rotation ordering, history/evidence collection, and clean shutdown. Pods fail
closed behind the custom `opc.openpacketcore.io/durable-quorum-ready` readiness
gate; `cnfctl` must continuously set or clear that Pod condition from a fresh
durable barrier, not merely from listener availability. Release qualification
must also prove the real cluster's node and volume failure-domain identities,
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
