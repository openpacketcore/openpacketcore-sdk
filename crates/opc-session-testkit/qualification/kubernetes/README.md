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

The process keeps stdin open so an authenticated campaign controller can drive
the existing strict JSON-line protocol. A real CNF `cnfctl` must still own that
control channel, durable-readiness gating, fault injection, rotation ordering,
history/evidence collection, and clean shutdown. Pods fail closed behind the
custom `opc.openpacketcore.io/durable-quorum-ready` readiness gate; `cnfctl`
must continuously set or clear that Pod condition from a fresh durable barrier,
not merely from listener availability. Release qualification must also prove
the real cluster's node and volume failure-domain identities,
projected-Secret update behavior, DNS behavior, storage class durability,
NetworkPolicy enforcement, alert firing/clearing, and three/five-node fault and
rotation schedules. The current qualification node still uses its documented
`MemoryKeyProvider` wrapper, so this manifest is not remote-HKMS evidence.
