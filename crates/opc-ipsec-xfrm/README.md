# opc-ipsec-xfrm

Safe Linux XFRM IPsec backend model, mock backend, and redaction-safe errors for
OpenPacketCore.

This crate provides:

- `XfrmBackend`: an async trait for allocating SPIs, installing/querying/
  rekeying/removing Security Associations, and installing/rekeying/removing
  Security Policies.
- `MockXfrmBackend`: a deterministic in-memory test double that records every
  operation and supports injected failures.
- `LinuxXfrmBackend`: a safe production backend that encodes SDK SA/SPD
  requests into Linux `NETLINK_XFRM` messages through `opc-linux-xfrm-sys`.
- `UnsupportedXfrmBackend`: a backend that reports `UnsupportedPlatform` on all
  mutating operations for non-Linux or intentionally disabled builds.
- Redaction-safe model types such as `KeyMaterial`, whose `Debug` and `Display`
  implementations never emit raw key bytes.
- SA query and restore models for replay/sequence continuity: `query_sa`
  returns `SaState` without key material, and `SaParameters::replay_state`
  restores legacy or ESN replay counters/bitmaps on install/rekey.
- `XfrmError`: an error enum with payload-free labels safe for logs and support
  bundles.
- Optional `ikev2` feature: a validated mapper from
  `opc-proto-ikev2` Child SA negotiation intent to bidirectional XFRM SA and
  policy install requests. The mapper is intentionally exact: it rejects
  non-ESP protocol IDs, malformed or zero SPIs, unrepresentable traffic-selector
  ranges, mismatched address families, missing directional keys, and zero replay
  windows instead of approximating product policy.

Raw Linux netlink socket work is intentionally kept in `opc-linux-xfrm-sys`.
This crate does not implement IKE, ESP processing, SA/SPD policy, namespace
management, product deployment defaults, or traffic-readiness decisions.
