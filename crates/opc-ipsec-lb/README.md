# opc-ipsec-lb

Pure SWu IKE/IPsec load-balancing primitives for OpenPacketCore CNFs.

This crate is the kernel-independent foundation for an ePDG/N3IWF/TWIF
steer layer:

- tagged SPI layout and allocation policy;
- clone-shared tagged-SPI reservations for excluding HA-restored live SAs from
  fresh and rekey allocation, with explicit release on SA retirement;
- rendezvous selection for shard and `IKE_SA_INIT` bootstrap routing;
- UDP/500 and UDP/4500 SWu classifier with RFC 3948 non-ESP marker handling;
- stateless IKE cookie helper for edge DoS posture;
- failover safety guards for IV-counter and replay-window restoration;
- audited same-SPI re-pin coordination with monotonic ownership fencing;
- BGP route-export VIP advertisement through the safe route-steering backend;
- session-store backed ownership reads and fenced SA-owner promotion;
- Host-XDP cross-node redirect config that fails closed unless mTLS/SPIFFE
  with no plaintext fallback is declared;
- NIC/DPU inline IPsec crypto offload posture validation for documented
  FIPS/HSM key-custody scope;
- reusable ports for steering backends, VIP advertisement, ownership reads,
  ownership fencing, and re-pin audit.

It intentionally does not decrypt ESP, derive IPsec keys, open BGP sessions,
shell out to routing daemons, implement VRRP, or claim packet forwarding.
Host-XDP steering and BGP route-export VIP advertisement are implemented behind
ports; SR-IOV, NIC offload, direct BGP speaker integrations, VRRP adapters, and
live failover evidence remain product/lab tiers built behind the ports. A
re-pin install never sets `forwarding_proven`; packet-flow proof must be
injected by lab/product dataplane evidence.

Same-SPI resume supports ESP Child SAs with 64-bit ESN and IKE SAs with a
64-bit AEAD explicit-IV counter; protocol-typed evidence must match the SA and
its steering SPI. Both persisted and live-mirrored key/counter sources must
supply an [RFC 6311](https://www.rfc-editor.org/rfc/rfc6311.html) send-IV
forward-jump of at least `2^30`, and the restored next IV must exactly match the
checked `checkpointed_next + forward_jump` result. The configured jump must
also bound the deployment's maximum packets sent between checkpoints. ESP ESN
evidence must additionally attest `max_peer_sequence_lag`: how far the peer's
highest authenticated sequence may trail `checkpointed_next - 1`, including
pre-checkpoint packet loss. [RFC 4303 Appendix
A2.2](https://www.rfc-editor.org/rfc/rfc4303.html#appendix-A.2.2) reconstructs
the untransmitted high-order bits from receiver replay-window state and assumes
a window no wider than `2^31`, so validation requires the checked sum
`forward_jump + 1 + max_peer_sequence_lag <= 2^31`. The exported ESP maximum
`2^31 - 1` is therefore only the absolute ceiling for an attested zero-lag
peer; any lag reduces it. ESP checkpoints and all resumed SA identifiers must
be non-zero. IKE's explicit-IV checkpoint may be zero and has no ESP-specific
maximum, but checked `u64` overflow always fails closed and requires rekey.

Inbound anti-replay evidence explicitly selects either a bit-for-bit exact
replay-window restore or bounded reopening with no bitmap-continuity claim.
The latter carries the caller-attested total number of previously accepted
values that might reopen, including lost bitmap state and post-checkpoint lag;
the SDK does not invent a deployment policy default. High-watermark rollback,
exact state not bound to its checkpoint, and a zero reopening bound fail closed.

Prepare every re-pin from `OwnershipSource::sa_ownership`, retaining both the
authoritative owner and its exact fence in `RePinRequest`. Generate one non-zero,
deployment-unique `OwnershipTransitionId` for that logical transition and reuse
it only when retrying the identical request; a later transition, including an
A→B→A owner cycle, requires a new ID. The coordinator computes a canonical
SHA-256 fingerprint over the complete safety-critical request and verifies that
the committed grant matches it. Session-store birth records use an empty
plaintext metadata payload; successful promotions replace it with versioned
transition-ID/fingerprint metadata. Ownership records with an expiry, an
arbitrary payload, or any mismatched key/type/owner/fence metadata fail closed.

After a store-backed ownership commit, recoverable audit or steering failures
return a non-cloneable partial for `RePinCoordinator::retry`; callers should
move that value into their retry queue and record its redaction-safe cause.
Before starting `repin`, retain a request clone (or clone `partial.request()`
before `retry`) when the future can be cancelled: replay performs a read-only
exact-fence recovery before it considers another ownership mutation. Steering
and audit ports must treat identical inputs idempotently so apply-then-error
outcomes converge. The coordinator revalidates the exact SA fence and takes a
final target-shard owner snapshot immediately before installing steering.
Those separate reads cannot make the current `SteeringBackend` mutation atomic
or order repeated A→B→C failovers; fence-aware steering replacement is tracked in
[issue #103](https://github.com/openpacketcore/openpacketcore-sdk/issues/103).

## Entropy note

The current ePDG SWu LB draft requires an embedded routing tag while also
requiring at least 64 unpredictable non-tag bits. That is not satisfiable for a
64-bit IKE responder SPI with any fixed tag, and ESP SPIs are only 32 bits.
`TaggedSpiLayout` therefore validates the requested entropy floor and fails
closed when a layout cannot meet it. Tests cover this explicitly so downstream
code cannot silently weaken SPI unpredictability.

## Verification

```sh
cargo fmt --all --check
cargo clippy --locked -p opc-ipsec-lb --all-targets --all-features -- -D warnings
cargo test --locked -p opc-ipsec-lb --all-features -- --test-threads=4
```
