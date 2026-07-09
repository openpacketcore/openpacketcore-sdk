# opc-ipsec-lb

Pure SWu IKE/IPsec load-balancing primitives for OpenPacketCore CNFs.

This crate is the kernel-independent foundation for an ePDG/N3IWF/TWIF
steer layer:

- tagged SPI layout and allocation policy;
- rendezvous selection for shard and `IKE_SA_INIT` bootstrap routing;
- UDP/500 and UDP/4500 SWu classifier with RFC 3948 non-ESP marker handling;
- stateless IKE cookie helper for edge DoS posture;
- failover safety guards for IV-counter and replay-window restoration;
- audited same-SPI re-pin coordination with monotonic ownership fencing;
- reusable ports for steering backends, VIP advertisement, ownership reads,
  ownership fencing, and re-pin audit.

It intentionally does not decrypt ESP, derive IPsec keys, advertise BGP/VRRP,
or claim packet forwarding. Host-XDP steering is implemented behind the backend
port; SR-IOV, NIC offload, VIP adapters, and live failover evidence remain
product/lab tiers built behind the ports. A re-pin install never sets
`forwarding_proven`; packet-flow proof must be injected by lab/product dataplane
evidence.

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
