# opc-ipsec-xfrm

Safe Linux XFRM IPsec backend model, mock backend, and redaction-safe errors for
OpenPacketCore.

This crate provides:

- `XfrmBackend`: an async trait for allocating SPIs and installing, rekeying,
  and removing Security Associations and Security Policies.
- `MockXfrmBackend`: a deterministic in-memory test double that records every
  operation and supports injected failures.
- `UnsupportedXfrmBackend`: a backend that reports `UnsupportedPlatform` on all
  mutating operations for non-Linux or intentionally disabled builds.
- Redaction-safe model types such as `KeyMaterial`, whose `Debug` and `Display`
  implementations never emit raw key bytes.
- `XfrmError`: an error enum with payload-free labels safe for logs and support
  bundles.

Raw Linux netlink work is intentionally kept in `opc-linux-xfrm-sys`. This crate
does not implement IKE, ESP processing, SA/SPD policy, namespace management, or
product deployment defaults.
