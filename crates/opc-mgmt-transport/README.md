# opc-mgmt-transport

Fail-closed mTLS bootstrap for the OpenPacketCore management plane (gNMI and
NETCONF servers), layered over `opc-tls`.

`opc-tls` fails closed on an unconstrained `PeerPolicy::default()` unless the
caller explicitly opts in, and it sets no ALPN on the server config. This crate
is the management-plane policy gate that makes the production posture explicit
and refuses to start insecurely:

- in fail-closed runtime modes (`RuntimeMode::Production` / `Conformance`) it
  **rejects an unconstrained `PeerPolicy`** (authentication without
  authorization);
- in non-fail-closed runtime modes it performs the explicit
  `allow_any_trusted_peer()` opt-in before delegating to `opc-tls`;
- it validates the caller's ALPN protocol ids (non-empty, <=255 bytes) and sets
  them on the built `rustls::ServerConfig` (e.g. `h2` for gNMI/gRPC);
- it builds the SPIFFE mTLS server config from a hot-reloading SVID watch
  (TLS 1.3 only unless TLS 1.2 compatibility is explicitly opted in);
- it provides a plaintext guard so a plaintext listener is permitted only for
  `RuntimeMode::Dev` or an explicit `RuntimeMode::Lab` profile, not for
  production, conformance, or perf runs.

Certificate-chain verification and the actual SVID handling stay in `opc-tls` /
rustls; this crate only enforces the management-plane security policy and wiring.
