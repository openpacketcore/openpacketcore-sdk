# opc-netconf-server

`opc-netconf-server` is the NETCONF server core for OpenPacketCore management
plane integrations.

The current slice is intentionally read-only and capability-honest:

- NETCONF base 1.0 end-marker framing.
- NETCONF base 1.1 chunked framing.
- Server `<hello>` rendering with base capabilities plus optional discovery
  capabilities only when their CNF binding hooks are present.
- Transport-neutral session handshake and RPC loop over an already-authenticated
  stream.
- NETCONF-over-TLS TCP listener accept loop over `opc-mgmt-transport` TLS
  bootstrap, with shutdown-aware accept stop and `max_sessions` enforcement.
- Optional `opc-runtime::Supervisor` task wrapper for the TLS listener.
- NETCONF-over-TLS principal extraction from verified rustls peer
  certificates, mapped through `opc-mgmt-principal` with no transport-derived
  grants.
- Bounded XML parsing for client `<hello>` and RPC envelopes.
- `<close-session>` with `<ok/>` reply and clean session teardown.
- Known-but-unimplemented NETCONF base operations are bounded, audited, and
  rejected with `operation-not-supported` while preserving `message-id`.
- `<get-config>` for the `running` datastore only.
- `<get>` for running config plus CNF-supplied operational state.
- Namespace/schema-aware structural subtree filters, including RFC 6241
  namespace wildcards, for `<get-config running>` and `<get>`.
- RFC 6243 `<with-defaults>` request parameters are recognized. The
  `:with-defaults` capability is advertised only when the CNF binding supplies
  a `WithDefaultsCapability` and default-aware XML projection hooks; otherwise
  requests are rejected with `operation-not-supported`. If a binding advertises
  the capability but the matching projection hook is absent or fails, the
  request fails closed with `operation-failed` and does not fall back to ordinary
  rendering.
- Optional RFC 8525 YANG Library read path: advertised as
  `:yang-library:1.1` only when the CNF binding supplies a content-id and XML
  renderer; otherwise the capability and namespace remain absent/fail-closed.
  If the capability is over-declared without a renderer, discovery reads fail
  closed with `operation-failed`.
- Optional RFC 6022 NETCONF monitoring and `<get-schema>` path: advertised only
  when the CNF binding supplies `/netconf-state` XML and schema source
  retrieval; otherwise the capability/namespace remain absent/fail-closed and
  `<get-schema>` returns `operation-not-supported`. If the capability is
  over-declared without a renderer or schema-source hook, discovery reads and
  `<get-schema>` fail closed with `operation-failed`.
- Read authorization through `opc-mgmt-authz`; if NACM denies every selected
  `<get-config>` or `<get>` data path, the server returns empty `<data/>`
  without calling the CNF config projection hook or operational-state provider.
  For `<get>`, state paths omitted by the operational provider are also pruned
  before XML projection, so absence cannot be rendered as fabricated state.
  Malformed provider responses with unrequested paths, duplicate paths, or
  unrequested origin metadata fail closed before XML projection.
- Read audit through `opc-mgmt-audit`.
- NETCONF RPC/session/NACM-denial metrics emitted through the shared
  `opc-redaction` registry with low-cardinality sanitized labels.

It does not implement SSH, Call Home, candidate/startup datastores, XPath
filters, subtree content-match/attribute-match forms, `:with-defaults` default
projection, writes, notifications, or generic YANG XML projection yet. A CNF
supplies NETCONF XML projection for config, operational state, YANG Library,
NETCONF monitoring, and schema source data through `NetconfConfigBinding` until
`opc-yanggen` grows schema-aware XML output and raw YANG source metadata.
