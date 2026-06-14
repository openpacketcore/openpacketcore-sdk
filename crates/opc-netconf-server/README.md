# opc-netconf-server

`opc-netconf-server` is the NETCONF server core for OpenPacketCore management
plane integrations.

The current slice is intentionally read-only and capability-honest:

- NETCONF base 1.0 end-marker framing.
- NETCONF base 1.1 chunked framing with malformed chunk lengths, including
  leading-zero lengths, truncated chunk bodies, and per-message chunk-count
  excesses rejected.
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
- Bounded XML parsing for client `<hello>` and RPC envelopes, including
  fail-closed rejection of missing, empty, or duplicate client hello capability
  containers, plus `MgmtLimits::max_paths_per_request` enforcement after subtree
  filters expand into schema-node selections. Parser errors that occur after a
  valid `<rpc>` envelope is read preserve the client `message-id` while keeping
  payload text out of the reply; bounded extra `<rpc>` attributes are copied
  onto all `<rpc-reply>` forms per RFC 6241, with prefixed NETCONF reply
  elements when a copied default namespace would otherwise collide with the
  reply namespace. XML text/CDATA plus non-text event payloads (comments,
  processing instructions, declarations, doctypes, and entity references) are
  value-bounded before handling. Reserved XML/XMLNS namespace binding misuse, XML declarations
  that are not the first parsed event, and unexpected protocol-container text
  are rejected.
- `<close-session>` with NACM `exec` authorization, `<ok/>` reply, and clean
  session teardown.
- Known-but-unimplemented NETCONF base operations are bounded, audited, and
  rejected with `operation-not-supported` while preserving `message-id`;
  bounded text and CDATA payloads inside those RPCs are ignored and never
  echoed.
- `<get-config>` for the `running` datastore only.
- `<get>` for running config plus CNF-supplied operational state.
- Namespace/schema-aware structural subtree filters, including RFC 6241
  namespace wildcards, for `<get-config running>` and `<get>`; expanded
  schema-node fanout is rejected fail-closed before NACM or CNF projection when
  it exceeds the configured path limit.
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
