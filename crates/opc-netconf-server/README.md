# opc-netconf-server

`opc-netconf-server` is the NETCONF server core for OpenPacketCore management
plane integrations.

The current slice is capability-gated and capability-honest:

- NETCONF base 1.0 end-marker framing.
- NETCONF base 1.1 chunked framing with malformed chunk lengths, including
  leading-zero lengths, truncated chunk bodies, and per-message chunk-count
  excesses rejected.
- Server `<hello>` rendering with base capabilities plus optional discovery,
  defaults, writable-running, candidate, confirmed-commit, and startup
  capabilities, plus notifications only when their CNF binding hooks are
  present.
- Transport-neutral session handshake and RPC loop over an already-authenticated
  stream.
- NETCONF-over-TLS TCP listener accept loop over `opc-mgmt-transport` TLS
  bootstrap, with shutdown-aware accept stop and `max_sessions` enforcement.
- Optional `opc-runtime::Supervisor` task wrappers for the TLS and SSH
  listeners.
- NETCONF-over-TLS principal extraction from verified rustls peer
  certificates, mapped through `opc-mgmt-principal` with no transport-derived
  grants.
- NETCONF-over-SSH TCP listener with caller-provisioned host keys, exact
  authorized public keys, public-key authentication only, `subsystem "netconf"`
  admission, `max_sessions` enforcement, shutdown drain, and shared
  registry-aware NETCONF session execution. Verified SSH usernames are mapped
  through `opc-mgmt-principal` into grant-free `TrustedPrincipal` values stamped
  `AuthStrength::SshPublicKey`.
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
  value-bounded before handling. Reserved XML/XMLNS namespace binding misuse,
  XML declarations that are not the first parsed event, and unexpected
  protocol-container text are rejected.
- `<close-session>` and `<kill-session>` with NACM `exec` authorization,
  payload-free denial/failure errors, audited outcomes, self-kill rejection,
  valid local session-id enforcement with exhausted-range rejection, and
  audit-before-signal in-process session-registry termination for live target
  sessions, including registered targets still waiting for client `<hello>` or
  blocked writing server hello / RPC replies.
- Running, candidate, and startup datastore `<lock>` / `<unlock>` with
  session-owned lock admission through the shared session registry.
- Optional running datastore `<edit-config>` when the CNF binding explicitly
  advertises `:writable-running` and supplies an edit candidate builder.
- Optional server-owned `:candidate` datastore support when the CNF binding opts
  in, including candidate `<edit-config>`, `<get-config>`, `<validate>`,
  `<commit>`, `<discard-changes>`, stale-running-version failure, and candidate
  lock/write guards.
- Optional `:startup` support through an explicit CNF `StartupDatastore`
  facade, including startup `<get-config>`, `<validate>`, `<edit-config>`,
  datastore-to-datastore `<copy-config>`, safe opt-in `<delete-config>`, and
  startup lock/write guards. SDK boot recovery is not treated as NETCONF
  startup.
- Optional `:confirmed-commit:1.1` support with candidate, including parsed
  `<confirmed>`, `<confirm-timeout>`, `<persist>`, `<persist-id>`,
  `<cancel-commit>`, timeout rollback through the config bus, explicit
  confirm/cancel, token-safe errors, durable rollback-parent checks, and
  non-persistent owner-session-exit rollback.
- Known-but-unimplemented NETCONF base operations are bounded, audited, and
  rejected with `operation-not-supported` while preserving `message-id`;
  bounded text and CDATA payloads inside those RPCs are ignored and never
  echoed.
- `<get-config>` for every advertised running/candidate/startup datastore.
- `<get>` for running config plus CNF-supplied operational state.
- Namespace/schema-aware structural subtree filters, including RFC 6241
  namespace wildcards, for `<get-config>` and `<get>`. Bounded subtree
  content-match and attribute-match forms are classified and rejected
  payload-free as unsupported within configured limits.
- A bounded XPath schema-selection subset for `<get-config>` and `<get>`:
  absolute prefixed child paths, `*` / `prefix:*` wildcards, and `|` union.
  Expanded schema-node fanout is rejected fail-closed before NACM or CNF
  projection when it exceeds the configured path limit. Full instance-aware
  XPath predicates, functions, axes, and the `:xpath` capability remain absent.
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
- Optional RFC 5277 live `NETCONF` stream notifications: advertised only when
  the CNF binding opts into `NetconfNotificationCapability`. The session runner
  accepts bounded `<create-subscription>`, authorizes through NACM `subscribe`,
  allows one active live subscription per session, subscribes to
  `opc-config-bus`, and emits schema-path-only RFC 6470-style config-change
  events without config values. Replay, `stopTime`, and
  notification filters are parsed within limits but rejected with
  `operation-not-supported` until bounded replay/filter semantics exist.
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
- An in-repo conformance fixture harness exercises the real session runner over
  base 1.0 and base 1.1 framing with running/candidate/startup, confirmed
  commit rollback, bounded XPath selection, `<get-schema>`, and with-defaults
  dispatch.

Complete base-session behavior is provided by the session runners. Direct
`ReadOnlyNetconfServer::handle_rpc` and `handle_rpc_xml` calls are low-level,
registry-free dispatch helpers: they preserve parser/audit/metrics/reply
behavior for one RPC, but `<kill-session>` returns `operation-not-supported`
without a live `SessionRegistry`, and `handle_rpc_xml` discards the
`<close-session>` close signal. The raw hello renderers require `NonZeroU32`
for a supplied session id, so direct helper callers cannot render `0` or an
out-of-range `<session-id>`. Custom transports that advertise a server
`<hello>` should use `run_read_only_session_with_registry` or
`run_read_only_tls_session_with_registry` /
`run_read_only_ssh_session_with_registry` for audited cross-session
`<kill-session>` and datastore lock/write semantics.

It still does not implement SSH host-key generation/storage/rotation, SSH
certificate CA authorization, password authentication, Call Home, notification
replay or notification filters, NMDA `<get-data>` / `<edit-data>`, a full RFC
XPath instance evaluator or advertised `:xpath`, URL and inline-config
copy/validate forms, `:rollback-on-error`, or external interop against
`netopeer2-cli`, `ncclient`, or a target NMS. CNFs may use generated NETCONF XML
projection/edit support for supported shapes, but unsupported YANG shapes remain
fail-closed and model-specific bindings still own any projection/edit behavior
outside the generated support matrix.
