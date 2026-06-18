//! NETCONF server core for the OpenPacketCore management plane.
//!
//! This crate is deliberately capability-honest. The current implementation
//! provides the protocol core needed to start integrating a NETCONF northbound
//! path:
//!
//! - NETCONF 1.0 and 1.1 message framing, including fail-closed rejection of
//!   malformed base 1.1 chunk lengths, truncated chunk bodies, and too many
//!   base 1.1 chunks per message.
//! - Server `<hello>` rendering with base capabilities plus optional discovery,
//!   defaults, writable-running, candidate, confirmed-commit, startup, and
//!   notification capabilities only when their CNF binding hooks are present.
//! - Transport-neutral session handshake and RPC dispatch over an already
//!   authenticated stream.
//! - NETCONF-over-TLS TCP listener accept loop over `opc-mgmt-transport`, with
//!   bounded TLS handshake timeout and session-permit release for stalled
//!   handshakes.
//! - NETCONF-over-SSH TCP listener accept loop with caller-provisioned host
//!   keys, exact public-key authorization, and `subsystem "netconf"` admission.
//! - NETCONF-over-SSH Call Home loop that dials configured NMS endpoints with
//!   bounded reconnect backoff, then runs the same SSH server/auth/subsystem
//!   path over the outbound TCP stream.
//! - Optional `opc-runtime::Supervisor` task wrappers for the TLS and SSH
//!   listeners and SSH Call Home.
//! - NETCONF-over-TLS principal extraction from verified rustls peer
//!   certificates.
//! - NETCONF-over-SSH authenticated-channel helpers that require
//!   `TransportType::NetconfSsh` and an `AuthStrength::SshPublicKey` principal.
//!   Host-key generation/storage/rotation and SSH certificate CA policy are
//!   deployment-owned inputs to this server profile.
//! - Bounded XML parsing for client `<hello>` and RPC envelopes, including
//!   fail-closed rejection of missing, empty, or duplicate client hello
//!   capability containers, bounded XPath filter `select` expressions, plus
//!   `MgmtLimits::max_paths_per_request` enforcement after subtree/XPath
//!   filters expand into schema-node selections;
//!   parser errors after a valid `<rpc>` envelope preserve `message-id` without
//!   echoing payload text, bounded extra `<rpc>` attributes are copied onto all
//!   `<rpc-reply>` forms per RFC 6241 with prefixed NETCONF reply elements when
//!   a copied default namespace would otherwise collide with the reply
//!   namespace, and reserved XML/XMLNS namespace binding misuse, XML
//!   declarations that are not the first parsed event, and unexpected
//!   protocol-container text are rejected. XML text/CDATA plus non-text event
//!   payloads (comments, processing instructions,
//!   declarations, doctypes, and entity references) are value-bounded before
//!   handling.
//! - `<close-session>`, `<kill-session>`, and running datastore
//!   `<lock>`/`<unlock>` with NACM `exec` authorization, payload-free
//!   denial/failure errors, audited outcomes, self-kill rejection, valid local
//!   session-id enforcement with exhausted-range rejection, audit-before-signal
//!   in-process session-registry termination for live target sessions, and
//!   audit-before-state-change lock ownership.
//! - Optional running datastore `<edit-config>` through registry-aware session
//!   runners when the CNF binding explicitly advertises `:writable-running` and
//!   implements the candidate builder hook. The server owns the NETCONF envelope
//!   parser, bounded namespace-preserving `<config>` capture, NACM `exec`
//!   authorization, running lock/write serialization, config-bus submission,
//!   commit-error mapping, metrics, and audit. The CNF owns schema-aware XML to
//!   config translation. This path supports running, candidate, and startup
//!   targets only when their capabilities/backing facades are present;
//!   `test-only`, `continue-on-error`, and `rollback-on-error` fail closed.
//! - Known-but-unimplemented NETCONF base operations are parsed only far
//!   enough to preserve `message-id`, audit the failed attempt, and return
//!   payload-free `operation-not-supported`; bounded text and CDATA payloads
//!   inside those RPCs are ignored and never echoed.
//! - `<get-config>` against the authoritative running snapshot published by
//!   `opc-config-bus`.
//! - `<get>` against running config plus CNF-supplied operational state.
//! - Namespace/schema-aware structural subtree filters, including RFC 6241
//!   namespace wildcards, plus a bounded XPath schema-selection subset
//!   (absolute prefixed child paths, wildcards, and union) for `<get-config>`
//!   and `<get>`; expanded schema-node fanout is rejected fail-closed before
//!   NACM or CNF projection when it exceeds the configured path limit. Full RFC
//!   XPath predicates, functions, axes, and the `:xpath` capability remain
//!   intentionally absent until an instance-aware evaluator exists.
//! - RFC 6243 `<with-defaults>` request parameters are recognized. The
//!   `:with-defaults` capability is advertised only when the CNF binding
//!   supplies a `WithDefaultsCapability` and default-aware XML projection hooks;
//!   otherwise requests are rejected with `operation-not-supported`. If a binding
//!   advertises the capability but the matching projection hook is absent or
//!   fails, the request fails closed with `operation-failed` and does not fall
//!   back to ordinary rendering.
//! - Optional RFC 8525 YANG Library read path and `:yang-library:1.1`
//!   advertisement when the CNF binding supplies a content-id and XML renderer.
//! - Optional RFC 6022 NETCONF monitoring and `<get-schema>` path when the CNF
//!   binding supplies `/netconf-state` XML and schema source retrieval.
//!   Over-declared discovery capabilities fail closed with `operation-failed`
//!   instead of falling back to ordinary rendering or pretending the data is
//!   absent.
//! - Optional RFC 5277 live `NETCONF` stream notifications backed by
//!   `opc-config-bus` subscribers. The server accepts bounded
//!   `<create-subscription>` only when the binding opts into
//!   `:notification:1.0`, authorizes subscription through NACM `subscribe`,
//!   allows one active live subscription per session, emits schema-path-only
//!   RFC 6470-style config-change events, and never includes config values.
//!   Replay, stop-time, and notification filters are recognized but rejected
//!   with payload-free `operation-not-supported` until bounded replay/filter
//!   support exists.
//! - Read NACM and audit integration through the shared management crates; an
//!   all-denied `<get-config>` or `<get>` returns empty `<data/>` without
//!   invoking the CNF config projection hook or operational-state provider, and
//!   provider-omitted state paths are pruned before XML projection. Malformed
//!   provider responses with unrequested paths, duplicate paths, or unrequested
//!   origin metadata fail closed before XML projection.
//!
//! Complete base-session semantics are provided by the session runners. The
//! public [`ReadOnlyNetconfServer::handle_rpc`] and
//! [`ReadOnlyNetconfServer::handle_rpc_xml`] helpers are registry-free,
//! low-level dispatch helpers: they preserve parser/audit/metrics/reply
//! behavior for one RPC, but `<kill-session>`, `<lock>`, `<unlock>`,
//! `<edit-config>`, and `<create-subscription>` return
//! `operation-not-supported` without a live [`SessionRegistry`] and session
//! loop, and `handle_rpc_xml` discards the `<close-session>` close signal. The
//! raw hello
//! renderers require
//! `NonZeroU32` for a supplied session id, so direct helper callers cannot
//! render `0` or an out-of-range `<session-id>`. Custom transports that
//! advertise a server `<hello>` should use
//! [`run_read_only_session_with_registry`] or
//! [`run_read_only_tls_session_with_registry`] or
//! [`run_read_only_ssh_session_with_registry`] to get audited cross-session
//! `<kill-session>`, datastore lock/write semantics, and notification delivery.
//!
//! The raw session-registry controls are intentionally not part of the public
//! API. Custom transports share a [`SessionRegistry`] by passing it into
//! [`run_read_only_session_with_registry`] or
//! [`run_read_only_tls_session_with_registry`] or
//! [`run_read_only_ssh_session_with_registry`]; they cannot register or
//! terminate sessions outside the audited RPC path:
//!
//! ```compile_fail
//! let registry = opc_netconf_server::SessionRegistry::new();
//! let _registration = registry.register(1);
//! ```
//!
//! ```compile_fail
//! let registry = opc_netconf_server::SessionRegistry::new();
//! let _ = registry.terminate_after(1, || Ok::<(), ()>(()));
//! ```
//!
//! The public registry handle is also deliberately not `Debug`, so accidentally
//! formatting the handle cannot dump live session ids from the private map:
//!
//! ```compile_fail
//! let registry = opc_netconf_server::SessionRegistry::new();
//! let _ = format!("{registry:?}");
//! ```
//!
//! The session-context RPC entry point is also crate-private. Custom transports
//! cannot inject arbitrary current-session ids; they must use the
//! registry-aware session runners:
//!
//! ```compile_fail
//! use opc_config_model::{OpcConfig, RequestId, TrustedPrincipal};
//! use opc_mgmt_audit::AuditSink;
//! use opc_mgmt_authz::PolicySource;
//! use opc_mgmt_limits::MgmtLimits;
//! use opc_netconf_server::{NetconfConfigBinding, ReadOnlyNetconfServer, SessionRegistry};
//!
//! fn cannot_inject_session_context<C, B, P, A>(
//!     server: &ReadOnlyNetconfServer<C, B, P, A>,
//!     principal: &TrustedPrincipal,
//!     sessions: &SessionRegistry,
//! ) where
//!     C: OpcConfig,
//!     B: NetconfConfigBinding<C>,
//!     P: PolicySource,
//!     A: AuditSink,
//! {
//!     let _ = server.handle_rpc_for_session(
//!         RequestId::new(),
//!         principal,
//!         "<rpc/>",
//!         &MgmtLimits::default(),
//!         1,
//!         sessions,
//!     );
//! }
//! ```
//!
//! It does not claim generic YANG XML projection. Generated config models are
//! RFC 7951 JSON-capable today; a CNF must supply the XML projection binding for
//! the models, discovery trees, and schema sources it serves until the
//! generator/runtime grows that facade.

#![forbid(unsafe_code)]

pub mod binding;
pub mod capabilities;
mod discovery;
mod edit_xml;
pub mod error;
pub mod filter;
pub mod framing;
pub mod listener;
mod metrics;
pub mod operations;
pub mod server;
pub mod session;
mod session_registry;
pub mod ssh;
pub mod supervision;
pub mod transport;
pub mod xml;

pub use binding::{
    BindingError, EditConfigCandidate, EditConfigError, GetSchemaError,
    GetSchemaRequest as NetconfGetSchemaRequest, NetconfConfigBinding, NetconfMonitoringCapability,
    NetconfNotificationCapability, ReadSelection, WithDefaultsCapability, YangLibraryCapability,
};
pub use capabilities::{
    read_only_base_capabilities, read_only_capabilities, render_server_hello, NETCONF_BASE_1_0,
    NETCONF_BASE_1_1, NETCONF_BASE_NS, NETCONF_MONITORING_NS, NETCONF_MONITORING_REVISION,
    NETCONF_NOTIFICATION_NS, NOTIFICATION_1_0, WITH_DEFAULTS_1_0_BASE, WITH_DEFAULTS_NS,
    WRITABLE_RUNNING_1_0, YANG_LIBRARY_1_1_BASE, YANG_LIBRARY_REVISION,
};
pub use error::{
    rpc_error_reply, rpc_get_schema_reply, rpc_ok_empty_reply, rpc_ok_reply, xml_escape, RpcError,
};
pub use filter::{
    get_config_paths, get_paths_with_discovery, get_paths_with_yang_library,
    netconf_monitoring_registry, yang_library_registry, FilterError, GetPathSelection,
    NETCONF_MONITORING_MODULE, NETCONF_MONITORING_PREFIX, YANG_LIBRARY_MODULE, YANG_LIBRARY_NS,
    YANG_LIBRARY_PREFIX,
};
pub use listener::{
    run_read_only_tls_listener, TlsListenerConfig, TlsListenerError, TlsListenerResult,
};
pub use server::{ReadOnlyNetconfServer, RpcHandlingResult, ServerInitError};
pub use session::{
    run_read_only_session, run_read_only_session_with_registry, SessionConfig, SessionError,
    SessionFraming, SessionResult,
};
pub use session_registry::SessionRegistry;
pub use ssh::{
    run_read_only_ssh_call_home, run_read_only_ssh_listener, SshAuthorizedKey, SshCallHomeConfig,
    SshCallHomeError, SshCallHomeResult, SshHostKey, SshListenerConfig, SshListenerError,
    SshListenerResult,
};
pub use supervision::{
    spawn_read_only_ssh_call_home, spawn_read_only_ssh_listener, spawn_read_only_tls_listener,
    SupervisedSshCallHomeConfig, SupervisedSshListenerConfig, SupervisedTlsListenerConfig,
};
pub use transport::{
    principal_from_identity_state, principal_from_identity_watch, principal_from_tls_stream,
    run_read_only_ssh_session, run_read_only_ssh_session_with_registry, run_read_only_tls_session,
    run_read_only_tls_session_with_registry, SshSessionError, TlsPrincipalError, TlsSessionError,
};
pub use xml::{
    parse_client_hello, parse_rpc, ClientHello, CreateSubscriptionRequest, Datastore,
    EditConfigRequest, EditDefaultOperation, EditErrorOption, EditTestOption, Filter,
    FilterElement, FilterKind, GetConfigRequest, GetRequest, KillSessionRequest, LockRequest,
    ParsedRpc, RpcOperation, SubtreeFilter, SubtreeSelection, UnlockRequest, UnsupportedOperation,
    ValidateRequest, WithDefaultsMode, XmlError,
};
