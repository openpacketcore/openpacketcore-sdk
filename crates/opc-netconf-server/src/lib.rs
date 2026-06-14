//! NETCONF server core for the OpenPacketCore management plane.
//!
//! This crate is deliberately capability-honest. The current implementation
//! provides the read-only protocol core needed to start integrating a NETCONF
//! northbound path:
//!
//! - NETCONF 1.0 and 1.1 message framing, including fail-closed rejection of
//!   malformed base 1.1 chunk lengths, truncated chunk bodies, and too many
//!   base 1.1 chunks per message.
//! - Server `<hello>` rendering with base capabilities plus optional discovery
//!   capabilities only when their CNF binding hooks are present.
//! - Transport-neutral session handshake and RPC dispatch over an already
//!   authenticated stream.
//! - NETCONF-over-TLS TCP listener accept loop over `opc-mgmt-transport`.
//! - Optional `opc-runtime::Supervisor` task wrapper for the TLS listener.
//! - NETCONF-over-TLS principal extraction from verified rustls peer
//!   certificates.
//! - Bounded XML parsing for client `<hello>` and RPC envelopes, including
//!   fail-closed rejection of missing, empty, or duplicate client hello
//!   capability containers, plus `MgmtLimits::max_paths_per_request`
//!   enforcement after subtree filters expand into schema-node selections;
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
//! - `<close-session>` with NACM `exec` authorization, `<ok/>` reply, and clean
//!   session teardown.
//! - Known-but-unimplemented NETCONF base operations are parsed only far
//!   enough to preserve `message-id`, audit the failed attempt, and return
//!   payload-free `operation-not-supported`; bounded text and CDATA payloads
//!   inside those RPCs are ignored and never echoed.
//! - `<get-config>` against the authoritative running snapshot published by
//!   `opc-config-bus`.
//! - `<get>` against running config plus CNF-supplied operational state.
//! - Namespace/schema-aware structural subtree filters, including RFC 6241
//!   namespace wildcards, for `<get-config running>` and `<get>`; expanded
//!   schema-node fanout is rejected fail-closed before NACM or CNF projection
//!   when it exceeds the configured path limit.
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
//! - Read NACM and audit integration through the shared management crates; an
//!   all-denied `<get-config>` or `<get>` returns empty `<data/>` without
//!   invoking the CNF config projection hook or operational-state provider, and
//!   provider-omitted state paths are pruned before XML projection. Malformed
//!   provider responses with unrequested paths, duplicate paths, or unrequested
//!   origin metadata fail closed before XML projection.
//!
//! It does not claim generic YANG XML projection. Generated config models are
//! RFC 7951 JSON-capable today; a CNF must supply the XML projection binding for
//! the models, discovery trees, and schema sources it serves until the
//! generator/runtime grows that facade.

#![forbid(unsafe_code)]

pub mod binding;
pub mod capabilities;
pub mod error;
pub mod filter;
pub mod framing;
pub mod listener;
mod metrics;
pub mod operations;
pub mod server;
pub mod session;
pub mod supervision;
pub mod transport;
pub mod xml;

pub use binding::{
    BindingError, GetSchemaError, GetSchemaRequest as NetconfGetSchemaRequest,
    NetconfConfigBinding, NetconfMonitoringCapability, ReadSelection, WithDefaultsCapability,
    YangLibraryCapability,
};
pub use capabilities::{
    read_only_base_capabilities, read_only_capabilities, render_server_hello, NETCONF_BASE_1_0,
    NETCONF_BASE_1_1, NETCONF_BASE_NS, NETCONF_MONITORING_NS, NETCONF_MONITORING_REVISION,
    WITH_DEFAULTS_1_0_BASE, WITH_DEFAULTS_NS, YANG_LIBRARY_1_1_BASE, YANG_LIBRARY_REVISION,
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
    run_read_only_session, SessionConfig, SessionError, SessionFraming, SessionResult,
};
pub use supervision::{spawn_read_only_tls_listener, SupervisedTlsListenerConfig};
pub use transport::{
    principal_from_identity_state, principal_from_identity_watch, principal_from_tls_stream,
    run_read_only_tls_session, TlsPrincipalError, TlsSessionError,
};
pub use xml::{
    parse_client_hello, parse_rpc, ClientHello, Datastore, Filter, FilterElement, FilterKind,
    GetConfigRequest, GetRequest, ParsedRpc, RpcOperation, SubtreeFilter, SubtreeSelection,
    UnsupportedOperation, WithDefaultsMode, XmlError,
};
