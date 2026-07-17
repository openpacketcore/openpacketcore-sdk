//! NETCONF response helpers.

use opc_config_bus::ConfigLeaderHint;
use opc_config_model::CommittedConfigRevision;
use opc_mgmt_errors::{NetconfError, NetconfErrorTag, NetconfErrorType};

use crate::capabilities::{NETCONF_BASE_NS, NETCONF_MONITORING_NS};

/// Namespace for OpenPacketCore NETCONF authority/revision response elements.
pub const OPC_NETCONF_CONFIG_AUTHORITY_NS: &str =
    "urn:openpacketcore:params:xml:ns:netconf:config-authority:1.0";

/// Stable `error-app-tag` used for writer-of-record redirects.
pub const NETCONF_NOT_LEADER_APP_TAG: &str = "not-leader";

/// Bounded extra attributes copied from a request `<rpc>` to `<rpc-reply>`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RpcReplyAttributes {
    attrs: Vec<(String, String)>,
}

impl RpcReplyAttributes {
    /// Builds reply attributes from parser-owned XML attribute name/value pairs.
    pub(crate) fn from_pairs(attrs: Vec<(String, String)>) -> Self {
        Self { attrs }
    }

    /// Returns true when no extra request attributes need to be copied.
    pub fn is_empty(&self) -> bool {
        self.attrs.is_empty()
    }

    fn append_to_start_tag(&self, out: &mut String) {
        for (name, value) in &self.attrs {
            out.push(' ');
            out.push_str(name);
            out.push_str(r#"=""#);
            out.push_str(&xml_escape(value));
            out.push('"');
        }
    }

    fn contains_default_namespace(&self) -> bool {
        self.attrs.iter().any(|(name, _)| name == "xmlns")
    }

    fn contains_namespace_prefix(&self, prefix: &str) -> bool {
        self.attrs
            .iter()
            .any(|(name, _)| name.strip_prefix("xmlns:") == Some(prefix))
    }
}

/// A client-facing NETCONF RPC error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpcError {
    /// RFC 6241 error classification.
    pub classification: NetconfError,
    /// Static, payload-free message text.
    pub message: &'static str,
    /// Optional stable application error tag.
    pub app_tag: Option<&'static str>,
    /// Optional RFC-defined error-info payload.
    pub info: Option<RpcErrorInfo>,
}

/// Structured RFC-defined `<error-info>` payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcErrorInfo {
    /// `lock-denied` owner session id.
    LockDenied {
        /// NETCONF session id of the lock owner, or zero for non-NETCONF owner.
        session_id: u64,
    },
}

impl RpcError {
    /// Builds an RPC error from a classification and static message.
    pub const fn new(classification: NetconfError, message: &'static str) -> Self {
        Self {
            classification,
            message,
            app_tag: None,
            info: None,
        }
    }

    /// Adds a stable application error tag.
    pub const fn with_app_tag(mut self, app_tag: &'static str) -> Self {
        self.app_tag = Some(app_tag);
        self
    }

    /// `(protocol, lock-denied)` with RFC 6241 owner `session-id`.
    pub const fn lock_denied(session_id: u64) -> Self {
        Self {
            classification: NetconfError::new(
                NetconfErrorType::Protocol,
                NetconfErrorTag::LockDenied,
            ),
            message: "lock denied",
            app_tag: None,
            info: Some(RpcErrorInfo::LockDenied { session_id }),
        }
    }

    /// `(protocol, operation-not-supported)`.
    pub const fn operation_not_supported() -> Self {
        Self::new(
            NetconfError::new(
                NetconfErrorType::Protocol,
                NetconfErrorTag::OperationNotSupported,
            ),
            "operation not supported",
        )
    }

    /// `(protocol, access-denied)`.
    pub const fn access_denied() -> Self {
        Self::new(
            NetconfError::new(NetconfErrorType::Protocol, NetconfErrorTag::AccessDenied),
            "access denied",
        )
    }

    /// `(application, invalid-value)`.
    pub const fn invalid_value() -> Self {
        Self::new(
            NetconfError::new(NetconfErrorType::Application, NetconfErrorTag::InvalidValue),
            "invalid value",
        )
    }

    /// `(application, data-missing)`.
    pub const fn data_missing() -> Self {
        Self::new(
            NetconfError::new(NetconfErrorType::Application, NetconfErrorTag::DataMissing),
            "data missing",
        )
    }

    /// `(application, operation-failed)`.
    pub const fn operation_failed() -> Self {
        Self::new(
            NetconfError::new(
                NetconfErrorType::Application,
                NetconfErrorTag::OperationFailed,
            ),
            "operation failed",
        )
    }

    /// `(application, resource-denied)`.
    pub const fn resource_denied() -> Self {
        Self::new(
            NetconfError::new(
                NetconfErrorType::Application,
                NetconfErrorTag::ResourceDenied,
            ),
            "resource denied",
        )
    }

    /// `(protocol, too-big)`.
    pub const fn too_big() -> Self {
        Self::new(
            NetconfError::new(NetconfErrorType::Protocol, NetconfErrorTag::TooBig),
            "request is too large",
        )
    }
}

/// Escapes XML character data or attribute values.
pub fn xml_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Renders a successful `<rpc-reply>`.
pub fn rpc_ok_reply(message_id: &str, data_xml: &str) -> String {
    rpc_ok_reply_with_attrs(message_id, &RpcReplyAttributes::default(), data_xml)
}

/// Renders a successful `<rpc-reply>` with copied request attributes.
pub fn rpc_ok_reply_with_attrs(
    message_id: &str,
    reply_attrs: &RpcReplyAttributes,
    data_xml: &str,
) -> String {
    rpc_ok_reply_with_attrs_and_data_ns(message_id, reply_attrs, NETCONF_BASE_NS, data_xml)
}

/// Renders a successful `<rpc-reply>` whose `<data>` element is in `data_ns`.
pub fn rpc_ok_reply_with_attrs_and_data_ns(
    message_id: &str,
    reply_attrs: &RpcReplyAttributes,
    data_ns: &str,
    data_xml: &str,
) -> String {
    let mut out = String::new();
    let prefix = append_rpc_reply_start(&mut out, Some(message_id), reply_attrs);
    out.push('>');
    let data_tag = if data_ns == NETCONF_BASE_NS {
        netconf_tag(prefix.as_deref(), "data")
    } else {
        "data".to_string()
    };
    if data_xml.trim().is_empty() {
        out.push('<');
        out.push_str(&data_tag);
        append_data_namespace(&mut out, data_ns);
        out.push_str("/>");
    } else {
        out.push('<');
        out.push_str(&data_tag);
        append_data_namespace(&mut out, data_ns);
        out.push('>');
        out.push_str(data_xml);
        out.push_str("</");
        out.push_str(&data_tag);
        out.push('>');
    }
    append_rpc_reply_end(&mut out, prefix.as_deref());
    out
}

fn append_data_namespace(out: &mut String, data_ns: &str) {
    if data_ns == NETCONF_BASE_NS {
        return;
    }
    out.push_str(r#" xmlns=""#);
    out.push_str(data_ns);
    out.push('"');
}

/// Renders a successful RFC 6022 `<get-schema>` `<rpc-reply>`.
pub fn rpc_get_schema_reply(message_id: &str, schema_text: &str) -> String {
    rpc_get_schema_reply_with_attrs(message_id, &RpcReplyAttributes::default(), schema_text)
}

/// Renders a successful RFC 6022 `<get-schema>` reply with copied attributes.
pub fn rpc_get_schema_reply_with_attrs(
    message_id: &str,
    reply_attrs: &RpcReplyAttributes,
    schema_text: &str,
) -> String {
    let mut out = String::new();
    let prefix = append_rpc_reply_start(&mut out, Some(message_id), reply_attrs);
    out.push_str(r#"><data xmlns=""#);
    out.push_str(NETCONF_MONITORING_NS);
    out.push_str(r#"">"#);
    out.push_str(&xml_escape(schema_text));
    out.push_str("</data>");
    append_rpc_reply_end(&mut out, prefix.as_deref());
    out
}

/// Renders a successful non-data `<rpc-reply>` with `<ok/>`.
pub fn rpc_ok_empty_reply(message_id: &str) -> String {
    rpc_ok_empty_reply_with_attrs(message_id, &RpcReplyAttributes::default())
}

/// Renders a successful non-data reply with copied request attributes.
pub fn rpc_ok_empty_reply_with_attrs(message_id: &str, reply_attrs: &RpcReplyAttributes) -> String {
    let mut out = String::new();
    let prefix = append_rpc_reply_start(&mut out, Some(message_id), reply_attrs);
    let ok_tag = netconf_tag(prefix.as_deref(), "ok");
    out.push_str("><");
    out.push_str(&ok_tag);
    out.push_str("/>");
    append_rpc_reply_end(&mut out, prefix.as_deref());
    out
}

/// Renders a successful opt-in commit reply with `<ok/>` followed by the
/// datastore-attested committed revision.
pub fn rpc_ok_committed_revision_reply(
    message_id: &str,
    revision: CommittedConfigRevision,
) -> String {
    rpc_ok_committed_revision_reply_with_attrs(message_id, &RpcReplyAttributes::default(), revision)
}

pub(crate) fn rpc_ok_committed_revision_reply_with_attrs(
    message_id: &str,
    reply_attrs: &RpcReplyAttributes,
    revision: CommittedConfigRevision,
) -> String {
    let mut out = String::new();
    let prefix = append_rpc_reply_start(&mut out, Some(message_id), reply_attrs);
    let ok_tag = netconf_tag(prefix.as_deref(), "ok");
    out.push_str("><");
    out.push_str(&ok_tag);
    out.push_str(r#"/><committed-revision xmlns=""#);
    out.push_str(OPC_NETCONF_CONFIG_AUTHORITY_NS);
    out.push_str(r#""><version>"#);
    out.push_str(&revision.version.get().to_string());
    out.push_str("</version><content-hash algorithm=\"sha-256\">");
    out.push_str(&revision.content_hash_hex());
    out.push_str("</content-hash></committed-revision>");
    append_rpc_reply_end(&mut out, prefix.as_deref());
    out
}

/// Renders an `<rpc-error>` reply.
pub fn rpc_error_reply(message_id: Option<&str>, error: RpcError) -> String {
    rpc_error_reply_with_attrs(message_id, &RpcReplyAttributes::default(), error)
}

/// Renders an `<rpc-error>` reply with copied request attributes.
pub fn rpc_error_reply_with_attrs(
    message_id: Option<&str>,
    reply_attrs: &RpcReplyAttributes,
    error: RpcError,
) -> String {
    rpc_error_reply_with_attrs_and_leader_hint(message_id, reply_attrs, error, None)
}

pub(crate) fn rpc_not_leader_reply_with_attrs(
    message_id: Option<&str>,
    reply_attrs: &RpcReplyAttributes,
    leader_hint: Option<&ConfigLeaderHint>,
) -> String {
    rpc_error_reply_with_attrs_and_leader_hint(
        message_id,
        reply_attrs,
        RpcError::operation_failed().with_app_tag(NETCONF_NOT_LEADER_APP_TAG),
        leader_hint,
    )
}

fn rpc_error_reply_with_attrs_and_leader_hint(
    message_id: Option<&str>,
    reply_attrs: &RpcReplyAttributes,
    error: RpcError,
    leader_hint: Option<&ConfigLeaderHint>,
) -> String {
    let mut out = String::new();
    let prefix = append_rpc_reply_start(&mut out, message_id, reply_attrs);
    let rpc_error_tag = netconf_tag(prefix.as_deref(), "rpc-error");
    let error_type_tag = netconf_tag(prefix.as_deref(), "error-type");
    let error_tag_tag = netconf_tag(prefix.as_deref(), "error-tag");
    let error_severity_tag = netconf_tag(prefix.as_deref(), "error-severity");
    let error_message_tag = netconf_tag(prefix.as_deref(), "error-message");
    let error_app_tag = netconf_tag(prefix.as_deref(), "error-app-tag");
    let error_info_tag = netconf_tag(prefix.as_deref(), "error-info");
    let session_id_tag = netconf_tag(prefix.as_deref(), "session-id");
    out.push_str("><");
    out.push_str(&rpc_error_tag);
    out.push_str("><");
    out.push_str(&error_type_tag);
    out.push('>');
    out.push_str(error.classification.error_type.as_str());
    out.push_str("</");
    out.push_str(&error_type_tag);
    out.push_str("><");
    out.push_str(&error_tag_tag);
    out.push('>');
    out.push_str(error.classification.tag.as_str());
    out.push_str("</");
    out.push_str(&error_tag_tag);
    out.push_str("><");
    out.push_str(&error_severity_tag);
    out.push_str(">error</");
    out.push_str(&error_severity_tag);
    out.push_str("><");
    out.push_str(&error_message_tag);
    out.push('>');
    out.push_str(&xml_escape(error.message));
    out.push_str("</");
    out.push_str(&error_message_tag);
    out.push('>');
    if let Some(app_tag) = error.app_tag {
        out.push('<');
        out.push_str(&error_app_tag);
        out.push('>');
        out.push_str(&xml_escape(app_tag));
        out.push_str("</");
        out.push_str(&error_app_tag);
        out.push('>');
    }
    if let Some(info) = error.info {
        match info {
            RpcErrorInfo::LockDenied { session_id } => {
                out.push('<');
                out.push_str(&error_info_tag);
                out.push_str("><");
                out.push_str(&session_id_tag);
                out.push('>');
                out.push_str(&session_id.to_string());
                out.push_str("</");
                out.push_str(&session_id_tag);
                out.push_str("></");
                out.push_str(&error_info_tag);
                out.push('>');
            }
        }
    }
    if let Some(hint) = leader_hint {
        out.push('<');
        out.push_str(&error_info_tag);
        out.push_str(r#"><leader-hint xmlns=""#);
        out.push_str(OPC_NETCONF_CONFIG_AUTHORITY_NS);
        out.push_str(r#"">"#);
        out.push_str(&xml_escape(hint.as_str()));
        out.push_str("</leader-hint></");
        out.push_str(&error_info_tag);
        out.push('>');
    }
    out.push_str("</");
    out.push_str(&rpc_error_tag);
    out.push('>');
    append_rpc_reply_end(&mut out, prefix.as_deref());
    out
}

fn append_rpc_reply_start(
    out: &mut String,
    message_id: Option<&str>,
    reply_attrs: &RpcReplyAttributes,
) -> Option<String> {
    let prefix = reply_prefix(reply_attrs);
    if let Some(prefix) = &prefix {
        out.push('<');
        out.push_str(prefix);
        out.push_str(r#":rpc-reply xmlns:"#);
        out.push_str(prefix);
        out.push_str(r#"=""#);
        out.push_str(NETCONF_BASE_NS);
        out.push('"');
    } else {
        out.push_str(r#"<rpc-reply xmlns=""#);
        out.push_str(NETCONF_BASE_NS);
        out.push('"');
    }
    if let Some(message_id) = message_id {
        out.push_str(r#" message-id=""#);
        out.push_str(&xml_escape(message_id));
        out.push('"');
    }
    reply_attrs.append_to_start_tag(out);
    prefix
}

fn append_rpc_reply_end(out: &mut String, prefix: Option<&str>) {
    out.push_str("</");
    if let Some(prefix) = prefix {
        out.push_str(prefix);
        out.push(':');
    }
    out.push_str("rpc-reply>");
}

fn reply_prefix(reply_attrs: &RpcReplyAttributes) -> Option<String> {
    if !reply_attrs.contains_default_namespace() {
        return None;
    }

    for i in 0.. {
        let candidate = if i == 0 {
            "nc".to_string()
        } else {
            format!("nc{i}")
        };
        if !reply_attrs.contains_namespace_prefix(&candidate) {
            return Some(candidate);
        }
    }
    unreachable!("unbounded prefix search always returns");
}

fn netconf_tag(prefix: Option<&str>, local: &str) -> String {
    match prefix {
        Some(prefix) => format!("{prefix}:{local}"),
        None => local.to_string(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use opc_types::ConfigVersion;

    #[test]
    fn public_rpc_error_contract_remains_copy_and_exhaustive() {
        fn assert_copy<T: Copy>() {}
        fn lock_owner(info: RpcErrorInfo) -> u64 {
            match info {
                RpcErrorInfo::LockDenied { session_id } => session_id,
            }
        }

        assert_copy::<RpcError>();
        assert_copy::<RpcErrorInfo>();
        assert_eq!(lock_owner(RpcErrorInfo::LockDenied { session_id: 42 }), 42);
    }

    #[test]
    fn escapes_attribute_values() {
        assert_eq!(xml_escape("a&b<'\">"), "a&amp;b&lt;&apos;&quot;&gt;");
    }

    #[test]
    fn error_reply_contains_stable_classification_only() {
        let reply = rpc_error_reply(Some("m1"), RpcError::operation_not_supported());
        assert!(reply.contains("<error-type>protocol</error-type>"));
        assert!(reply.contains("<error-tag>operation-not-supported</error-tag>"));
        assert!(!reply.contains("candidate datastore"));
    }

    #[test]
    fn rpc_reply_helpers_copy_extra_attributes_escaped() {
        let attrs =
            RpcReplyAttributes::from_pairs(vec![("trace:id".to_string(), "a&b\"c".to_string())]);

        let ok = rpc_ok_empty_reply_with_attrs("m1", &attrs);
        assert!(ok.contains(r#"trace:id="a&amp;b&quot;c""#));

        let data = rpc_ok_reply_with_attrs("m1", &attrs, "");
        assert!(data.contains(r#"trace:id="a&amp;b&quot;c""#));

        let schema = rpc_get_schema_reply_with_attrs("m1", &attrs, "module demo {}");
        assert!(schema.contains(r#"trace:id="a&amp;b&quot;c""#));

        let error = rpc_error_reply_with_attrs(Some("m1"), &attrs, RpcError::operation_failed());
        assert!(error.contains(r#"trace:id="a&amp;b&quot;c""#));
    }

    #[test]
    fn get_schema_reply_escapes_raw_yang_source_text() {
        let reply = rpc_get_schema_reply_with_attrs(
            "m1",
            &RpcReplyAttributes::default(),
            r#"module demo { description "a < b & c"; }"#,
        );
        assert!(reply.contains("module demo"));
        assert!(reply.contains("&quot;a &lt; b &amp; c&quot;"));
        assert!(!reply.contains("\"a < b & c\""));
    }

    #[test]
    fn rpc_reply_helpers_prefix_netconf_when_copying_default_namespace() {
        let attrs = RpcReplyAttributes::from_pairs(vec![
            ("xmlns".to_string(), "urn:client:default".to_string()),
            (
                "xmlns:nc".to_string(),
                "urn:client:nc-collision".to_string(),
            ),
            ("client-tag".to_string(), "cli-1".to_string()),
        ]);

        let ok = rpc_ok_reply_with_attrs("m1", &attrs, "");
        assert!(ok.starts_with(&format!(
            r#"<nc1:rpc-reply xmlns:nc1="{NETCONF_BASE_NS}" message-id="m1""#
        )));
        assert!(ok.contains(r#" xmlns="urn:client:default""#));
        assert!(ok.contains(r#" xmlns:nc="urn:client:nc-collision""#));
        assert!(ok.contains("<nc1:data/>"));
        assert!(ok.ends_with("</nc1:rpc-reply>"));

        let empty = rpc_ok_empty_reply_with_attrs("m1", &attrs);
        assert!(empty.contains("<nc1:ok/>"));

        let error = rpc_error_reply_with_attrs(Some("m1"), &attrs, RpcError::operation_failed());
        assert!(error.contains("<nc1:rpc-error><nc1:error-type>"));
        assert!(error.contains("</nc1:rpc-error></nc1:rpc-reply>"));
    }

    #[test]
    fn lock_denied_error_includes_prefixed_owner_session_id() {
        let attrs = RpcReplyAttributes::from_pairs(vec![(
            "xmlns".to_string(),
            "urn:client:default".to_string(),
        )]);

        let reply = rpc_error_reply_with_attrs(Some("m1"), &attrs, RpcError::lock_denied(454));

        assert!(reply.contains("<nc:rpc-error><nc:error-type>protocol</nc:error-type>"));
        assert!(reply.contains("<nc:error-tag>lock-denied</nc:error-tag>"));
        assert!(reply.contains("<nc:error-info><nc:session-id>454</nc:session-id></nc:error-info>"));
    }

    #[test]
    fn not_leader_hint_is_escaped_and_preserves_reply_namespaces() {
        let attrs = RpcReplyAttributes::from_pairs(vec![
            ("xmlns".to_string(), "urn:client:default".to_string()),
            ("client:trace".to_string(), "trace-1".to_string()),
            ("xmlns:client".to_string(), "urn:client:trace".to_string()),
        ]);
        let hint = ConfigLeaderHint::new("node&<>\"'").expect("printable hint");

        let reply = rpc_not_leader_reply_with_attrs(Some("m&1"), &attrs, Some(&hint));

        assert!(reply.starts_with(&format!(
            r#"<nc:rpc-reply xmlns:nc="{NETCONF_BASE_NS}" message-id="m&amp;1""#
        )));
        assert!(reply.contains(r#" xmlns="urn:client:default""#));
        assert!(reply.contains(r#" client:trace="trace-1""#));
        assert!(reply.contains("<nc:error-tag>operation-failed</nc:error-tag>"));
        assert!(reply.contains(&format!(
            "<nc:error-app-tag>{NETCONF_NOT_LEADER_APP_TAG}</nc:error-app-tag>"
        )));
        assert!(reply.contains(&format!(
            r#"<nc:error-info><leader-hint xmlns="{OPC_NETCONF_CONFIG_AUTHORITY_NS}">node&amp;&lt;&gt;&quot;&apos;</leader-hint></nc:error-info>"#
        )));
        assert!(reply.ends_with("</nc:rpc-reply>"));
        assert!(!reply.contains("node&<"));
    }

    #[test]
    fn committed_revision_reply_is_exact_and_prefix_safe() {
        let revision = CommittedConfigRevision::new(ConfigVersion::new(42), [0xa5; 32]);
        let expected_hash = "a5".repeat(32);

        assert_eq!(
            rpc_ok_committed_revision_reply("m1", revision),
            format!(
                r#"<rpc-reply xmlns="{NETCONF_BASE_NS}" message-id="m1"><ok/><committed-revision xmlns="{OPC_NETCONF_CONFIG_AUTHORITY_NS}"><version>42</version><content-hash algorithm="sha-256">{expected_hash}</content-hash></committed-revision></rpc-reply>"#
            )
        );

        let attrs = RpcReplyAttributes::from_pairs(vec![(
            "xmlns".to_string(),
            "urn:client:default".to_string(),
        )]);
        let prefixed = rpc_ok_committed_revision_reply_with_attrs("m1", &attrs, revision);
        assert!(prefixed.contains("<nc:ok/>"));
        assert!(prefixed.contains(&format!(
            r#"<committed-revision xmlns="{OPC_NETCONF_CONFIG_AUTHORITY_NS}">"#
        )));
        assert!(prefixed.ends_with("</nc:rpc-reply>"));
    }
}
