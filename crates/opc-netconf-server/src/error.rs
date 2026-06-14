//! NETCONF response helpers.

use opc_mgmt_errors::{NetconfError, NetconfErrorTag, NetconfErrorType};

use crate::capabilities::{NETCONF_BASE_NS, NETCONF_MONITORING_NS};

/// A client-facing NETCONF RPC error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpcError {
    /// RFC 6241 error classification.
    pub classification: NetconfError,
    /// Static, payload-free message text.
    pub message: &'static str,
    /// Optional stable application error tag.
    pub app_tag: Option<&'static str>,
}

impl RpcError {
    /// Builds an RPC error from a classification and static message.
    pub const fn new(classification: NetconfError, message: &'static str) -> Self {
        Self {
            classification,
            message,
            app_tag: None,
        }
    }

    /// Adds a stable application error tag.
    pub const fn with_app_tag(mut self, app_tag: &'static str) -> Self {
        self.app_tag = Some(app_tag);
        self
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
    let mut out = String::from(r#"<rpc-reply xmlns=""#);
    out.push_str(NETCONF_BASE_NS);
    out.push_str(r#"" message-id=""#);
    out.push_str(&xml_escape(message_id));
    out.push_str(r#"">"#);
    if data_xml.trim().is_empty() {
        out.push_str("<data/>");
    } else {
        out.push_str("<data>");
        out.push_str(data_xml);
        out.push_str("</data>");
    }
    out.push_str("</rpc-reply>");
    out
}

/// Renders a successful RFC 6022 `<get-schema>` `<rpc-reply>`.
pub fn rpc_get_schema_reply(message_id: &str, schema_xml: &str) -> String {
    let mut out = String::from(r#"<rpc-reply xmlns=""#);
    out.push_str(NETCONF_BASE_NS);
    out.push_str(r#"" message-id=""#);
    out.push_str(&xml_escape(message_id));
    out.push_str(r#""><data xmlns=""#);
    out.push_str(NETCONF_MONITORING_NS);
    out.push_str(r#"">"#);
    out.push_str(schema_xml);
    out.push_str("</data></rpc-reply>");
    out
}

/// Renders a successful non-data `<rpc-reply>` with `<ok/>`.
pub fn rpc_ok_empty_reply(message_id: &str) -> String {
    let mut out = String::from(r#"<rpc-reply xmlns=""#);
    out.push_str(NETCONF_BASE_NS);
    out.push_str(r#"" message-id=""#);
    out.push_str(&xml_escape(message_id));
    out.push_str(r#""><ok/></rpc-reply>"#);
    out
}

/// Renders an `<rpc-error>` reply.
pub fn rpc_error_reply(message_id: Option<&str>, error: RpcError) -> String {
    let mut out = String::from(r#"<rpc-reply xmlns=""#);
    out.push_str(NETCONF_BASE_NS);
    out.push('"');
    if let Some(message_id) = message_id {
        out.push_str(r#" message-id=""#);
        out.push_str(&xml_escape(message_id));
        out.push('"');
    }
    out.push_str("><rpc-error><error-type>");
    out.push_str(error.classification.error_type.as_str());
    out.push_str("</error-type><error-tag>");
    out.push_str(error.classification.tag.as_str());
    out.push_str("</error-tag><error-severity>error</error-severity><error-message>");
    out.push_str(&xml_escape(error.message));
    out.push_str("</error-message>");
    if let Some(app_tag) = error.app_tag {
        out.push_str("<error-app-tag>");
        out.push_str(&xml_escape(app_tag));
        out.push_str("</error-app-tag>");
    }
    out.push_str("</rpc-error></rpc-reply>");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
