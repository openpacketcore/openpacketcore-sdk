//! NETCONF capability constants and `<hello>` rendering.

use std::num::NonZeroU32;

use crate::binding::{NetconfMonitoringCapability, WithDefaultsCapability, YangLibraryCapability};
use crate::error::xml_escape;

/// NETCONF base namespace URI.
pub const NETCONF_BASE_NS: &str = "urn:ietf:params:xml:ns:netconf:base:1.0";
/// NETCONF base 1.0 capability.
pub const NETCONF_BASE_1_0: &str = "urn:ietf:params:netconf:base:1.0";
/// NETCONF base 1.1 capability.
pub const NETCONF_BASE_1_1: &str = "urn:ietf:params:netconf:base:1.1";
/// RFC 8526 NETCONF YANG Library 1.1 capability base URI.
pub const YANG_LIBRARY_1_1_BASE: &str = "urn:ietf:params:netconf:capability:yang-library:1.1";
/// RFC 8525 `ietf-yang-library` revision required by RFC 8526.
pub const YANG_LIBRARY_REVISION: &str = "2019-01-04";
/// RFC 6022 NETCONF monitoring XML namespace.
pub const NETCONF_MONITORING_NS: &str = "urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring";
/// RFC 6022 `ietf-netconf-monitoring` revision.
pub const NETCONF_MONITORING_REVISION: &str = "2010-10-04";
/// RFC 6243 `ietf-netconf-with-defaults` XML namespace.
///
/// The read-only core supports this capability only when the embedding CNF
/// advertises default-aware projection through `NetconfConfigBinding`.
pub const WITH_DEFAULTS_NS: &str = "urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults";
/// RFC 6243 NETCONF with-defaults capability base URI.
pub const WITH_DEFAULTS_1_0_BASE: &str = "urn:ietf:params:netconf:capability:with-defaults:1.0";

const NETCONF_MONITORING_MODULE: &str = "ietf-netconf-monitoring";

const READ_ONLY_CAPABILITIES: [&str; 2] = [NETCONF_BASE_1_0, NETCONF_BASE_1_1];

/// Returns the base capabilities implemented by the current read-only server core.
///
/// Candidate, startup, writable-running, validate, confirmed-commit,
/// with-defaults, XPath, and notifications are intentionally absent until those
/// behaviors exist and are tested. Optional binding-backed capabilities are
/// appended by [`read_only_capabilities`] only when their hooks are present.
pub const fn read_only_base_capabilities() -> &'static [&'static str] {
    &READ_ONLY_CAPABILITIES
}

/// Returns the capabilities advertised for this server instance.
///
/// YANG Library, NETCONF monitoring, and with-defaults are included only when
/// the embedding CNF supplied the matching capability descriptors and renderers
/// through [`crate::binding::NetconfConfigBinding`].
pub fn read_only_capabilities(
    yang_library: Option<&YangLibraryCapability>,
    monitoring: Option<&NetconfMonitoringCapability>,
    with_defaults: Option<&WithDefaultsCapability>,
) -> Vec<String> {
    let mut capabilities = read_only_base_capabilities()
        .iter()
        .map(|capability| (*capability).to_string())
        .collect::<Vec<_>>();
    if let Some(yang_library) = yang_library {
        capabilities.push(yang_library_capability(yang_library.content_id()));
    }
    if monitoring.is_some() {
        capabilities.push(netconf_monitoring_capability());
    }
    if let Some(with_defaults) = with_defaults {
        capabilities.push(with_defaults_capability(with_defaults));
    }
    capabilities
}

/// Renders a server `<hello>` document.
///
/// A NETCONF session id is optional in the raw renderer, but when present it is
/// represented as [`NonZeroU32`] so callers cannot render an unaddressable
/// `<session-id>`.
pub fn render_server_hello(
    session_id: Option<NonZeroU32>,
    yang_library: Option<&YangLibraryCapability>,
    monitoring: Option<&NetconfMonitoringCapability>,
    with_defaults: Option<&WithDefaultsCapability>,
) -> String {
    let capabilities = read_only_capabilities(yang_library, monitoring, with_defaults);
    render_hello(&capabilities, session_id)
}

fn yang_library_capability(content_id: &str) -> String {
    format!(
        "{YANG_LIBRARY_1_1_BASE}?revision={YANG_LIBRARY_REVISION}&content-id={}",
        uri_query_escape(content_id)
    )
}

fn netconf_monitoring_capability() -> String {
    format!(
        "{NETCONF_MONITORING_NS}?module={NETCONF_MONITORING_MODULE}&revision={NETCONF_MONITORING_REVISION}"
    )
}

fn with_defaults_capability(capability: &WithDefaultsCapability) -> String {
    let mut out = format!(
        "{WITH_DEFAULTS_1_0_BASE}?basic-mode={}",
        capability.basic_mode().as_str()
    );
    if !capability.also_supported().is_empty() {
        out.push_str("&also-supported=");
        for (index, mode) in capability.also_supported().iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str(mode.as_str());
        }
    }
    out
}

fn uri_query_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(hex(byte >> 4));
            out.push(hex(byte & 0x0f));
        }
    }
    out
}

const fn hex(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'A' + (nibble - 10)) as char,
    }
}

fn render_hello(capabilities: &[String], session_id: Option<NonZeroU32>) -> String {
    let mut out = String::from(r#"<hello xmlns=""#);
    out.push_str(NETCONF_BASE_NS);
    out.push_str(r#""><capabilities>"#);
    for capability in capabilities {
        out.push_str("<capability>");
        out.push_str(&xml_escape(capability));
        out.push_str("</capability>");
    }
    out.push_str("</capabilities>");
    if let Some(session_id) = session_id {
        out.push_str("<session-id>");
        out.push_str(&session_id.get().to_string());
        out.push_str("</session-id>");
    }
    out.push_str("</hello>");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_capabilities_are_base_only_without_yang_library() {
        let capabilities = read_only_capabilities(None, None, None);
        assert_eq!(capabilities, [NETCONF_BASE_1_0, NETCONF_BASE_1_1]);
        assert!(!capabilities.iter().any(|cap| cap.contains("candidate")));
        assert!(!capabilities.iter().any(|cap| cap.contains("startup")));
        assert!(!capabilities
            .iter()
            .any(|cap| cap.contains("writable-running")));
        assert!(!capabilities.iter().any(|cap| cap.contains("xpath")));
        assert!(!capabilities.iter().any(|cap| cap.contains("with-defaults")));
        assert!(!capabilities.iter().any(|cap| cap.contains("yang-library")));
        assert!(!capabilities
            .iter()
            .any(|cap| cap.contains("ietf-netconf-monitoring")));
    }

    #[test]
    fn yang_library_capability_includes_revision_and_escaped_content_id() {
        let yang_library =
            YangLibraryCapability::new("fnv1a64:abc&def").expect("capability content id");
        let capabilities = read_only_capabilities(Some(&yang_library), None, None);

        assert_eq!(capabilities.len(), 3);
        assert_eq!(
            capabilities[2],
            "urn:ietf:params:netconf:capability:yang-library:1.1?revision=2019-01-04&content-id=fnv1a64%3Aabc%26def"
        );

        let hello = render_server_hello(
            std::num::NonZeroU32::new(42),
            Some(&yang_library),
            None,
            None,
        );
        assert!(hello.contains("yang-library:1.1?revision=2019-01-04"));
        assert!(hello.contains("content-id=fnv1a64%3Aabc%26def"));
    }

    #[test]
    fn monitoring_capability_is_opt_in() {
        let monitoring = NetconfMonitoringCapability;
        let capabilities = read_only_capabilities(None, Some(&monitoring), None);

        assert_eq!(capabilities.len(), 3);
        assert_eq!(capabilities[0], NETCONF_BASE_1_0);
        assert_eq!(capabilities[1], NETCONF_BASE_1_1);
        assert_eq!(
            capabilities[2],
            "urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring?module=ietf-netconf-monitoring&revision=2010-10-04"
        );
    }

    #[test]
    fn with_defaults_capability_is_opt_in_and_lists_modes() {
        let with_defaults = WithDefaultsCapability::new(
            crate::xml::WithDefaultsMode::ReportAll,
            [
                crate::xml::WithDefaultsMode::Trim,
                crate::xml::WithDefaultsMode::Explicit,
                crate::xml::WithDefaultsMode::ReportAllTagged,
            ],
        )
        .expect("with-defaults capability");
        let capabilities = read_only_capabilities(None, None, Some(&with_defaults));

        assert_eq!(capabilities.len(), 3);
        assert_eq!(
            capabilities[2],
            "urn:ietf:params:netconf:capability:with-defaults:1.0?basic-mode=report-all&also-supported=trim,explicit,report-all-tagged"
        );
    }

    #[test]
    fn hello_contains_session_id_when_requested() {
        let hello = render_server_hello(std::num::NonZeroU32::new(42), None, None, None);
        assert!(hello.contains(NETCONF_BASE_1_0));
        assert!(hello.contains(NETCONF_BASE_1_1));
        assert!(hello.contains("<session-id>42</session-id>"));
    }
}
