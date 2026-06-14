use generated_test::netconf_xml::renderer;
use generated_test::types::*;
use opc_mgmt_schema::{DefaultReport, NetconfProjectionError, NetconfXmlRenderer};

fn sample_config() -> System {
    let mut system = System::default();
    system.hostname = LeafPresence::Explicit("router1".to_string());
    system.enabled = LeafPresence::Explicit(true);
    system.secret = SecretLeaf::new(LeafPresence::Explicit("hunter2".to_string()));
    system.uptime = Some(123);
    let mut dns = Dns::default();
    dns.server = LeafPresence::Explicit("1.1.1.1".to_string());
    system.dns = Some(dns);
    system
}

#[test]
fn selected_leaf_only() {
    let system = sample_config();
    let xml = renderer()
        .render_running_config(&system, &["/ex:system/ex:hostname"], DefaultReport::Trim)
        .unwrap();
    assert!(xml.contains("<ex:hostname>router1</ex:hostname>"));
    assert!(!xml.contains("<ex:secret>"));
    assert!(!xml.contains("hunter2"));
}

#[test]
fn selected_container_and_descendants() {
    let system = sample_config();
    let xml = renderer()
        .render_running_config(&system, &["/ex:system/ex:dns"], DefaultReport::Trim)
        .unwrap();
    assert!(xml.contains("<ex:dns>"));
    assert!(xml.contains("<ex:server>1.1.1.1</ex:server>"));
    assert!(xml.contains("</ex:dns>"));
}

#[test]
fn denied_leaf_omitted() {
    let system = sample_config();
    let xml = renderer()
        .render_running_config(
            &system,
            &["/ex:system/ex:hostname", "/ex:system/ex:enabled"],
            DefaultReport::Trim,
        )
        .unwrap();
    assert!(xml.contains("<ex:hostname>"));
    assert!(xml.contains("<ex:enabled>true</ex:enabled>"));
    assert!(!xml.contains("<ex:secret>"));
    assert!(!xml.contains("hunter2"));
}

#[test]
fn secret_value_is_redacted() {
    let system = sample_config();
    let xml = renderer()
        .render_running_config(&system, &["/ex:system/ex:secret"], DefaultReport::Trim)
        .unwrap();
    assert!(xml.contains("<ex:secret>"));
    assert!(!xml.contains("hunter2"));
    assert!(xml.ends_with("</ex:secret>") || xml.contains("</ex:secret>"));
}

#[test]
fn xml_special_chars_escaped() {
    let mut system = System::default();
    system.hostname = LeafPresence::Explicit("a & b < c > d".to_string());
    let xml = renderer()
        .render_running_config(&system, &["/ex:system/ex:hostname"], DefaultReport::Trim)
        .unwrap();
    assert!(xml.contains("<ex:hostname>a &amp; b &lt; c &gt; d</ex:hostname>"));
}

#[test]
fn namespace_and_prefix_declared() {
    let system = sample_config();
    let xml = renderer()
        .render_running_config(&system, &["/ex:system/ex:hostname"], DefaultReport::Trim)
        .unwrap();
    assert!(xml.contains("xmlns:ex=\"urn:example\""));
    assert!(xml.contains("<ex:hostname>"));
}

#[test]
fn unsupported_list_fails_closed() {
    let system = sample_config();
    let err = renderer()
        .render_running_config(&system, &["/ex:system/ex:interfaces"], DefaultReport::Trim)
        .unwrap_err();
    assert_eq!(
        err,
        NetconfProjectionError::UnsupportedShape {
            path: "/ex:system/ex:interfaces",
            kind: opc_mgmt_schema::NodeKind::List,
        }
    );
}

#[test]
fn deterministic_output_order() {
    let system = sample_config();
    let xml1 = renderer()
        .render_running_config(
            &system,
            &["/ex:system/ex:hostname", "/ex:system/ex:dns"],
            DefaultReport::Trim,
        )
        .unwrap();
    let xml2 = renderer()
        .render_running_config(
            &system,
            &["/ex:system/ex:dns", "/ex:system/ex:hostname"],
            DefaultReport::Trim,
        )
        .unwrap();
    assert_eq!(xml1, xml2);
}

#[test]
fn trim_omits_schema_default_values() {
    let mut system = System::default();
    system.hostname = LeafPresence::Explicit("router1".to_string());
    system.enabled = LeafPresence::Defaulted(true);
    let mut dns = Dns::default();
    dns.server = LeafPresence::Defaulted("8.8.8.8".to_string());
    system.dns = Some(dns);

    let xml = renderer()
        .render_running_config(
            &system,
            &[
                "/ex:system/ex:hostname",
                "/ex:system/ex:enabled",
                "/ex:system/ex:dns/ex:server",
            ],
            DefaultReport::Trim,
        )
        .unwrap();
    assert!(xml.contains("<ex:hostname>router1</ex:hostname>"));
    assert!(!xml.contains("<ex:enabled>"));
    assert!(!xml.contains("<ex:server>"));
}

#[test]
fn report_all_includes_defaulted_values() {
    let mut system = System::default();
    system.hostname = LeafPresence::Explicit("router1".to_string());
    system.enabled = LeafPresence::Defaulted(true);
    let mut dns = Dns::default();
    dns.server = LeafPresence::Defaulted("8.8.8.8".to_string());
    system.dns = Some(dns);

    let xml = renderer()
        .render_running_config(
            &system,
            &[
                "/ex:system/ex:hostname",
                "/ex:system/ex:enabled",
                "/ex:system/ex:dns/ex:server",
            ],
            DefaultReport::ReportAll,
        )
        .unwrap();
    assert!(xml.contains("<ex:hostname>router1</ex:hostname>"));
    assert!(xml.contains("<ex:enabled>true</ex:enabled>"));
    assert!(xml.contains("<ex:server>8.8.8.8</ex:server>"));
}

#[test]
fn state_leaf_rendered_when_selected() {
    let mut system = System::default();
    system.uptime = Some(123);
    let xml = renderer()
        .render_running_config(&system, &["/ex:system/ex:uptime"], DefaultReport::Trim)
        .unwrap();
    assert!(xml.contains("<ex:uptime>123</ex:uptime>"));
}
