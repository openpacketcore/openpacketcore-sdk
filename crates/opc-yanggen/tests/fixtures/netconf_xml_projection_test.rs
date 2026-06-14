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

fn interface_eth0() -> Interfaces {
    let mut iface = Interfaces::default();
    iface.name = LeafPresence::Explicit("eth0".to_string());
    iface.mtu = LeafPresence::Explicit(1500);
    iface.admin = LeafPresence::Explicit(true);
    iface.auth_key = SecretLeaf::new(LeafPresence::Explicit("auth-secret".to_string()));
    iface
}

fn interface_eth1() -> Interfaces {
    let mut iface = Interfaces::default();
    iface.name = LeafPresence::Explicit("eth1".to_string());
    iface.mtu = LeafPresence::Explicit(9000);
    iface.admin = LeafPresence::Explicit(false);
    iface.auth_key = SecretLeaf::new(LeafPresence::Explicit("auth-secret-2".to_string()));
    iface
}

#[test]
fn selected_leaf_only() {
    let system = sample_config();
    let xml = renderer()
        .render_running_config(
            &system,
            &["/ex:system", "/ex:system/ex:hostname"],
            DefaultReport::Trim,
        )
        .unwrap();
    assert!(xml.contains("<ex:hostname>router1</ex:hostname>"));
    assert!(!xml.contains("<ex:enabled>"));
    assert!(!xml.contains("<ex:secret>"));
    assert!(!xml.contains("hunter2"));
}

#[test]
fn selected_container_and_descendants() {
    let system = sample_config();
    let xml = renderer()
        .render_running_config(
            &system,
            &["/ex:system/ex:dns", "/ex:system/ex:dns/ex:server"],
            DefaultReport::Trim,
        )
        .unwrap();
    assert!(xml.contains("<ex:dns>"));
    assert!(xml.contains("<ex:server>1.1.1.1</ex:server>"));
    assert!(xml.contains("</ex:dns>"));
}

#[test]
fn selected_container_without_leaf_descendant_does_not_emit_siblings() {
    let system = sample_config();
    let xml = renderer()
        .render_running_config(&system, &["/ex:system/ex:dns"], DefaultReport::Trim)
        .unwrap();
    assert!(xml.contains("<ex:dns>"));
    assert!(!xml.contains("<ex:server>"));
    assert!(!xml.contains("<ex:hostname>"));
    assert!(!xml.contains("<ex:secret>"));
}

#[test]
fn denied_leaf_omitted() {
    let system = sample_config();
    let xml = renderer()
        .render_running_config(
            &system,
            &[
                "/ex:system",
                "/ex:system/ex:hostname",
                "/ex:system/ex:enabled",
            ],
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
fn unsupported_custom_leaf_list_fails_closed() {
    let system = sample_config();
    let err = renderer()
        .render_running_config(&system, &["/ex:system/ex:custom-tags"], DefaultReport::Trim)
        .unwrap_err();
    assert_eq!(
        err,
        NetconfProjectionError::UnsupportedShape {
            path: "/ex:system/ex:custom-tags",
            kind: opc_mgmt_schema::NodeKind::LeafList,
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

#[test]
fn keyed_list_renders_selected_children() {
    let mut system = sample_config();
    system
        .interfaces
        .insert("eth0".to_string(), interface_eth0());
    system
        .interfaces
        .insert("eth1".to_string(), interface_eth1());

    let xml = renderer()
        .render_running_config(
            &system,
            &[
                "/ex:system/ex:interfaces",
                "/ex:system/ex:interfaces/ex:name",
                "/ex:system/ex:interfaces/ex:mtu",
            ],
            DefaultReport::Trim,
        )
        .unwrap();

    assert!(xml.contains("<ex:interfaces><ex:name>eth0</ex:name><ex:mtu>1500</ex:mtu></ex:interfaces>"));
    assert!(xml.contains("<ex:interfaces><ex:name>eth1</ex:name><ex:mtu>9000</ex:mtu></ex:interfaces>"));
    assert!(!xml.contains("<ex:admin>"));
    assert!(!xml.contains("auth-secret"));
}

#[test]
fn selected_list_container_without_child_does_not_emit_unauthorized_children() {
    let mut system = sample_config();
    system
        .interfaces
        .insert("eth0".to_string(), interface_eth0());

    let xml = renderer()
        .render_running_config(&system, &["/ex:system/ex:interfaces"], DefaultReport::Trim)
        .unwrap();

    assert!(!xml.contains("<ex:name>"));
    assert!(!xml.contains("<ex:mtu>"));
    assert!(!xml.contains("<ex:admin>"));
    assert!(!xml.contains("auth-secret"));
}

#[test]
fn selected_child_under_list_does_not_leak_siblings() {
    let mut system = sample_config();
    system
        .interfaces
        .insert("eth0".to_string(), interface_eth0());

    let xml = renderer()
        .render_running_config(
            &system,
            &[
                "/ex:system/ex:interfaces/ex:name",
                "/ex:system/ex:interfaces/ex:mtu",
            ],
            DefaultReport::Trim,
        )
        .unwrap();

    assert!(xml.contains("<ex:name>eth0</ex:name>"));
    assert!(xml.contains("<ex:mtu>1500</ex:mtu>"));
    assert!(!xml.contains("<ex:admin>"));
    assert!(!xml.contains("auth-secret"));
}

#[test]
fn selected_list_child_without_key_fails_closed() {
    let mut system = sample_config();
    system
        .interfaces
        .insert("eth0".to_string(), interface_eth0());

    let err = renderer()
        .render_running_config(
            &system,
            &["/ex:system/ex:interfaces/ex:mtu"],
            DefaultReport::Trim,
        )
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
fn list_with_secret_leaf_redaction() {
    let mut system = sample_config();
    system
        .interfaces
        .insert("eth0".to_string(), interface_eth0());

    let xml = renderer()
        .render_running_config(
            &system,
            &[
                "/ex:system/ex:interfaces",
                "/ex:system/ex:interfaces/ex:name",
                "/ex:system/ex:interfaces/ex:auth-key",
            ],
            DefaultReport::Trim,
        )
        .unwrap();

    assert!(xml.contains("<ex:name>eth0</ex:name>"));
    assert!(xml.contains("<ex:auth-key>"));
    assert!(!xml.contains("auth-secret"));
}

#[test]
fn multi_key_list_renders_keys_in_schema_order() {
    let mut system = sample_config();
    let mut route = Routes::default();
    route.dest = LeafPresence::Explicit("0.0.0.0/0".to_string());
    route.next_hop = LeafPresence::Explicit("10.0.0.1".to_string());
    route.metric = LeafPresence::Explicit(1);
    system.routes.insert(
        RoutesKey {
            dest: "0.0.0.0/0".to_string(),
            next_hop: "10.0.0.1".to_string(),
        },
        route,
    );

    let xml = renderer()
        .render_running_config(
            &system,
            &[
                "/ex:system/ex:routes",
                "/ex:system/ex:routes/ex:dest",
                "/ex:system/ex:routes/ex:next-hop",
                "/ex:system/ex:routes/ex:metric",
            ],
            DefaultReport::Trim,
        )
        .unwrap();

    let dest_pos = xml.find("<ex:dest>").unwrap();
    let next_hop_pos = xml.find("<ex:next-hop>").unwrap();
    let metric_pos = xml.find("<ex:metric>").unwrap();
    assert!(dest_pos < next_hop_pos);
    assert!(next_hop_pos < metric_pos);
    assert!(xml.contains("<ex:dest>0.0.0.0/0</ex:dest>"));
    assert!(xml.contains("<ex:next-hop>10.0.0.1</ex:next-hop>"));
    assert!(xml.contains("<ex:metric>1</ex:metric>"));
}

#[test]
fn nested_list_renders_selected_children() {
    let mut system = sample_config();
    let mut iface = interface_eth0();
    let mut sub = SubInterfaces::default();
    sub.id = LeafPresence::Explicit(100);
    sub.description = LeafPresence::Explicit("vlan100".to_string());
    iface.sub_interfaces.insert(100, sub);
    system.interfaces.insert("eth0".to_string(), iface);

    let xml = renderer()
        .render_running_config(
            &system,
            &[
                "/ex:system/ex:interfaces",
                "/ex:system/ex:interfaces/ex:name",
                "/ex:system/ex:interfaces/ex:sub-interfaces",
                "/ex:system/ex:interfaces/ex:sub-interfaces/ex:id",
                "/ex:system/ex:interfaces/ex:sub-interfaces/ex:description",
            ],
            DefaultReport::Trim,
        )
        .unwrap();

    assert!(xml.contains("<ex:name>eth0</ex:name>"));
    assert!(xml.contains("<ex:sub-interfaces><ex:id>100</ex:id><ex:description>vlan100</ex:description></ex:sub-interfaces>"));
}

#[test]
fn leaf_list_scalar_render() {
    let mut system = sample_config();
    system.servers = vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()];

    let xml = renderer()
        .render_running_config(&system, &["/ex:system/ex:servers"], DefaultReport::Trim)
        .unwrap();

    assert!(xml.contains("<ex:servers>8.8.8.8</ex:servers>"));
    assert!(xml.contains("<ex:servers>1.1.1.1</ex:servers>"));
}

#[test]
fn leaf_list_xml_escaped() {
    let mut system = sample_config();
    system.servers = vec!["a & b".to_string()];

    let xml = renderer()
        .render_running_config(&system, &["/ex:system/ex:servers"], DefaultReport::Trim)
        .unwrap();

    assert!(xml.contains("<ex:servers>a &amp; b</ex:servers>"));
}

#[test]
fn leaf_list_numeric_render() {
    let mut system = sample_config();
    system.tags = vec![10, 20];

    let xml = renderer()
        .render_running_config(&system, &["/ex:system/ex:tags"], DefaultReport::Trim)
        .unwrap();

    assert!(xml.contains("<ex:tags>10</ex:tags>"));
    assert!(xml.contains("<ex:tags>20</ex:tags>"));
}

#[test]
fn sensitive_leaf_list_is_redacted() {
    let mut system = sample_config();
    system.secret_codes = SecretLeaf::new(vec!["alpha".to_string(), "beta".to_string()]);

    let xml = renderer()
        .render_running_config(&system, &["/ex:system/ex:secret-codes"], DefaultReport::Trim)
        .unwrap();

    assert!(xml.contains("<ex:secret-codes>"));
    assert!(!xml.contains("alpha"));
    assert!(!xml.contains("beta"));
}

#[test]
fn explicit_emits_explicit_values_omits_defaulted_and_absent() {
    let mut system = System::default();
    system.hostname = LeafPresence::Explicit("router1".to_string());
    system.enabled = LeafPresence::Explicit(true);
    system.dns = Some(Dns::default());

    let xml = renderer()
        .render_running_config(
            &system,
            &[
                "/ex:system/ex:hostname",
                "/ex:system/ex:enabled",
                "/ex:system/ex:dns/ex:server",
            ],
            DefaultReport::Explicit,
        )
        .unwrap();

    assert!(xml.contains("<ex:hostname>router1</ex:hostname>"));
    assert!(xml.contains("<ex:enabled>true</ex:enabled>"));
    // Defaulted value is omitted in explicit mode.
    assert!(!xml.contains("<ex:server>"));
}

#[test]
fn explicit_omits_defaulted_leaf_even_when_same_value_explicit_exists() {
    let mut system = System::default();
    system.enabled = LeafPresence::Defaulted(true);

    let xml = renderer()
        .render_running_config(&system, &["/ex:system/ex:enabled"], DefaultReport::Explicit)
        .unwrap();

    assert!(!xml.contains("<ex:enabled>"));
}

#[test]
fn report_all_tagged_emits_defaulted_values_with_tag() {
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
            DefaultReport::ReportAllTagged,
        )
        .unwrap();

    assert!(xml.contains("xmlns:wd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\""));
    assert!(xml.contains("<ex:hostname>router1</ex:hostname>"));
    assert!(xml.contains("<ex:enabled wd:default=\"true\">true</ex:enabled>"));
    assert!(xml.contains("<ex:server wd:default=\"true\">8.8.8.8</ex:server>"));
}

#[test]
fn report_all_tagged_explicit_same_value_leaf_emits_without_tag() {
    let mut system = System::default();
    system.enabled = LeafPresence::Explicit(true);

    let xml = renderer()
        .render_running_config(&system, &["/ex:system/ex:enabled"], DefaultReport::ReportAllTagged)
        .unwrap();

    assert!(xml.contains("<ex:enabled>true</ex:enabled>"));
    assert!(!xml.contains("wd:default"));
}

#[test]
fn report_all_tagged_nested_container_and_keyed_list() {
    let mut system = System::default();
    let mut dns = Dns::default();
    dns.server = LeafPresence::Defaulted("8.8.8.8".to_string());
    system.dns = Some(dns);

    let mut iface = Interfaces::default();
    iface.name = LeafPresence::Explicit("eth0".to_string());
    iface.mtu = LeafPresence::Defaulted(1500);
    system.interfaces.insert("eth0".to_string(), iface);

    let xml = renderer()
        .render_running_config(
            &system,
            &[
                "/ex:system/ex:dns",
                "/ex:system/ex:dns/ex:server",
                "/ex:system/ex:interfaces",
                "/ex:system/ex:interfaces/ex:name",
                "/ex:system/ex:interfaces/ex:mtu",
            ],
            DefaultReport::ReportAllTagged,
        )
        .unwrap();

    assert!(xml.contains("xmlns:wd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\""));
    assert!(xml.contains("<ex:server wd:default=\"true\">8.8.8.8</ex:server>"));
    assert!(xml.contains("<ex:interfaces><ex:name>eth0</ex:name><ex:mtu wd:default=\"true\">1500</ex:mtu></ex:interfaces>"));
}

#[test]
fn report_all_tagged_secret_defaulted_leaf_redacts_value_and_still_tags() {
    let mut system = System::default();
    system.secret = SecretLeaf::new(LeafPresence::Defaulted("hunter2".to_string()));

    let xml = renderer()
        .render_running_config(&system, &["/ex:system/ex:secret"], DefaultReport::ReportAllTagged)
        .unwrap();

    assert!(xml.contains("<ex:secret wd:default=\"true\">"));
    assert!(!xml.contains("hunter2"));
}

#[test]
fn explicit_secret_defaulted_leaf_omits() {
    let mut system = System::default();
    system.secret = SecretLeaf::new(LeafPresence::Defaulted("hunter2".to_string()));

    let xml = renderer()
        .render_running_config(&system, &["/ex:system/ex:secret"], DefaultReport::Explicit)
        .unwrap();

    assert!(!xml.contains("<ex:secret>"));
    assert!(!xml.contains("hunter2"));
}

#[test]
fn report_all_tagged_no_duplicate_wd_declaration() {
    let mut system = System::default();
    system.enabled = LeafPresence::Defaulted(true);
    system.hostname = LeafPresence::Explicit("router1".to_string());

    let xml = renderer()
        .render_running_config(
            &system,
            &[
                "/ex:system/ex:hostname",
                "/ex:system/ex:enabled",
            ],
            DefaultReport::ReportAllTagged,
        )
        .unwrap();

    let mut found = 0usize;
    for m in xml.match_indices("xmlns:wd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\"") {
        let _ = m;
        found += 1;
    }
    assert_eq!(found, 1, "wd namespace should be declared exactly once");
}
