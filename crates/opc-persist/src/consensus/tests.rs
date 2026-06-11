use super::identity::parse_spiffe_id;

#[test]
fn parse_spiffe_id_accepts_canonical_profile() {
    let parsed = parse_spiffe_id(
        "spiffe://prod.example.org/tenant/carrier/ns/core/sa/opc-consensus/nf/amf/instance/17",
    )
    .unwrap();

    assert_eq!(parsed.trust_domain, "prod.example.org");
    assert!(parsed.legacy_path_prefix.is_empty());
    assert_eq!(parsed.tenant_id, "carrier");
    assert_eq!(parsed.namespace, "core");
    assert_eq!(parsed.service_account, "opc-consensus");
    assert_eq!(parsed.nf_kind, "amf");
    assert_eq!(parsed.instance_id, 17);
}

#[test]
fn parse_spiffe_id_keeps_legacy_test_profile_compatible() {
    let parsed = parse_spiffe_id(
        "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/1",
    )
    .unwrap();

    assert_eq!(parsed.trust_domain, "test");
    assert_eq!(parsed.legacy_path_prefix, vec!["trust-domain"]);
    assert_eq!(parsed.instance_id, 1);
}

#[test]
fn spiffe_workload_profile_ignores_instance_only() {
    let node_a = parse_spiffe_id(
        "spiffe://prod.example.org/tenant/carrier/ns/core/sa/opc-consensus/nf/amf/instance/1",
    )
    .unwrap();
    let node_b = parse_spiffe_id(
        "spiffe://prod.example.org/tenant/carrier/ns/core/sa/opc-consensus/nf/amf/instance/2",
    )
    .unwrap();
    let other_workload = parse_spiffe_id(
        "spiffe://prod.example.org/tenant/carrier/ns/core/sa/other/nf/amf/instance/2",
    )
    .unwrap();

    assert!(node_a.same_workload_profile(&node_b));
    assert!(!node_a.same_workload_profile(&other_workload));
}
