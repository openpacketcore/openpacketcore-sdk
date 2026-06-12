use opc_types::{
    redact, ConfigVersion, InstanceId, IntoRedacted, NfKind, PlmnId, Redacted, RegionId,
    SchemaDigest, Snssai, SpiffeId, TenantId, Timestamp, TxId,
};
use std::str::FromStr;

#[test]
fn slug_identifiers_validate_and_round_trip() {
    let tenant = TenantId::new("tenant-a").expect("valid tenant");
    let instance = InstanceId::new("amf-01").expect("valid instance");
    let region = RegionId::new("us-central").expect("valid region");
    let nf_kind = NfKind::new("amf").expect("valid nf kind");

    assert_eq!(tenant.as_str(), "tenant-a");
    assert_eq!(instance.as_str(), "amf-01");
    assert_eq!(region.as_str(), "us-central");
    assert_eq!(nf_kind.as_str(), "amf");
    assert!(nf_kind.is_known());

    assert!(NfKind::new("nwdaf").expect("valid nwdaf").is_known());
    assert!(NfKind::new("bsf").expect("valid bsf").is_known());
    assert!(NfKind::new("chf").expect("valid chf").is_known());
    assert!(!NfKind::new("unknown-nf").expect("valid slug").is_known());

    assert!(TenantId::new("TenantA").is_err());
    assert!(InstanceId::new("-bad").is_err());
}

#[test]
fn spiffe_id_exposes_trust_domain_and_path() {
    let spiffe = SpiffeId::new(
        "spiffe://core.example/tenant/tenant-a/ns/core-control/sa/opc-amf/nf/amf/instance/amf-01",
    )
    .expect("valid spiffe id");

    assert_eq!(spiffe.trust_domain(), "core.example");
    assert_eq!(
        spiffe.path(),
        "/tenant/tenant-a/ns/core-control/sa/opc-amf/nf/amf/instance/amf-01"
    );
    assert!(SpiffeId::new("spiffe://core.example").is_err());
    assert!(
        SpiffeId::new("spiffe://core.example/ns/default/sa/api/nf/amf/instance/amf-01").is_err()
    );
    assert!(SpiffeId::new("spiffe://core.example/tenant/tenant-a/ns/default/sa/api").is_err());
    assert!(SpiffeId::new("spiffe://core.example/foo/bar").is_err());
    assert!(SpiffeId::new(
        "spiffe://core.example/tenant/TeamA/ns/default/sa/api/nf/amf/instance/amf-01"
    )
    .is_err());
}

#[test]
fn plmn_and_snssai_support_canonical_parsing() {
    let plmn = PlmnId::from_str("001-01").expect("valid plmn");
    assert_eq!(plmn.mcc(), "001");
    assert_eq!(plmn.mnc(), "01");
    assert_eq!(plmn.to_string(), "001-01");

    let compact = PlmnId::from_str("310260").expect("compact plmn");
    assert_eq!(compact.to_string(), "310-260");

    let snssai = Snssai::from_str("sst=1,sd=ABC123").expect("valid snssai");
    assert_eq!(snssai.sst(), 1);
    assert_eq!(snssai.sd(), Some("abc123"));
    assert_eq!(snssai.to_string(), "sst=1,sd=abc123");

    let compact_slice = Snssai::from_str("2-010203").expect("compact snssai");
    assert_eq!(compact_slice.to_string(), "sst=2,sd=010203");
}

#[test]
fn schema_digest_and_timestamp_serde_round_trip() {
    let digest =
        SchemaDigest::from_str("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .expect("valid digest");
    assert_eq!(
        digest.to_string(),
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    );

    let timestamp =
        Timestamp::from_str("2026-05-27T10:20:30-06:00").expect("valid timestamp input");
    assert_eq!(timestamp.to_string(), "2026-05-27T16:20:30Z");

    let digest_json = serde_json::to_string(&digest).expect("serialize digest");
    let round_digest: SchemaDigest =
        serde_json::from_str(&digest_json).expect("deserialize digest");
    assert_eq!(round_digest, digest);

    let timestamp_json = serde_json::to_string(&timestamp).expect("serialize timestamp");
    let round_timestamp: Timestamp =
        serde_json::from_str(&timestamp_json).expect("deserialize timestamp");
    assert_eq!(round_timestamp, timestamp);
}

#[test]
fn config_versions_and_tx_ids_are_usable() {
    let version = ConfigVersion::INITIAL.next().unwrap().next().unwrap();
    assert_eq!(version.get(), 2);

    let tx = TxId::new();
    let tx_round = TxId::from_str(&tx.to_string()).expect("parse tx id");
    assert_eq!(tx_round, tx);

    assert!(ConfigVersion::new(u64::MAX).next().is_none());
}

#[test]
fn public_types_support_serde_round_trips() {
    let tenant = TenantId::new("tenant-a").expect("tenant");
    let instance = InstanceId::new("amf-01").expect("instance");
    let region = RegionId::new("us-central").expect("region");
    let spiffe = SpiffeId::new(
        "spiffe://core.example/tenant/tenant-a/ns/core-control/sa/opc-amf/nf/amf/instance/amf-01",
    )
    .expect("spiffe");
    let nf_kind = NfKind::new("amf").expect("nf kind");
    let plmn = PlmnId::from_str("310260").expect("plmn");
    let snssai = Snssai::from_str("sst=1,sd=010203").expect("snssai");
    let config_version = ConfigVersion::new(42);
    let tx_id = TxId::from_str("123e4567-e89b-12d3-a456-426614174000").expect("tx id");

    let tenant_json = serde_json::to_string(&tenant).expect("serialize tenant");
    let instance_json = serde_json::to_string(&instance).expect("serialize instance");
    let region_json = serde_json::to_string(&region).expect("serialize region");
    let spiffe_json = serde_json::to_string(&spiffe).expect("serialize spiffe");
    let nf_kind_json = serde_json::to_string(&nf_kind).expect("serialize nf kind");
    let plmn_json = serde_json::to_string(&plmn).expect("serialize plmn");
    let snssai_json = serde_json::to_string(&snssai).expect("serialize snssai");
    let config_version_json =
        serde_json::to_string(&config_version).expect("serialize config version");
    let tx_id_json = serde_json::to_string(&tx_id).expect("serialize tx id");

    let tenant_round: TenantId = serde_json::from_str(&tenant_json).expect("deserialize tenant");
    let instance_round: InstanceId =
        serde_json::from_str(&instance_json).expect("deserialize instance");
    let region_round: RegionId = serde_json::from_str(&region_json).expect("deserialize region");
    let spiffe_round: SpiffeId = serde_json::from_str(&spiffe_json).expect("deserialize spiffe");
    let nf_kind_round: NfKind = serde_json::from_str(&nf_kind_json).expect("deserialize nf kind");
    let plmn_round: PlmnId = serde_json::from_str(&plmn_json).expect("deserialize plmn");
    let snssai_round: Snssai = serde_json::from_str(&snssai_json).expect("deserialize snssai");
    let config_version_round: ConfigVersion =
        serde_json::from_str(&config_version_json).expect("deserialize config version");
    let tx_id_round: TxId = serde_json::from_str(&tx_id_json).expect("deserialize tx id");

    assert_eq!(tenant_round, tenant);
    assert_eq!(instance_round, instance);
    assert_eq!(region_round, region);
    assert_eq!(spiffe_round, spiffe);
    assert_eq!(nf_kind_round, nf_kind);
    assert_eq!(plmn_round, plmn);
    assert_eq!(snssai_round, snssai);
    assert_eq!(config_version_round, config_version);
    assert_eq!(tx_id_round, tx_id);
}

#[test]
fn redacted_helpers_never_leak_secret_values_in_debug() {
    let secret = "super-secret-token";
    let owned: Redacted<String> = secret.to_owned().redacted();
    let borrowed = redact(&secret);

    let owned_debug = format!("{owned:?}");
    let owned_display = owned.to_string();
    let borrowed_debug = format!("{borrowed:?}");
    let borrowed_display = borrowed.to_string();

    assert!(!owned_debug.contains(secret));
    assert!(!borrowed_debug.contains(secret));
    assert!(!owned_display.contains(secret));
    assert!(!borrowed_display.contains(secret));
    assert_eq!(owned.expose(), secret);
}

#[test]
fn negative_validation_rejects_malformed_inputs() {
    // PlmnId — non-digit, wrong length, multi-byte UTF-8
    assert!(PlmnId::from_str("abc").is_err());
    assert!(PlmnId::from_str("1234").is_err());
    assert!(PlmnId::from_str("1234567").is_err());
    assert!(PlmnId::from_str("1中2").is_err());

    // Snssai — SST overflow (u8), empty SD, wrong SD length
    assert!(Snssai::from_str("sst=256").is_err());
    assert!(Snssai::from_str("sst=1,sd=").is_err());
    assert!(Snssai::from_str("sst=1,sd=ABC12").is_err());

    // SchemaDigest — wrong length, non-hex characters
    assert!(SchemaDigest::from_str("0123456789abcdef").is_err());
    assert!(SchemaDigest::from_str(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdzz"
    )
    .is_err());

    // SpiffeId trust domain validation — malformed domains
    let canonical_path = "/tenant/tenant-a/ns/core-control/sa/opc-amf/nf/amf/instance/amf-01";
    assert!(SpiffeId::new(format!("spiffe://core..example{canonical_path}")).is_err());
    assert!(SpiffeId::new(format!("spiffe://.core.example{canonical_path}")).is_err());
    assert!(SpiffeId::new(format!("spiffe://core.example.{canonical_path}")).is_err());
    assert!(SpiffeId::new(format!("spiffe://-core.example{canonical_path}")).is_err());
    assert!(SpiffeId::new(format!("spiffe://core.example-{canonical_path}")).is_err());
    assert!(SpiffeId::new(format!("spiffe://core.EXample{canonical_path}")).is_err());
    assert!(SpiffeId::new(format!("spiffe://core._example{canonical_path}")).is_err());
    assert!(SpiffeId::new(format!("spiffe://{canonical_path}")).is_err());
    assert!(SpiffeId::new(format!("spiffe:// /{canonical_path}")).is_err());
    assert!(SpiffeId::new(format!("spiffe://-/{canonical_path}")).is_err());
}

#[test]
fn spiffe_id_rejects_non_canonical_paths() {
    // Too few segments
    assert!(SpiffeId::new("spiffe://core.example/tenant/tenant-a").is_err());

    // Too many segments
    assert!(SpiffeId::new(
        "spiffe://core.example/tenant/tenant-a/ns/core-control/sa/opc-amf/nf/amf/instance/amf-01/extra"
    )
    .is_err());

    // Wrong fixed label ("tennant" instead of "tenant")
    assert!(SpiffeId::new(
        "spiffe://core.example/tennant/tenant-a/ns/core-control/sa/opc-amf/nf/amf/instance/amf-01"
    )
    .is_err());

    // Missing a fixed label (no "instance" keyword, 9 segments)
    assert!(SpiffeId::new(
        "spiffe://core.example/tenant/tenant-a/ns/core-control/sa/opc-amf/nf/amf/amf-01"
    )
    .is_err());
}

#[test]
fn spiffe_id_propagates_typed_segment_errors() {
    // tenant_id with underscore passes validate_spiffe_path but fails TenantId::new
    let err = SpiffeId::new(
        "spiffe://core.example/tenant/tenant_a/ns/core-control/sa/opc-amf/nf/amf/instance/amf-01",
    )
    .expect_err("tenant with underscore should fail");
    let msg = err.to_string();
    assert!(
        msg.contains("tenant id"),
        "expected specific 'tenant id' error, got: {msg}"
    );

    // nf_kind with underscore passes validate_spiffe_path but fails NfKind::new
    let err = SpiffeId::new(
        "spiffe://core.example/tenant/tenant-a/ns/core-control/sa/opc-amf/nf/amf_01/instance/amf-01",
    )
    .expect_err("nf-kind with underscore should fail");
    let msg = err.to_string();
    assert!(
        msg.contains("nf kind"),
        "expected specific 'nf kind' error, got: {msg}"
    );

    // instance_id starting with '-' passes validate_spiffe_path but fails InstanceId::new
    let err = SpiffeId::new(
        "spiffe://core.example/tenant/tenant-a/ns/core-control/sa/opc-amf/nf/amf/instance/-amf-01",
    )
    .expect_err("instance starting with hyphen should fail");
    let msg = err.to_string();
    assert!(
        msg.contains("instance id"),
        "expected specific 'instance id' error, got: {msg}"
    );
}

#[test]
fn spiffe_id_layout_error_precedes_type_error() {
    // A path that is both non-canonical (extra segment) AND type-invalid
    // (instance starts with '-') must report the layout error, not the
    // instance-id validation error.
    let err = SpiffeId::new(
        "spiffe://core.example/tenant/tenant-a/ns/core-control/sa/opc-amf/nf/amf/instance/-amf-01/extra",
    )
    .expect_err("extra segment should fail");
    let msg = err.to_string();
    assert!(
        msg.contains("path must follow canonical OpenPacketCore layout"),
        "expected layout error to take precedence, got: {msg}"
    );
}

#[test]
fn spiffe_id_rejects_malformed_trust_domains() {
    // Empty label via double-dot: split produces "" between the dots.
    let err = SpiffeId::new(
        "spiffe://core..example/tenant/tenant-a/ns/core-control/sa/opc-amf/nf/amf/instance/amf-01",
    )
    .expect_err("empty label (double-dot) should be rejected");
    assert!(
        err.to_string()
            .contains("trust domain labels must not be empty"),
        "expected 'empty label' error, got: {err}"
    );

    // Leading dot: split(".core.example") → ["" ,"core", "example"].
    let err = SpiffeId::new(
        "spiffe://.core.example/tenant/tenant-a/ns/core-control/sa/opc-amf/nf/amf/instance/amf-01",
    )
    .expect_err("leading dot should be rejected");
    assert!(
        err.to_string()
            .contains("trust domain labels must not be empty"),
        "expected 'empty label' error, got: {err}"
    );

    // Label starting with hyphen.
    let err = SpiffeId::new(
        "spiffe://-core.example/tenant/tenant-a/ns/core-control/sa/opc-amf/nf/amf/instance/amf-01",
    )
    .expect_err("label starting with hyphen should be rejected");
    assert!(
        err.to_string().contains("must not start or end with '-'"),
        "expected hyphen-boundary error, got: {err}"
    );

    // Label ending with hyphen.
    let err = SpiffeId::new(
        "spiffe://core-.example/tenant/tenant-a/ns/core-control/sa/opc-amf/nf/amf/instance/amf-01",
    )
    .expect_err("label ending with hyphen should be rejected");
    assert!(
        err.to_string().contains("must not start or end with '-'"),
        "expected hyphen-boundary error, got: {err}"
    );

    // Uppercase character in trust domain (labels must be lowercase).
    let err = SpiffeId::new(
        "spiffe://Core.example/tenant/tenant-a/ns/core-control/sa/opc-amf/nf/amf/instance/amf-01",
    )
    .expect_err("uppercase in trust domain should be rejected");
    assert!(
        err.to_string()
            .contains("trust domain labels must contain only lowercase"),
        "expected lowercase-only error, got: {err}"
    );
}

#[test]
fn bytes_compiles() {
    let mut buf = bytes::BytesMut::with_capacity(16);
    buf.extend_from_slice(b"opc");
    let frozen = buf.freeze();
    assert_eq!(&frozen[..], b"opc");
}
