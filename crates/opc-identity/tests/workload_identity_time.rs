use opc_identity::{
    IdentityReloadError, Namespace, ServiceAccount, TrustBundle, TrustBundleSet, TrustDomain,
    WorkloadIdentity,
};
use opc_types::{InstanceId, NfKind, SpiffeId, TenantId, Timestamp};
use rcgen::{CertificateParams, KeyPair, SanType};

const SPIFFE_ID: &str =
    "spiffe://example.test/tenant/tenant-a/ns/core/sa/session/nf/smf/instance/smf-0";

fn certificate(not_before: Timestamp, not_after: Timestamp, uris: &[&str]) -> Vec<u8> {
    let mut params = CertificateParams::default();
    params.not_before = *not_before.as_offset_datetime();
    params.not_after = *not_after.as_offset_datetime();
    params.subject_alt_names = uris
        .iter()
        .map(|uri| SanType::URI((*uri).try_into().unwrap()))
        .collect();
    let key = KeyPair::generate().unwrap();
    params.self_signed(&key).unwrap().der().to_vec()
}

fn active_bundles() -> TrustBundleSet {
    let mut bundles = TrustBundleSet::new();
    bundles.insert(TrustBundle {
        trust_domain: TrustDomain::new("example.test").unwrap(),
        certificates: Vec::new(),
    });
    bundles
}

fn fixed_validity() -> (Timestamp, Timestamp) {
    (
        Timestamp::from_offset_datetime(rcgen::date_time_ymd(2024, 1, 1)),
        Timestamp::from_offset_datetime(rcgen::date_time_ymd(2025, 1, 1)),
    )
}

#[test]
fn workload_identity_is_valid_at_an_explicit_time() {
    let (not_before, not_after) = fixed_validity();
    let cert = certificate(not_before, not_after, &[SPIFFE_ID]);
    let verification_time = not_before.add_seconds(3_600).unwrap();

    let identity =
        WorkloadIdentity::from_cert_der_at(&cert, &active_bundles(), verification_time).unwrap();

    assert_eq!(
        identity,
        WorkloadIdentity {
            trust_domain: TrustDomain::new("example.test").unwrap(),
            tenant: TenantId::new("tenant-a").unwrap(),
            namespace: Namespace::new("core").unwrap(),
            service_account: ServiceAccount::new("session").unwrap(),
            nf_kind: NfKind::new("smf").unwrap(),
            instance: InstanceId::new("smf-0").unwrap(),
            spiffe_id: SpiffeId::new(SPIFFE_ID).unwrap(),
            expires_at: not_after,
        }
    );
}

#[test]
fn workload_identity_expires_exactly_at_not_after() {
    let (not_before, not_after) = fixed_validity();
    let cert = certificate(not_before, not_after, &[SPIFFE_ID]);

    assert_eq!(
        WorkloadIdentity::from_cert_der_at(&cert, &active_bundles(), not_after),
        Err(IdentityReloadError::ExpiredSvid)
    );
}

#[test]
fn workload_identity_is_expired_after_not_after() {
    let (not_before, not_after) = fixed_validity();
    let cert = certificate(not_before, not_after, &[SPIFFE_ID]);

    assert_eq!(
        WorkloadIdentity::from_cert_der_at(
            &cert,
            &active_bundles(),
            not_after.add_seconds(1).unwrap(),
        ),
        Err(IdentityReloadError::ExpiredSvid)
    );
}

#[test]
fn workload_identity_is_not_yet_valid_before_not_before() {
    let (not_before, not_after) = fixed_validity();
    let cert = certificate(not_before, not_after, &[SPIFFE_ID]);

    assert_eq!(
        WorkloadIdentity::from_cert_der_at(
            &cert,
            &active_bundles(),
            not_before.add_seconds(-1).unwrap(),
        ),
        Err(IdentityReloadError::NotYetValidSvid)
    );
}

#[test]
fn workload_identity_is_valid_exactly_at_not_before() {
    let (not_before, not_after) = fixed_validity();
    let cert = certificate(not_before, not_after, &[SPIFFE_ID]);

    let identity =
        WorkloadIdentity::from_cert_der_at(&cert, &active_bundles(), not_before).unwrap();

    assert_eq!(identity.spiffe_id.as_str(), SPIFFE_ID);
    assert_eq!(identity.expires_at, not_after);
}

#[test]
fn workload_identity_wall_clock_wrapper_matches_explicit_current_time() {
    let now = Timestamp::now_utc();
    // Keep both calls well away from a validity boundary so crossing a clock
    // tick between them cannot change the expected result.
    let cert = certificate(
        now.add_seconds(-86_400).unwrap(),
        now.add_seconds(86_400).unwrap(),
        &[SPIFFE_ID],
    );
    let bundles = active_bundles();
    let explicit = WorkloadIdentity::from_cert_der_at(&cert, &bundles, now);
    assert!(explicit.is_ok());

    assert_eq!(WorkloadIdentity::from_cert_der(&cert, &bundles), explicit);
    assert_eq!(
        WorkloadIdentity::from_cert_der(&cert, &TrustBundleSet::new()),
        WorkloadIdentity::from_cert_der_at(&cert, &TrustBundleSet::new(), now),
    );
}

#[test]
fn workload_identity_explicit_time_preserves_validation_order() {
    let (not_before, not_after) = fixed_validity();
    let cert = certificate(not_before, not_after, &[]);
    let mut trailing = cert.clone();
    trailing.push(0);
    // A dot is allowed in a canonical SPIFFE path segment, but rejected by
    // Namespace. Keep the URI valid so these cases reach the later checks.
    let malformed_path_uri = SPIFFE_ID.replace("/ns/core/", "/ns/core.invalid/");
    let unknown_domain_uri = malformed_path_uri.replace("example.test", "unknown.test");
    assert!(SpiffeId::new(&malformed_path_uri).is_ok());
    assert!(SpiffeId::new(&unknown_domain_uri).is_ok());
    let unknown_domain = certificate(not_before, not_after, &[&unknown_domain_uri]);
    let malformed_path = certificate(not_before, not_after, &[&malformed_path_uri]);
    let bundles = active_bundles();

    for (der, verification_time, expected) in [
        (
            &b"not a certificate"[..],
            not_after,
            IdentityReloadError::MalformedSpiffeId,
        ),
        (
            trailing.as_slice(),
            not_after,
            IdentityReloadError::MalformedSpiffeId,
        ),
        (cert.as_slice(), not_after, IdentityReloadError::ExpiredSvid),
        (
            cert.as_slice(),
            not_before.add_seconds(-1).unwrap(),
            IdentityReloadError::NotYetValidSvid,
        ),
        (
            cert.as_slice(),
            not_before,
            IdentityReloadError::MalformedSpiffeId,
        ),
        (
            unknown_domain.as_slice(),
            not_before,
            IdentityReloadError::UnknownTrustDomain,
        ),
        (
            malformed_path.as_slice(),
            not_before,
            IdentityReloadError::MalformedPath,
        ),
    ] {
        assert_eq!(
            WorkloadIdentity::from_cert_der_at(der, &bundles, verification_time),
            Err(expected),
        );
    }
}
