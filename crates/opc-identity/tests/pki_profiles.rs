use opc_identity::{
    build_identity_state, extract_spiffe_id_from_cert_der, extract_spiffe_id_from_pki_cert_der,
    validate_local_pki_identity, IdentityReloadError, LocalPkiUsage, SpiffeSanError, TrustBundle,
    TrustBundleSet, TrustDomain,
};
use rcgen::{CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, KeyPair, SanType};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

const ID: &str = "spiffe://example.test/tenant/tenant-a/ns/core/sa/session/nf/smf/instance/smf-0";

struct Fixture {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    bundles: TrustBundleSet,
}

fn fixture(ekus: Vec<ExtendedKeyUsagePurpose>, uris: &[&str]) -> Fixture {
    fixture_with(ekus, uris, |_| {})
}

fn fixture_with(
    ekus: Vec<ExtendedKeyUsagePurpose>,
    uris: &[&str],
    adjust: impl FnOnce(&mut CertificateParams),
) -> Fixture {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let mut params = CertificateParams::default();
    params.extended_key_usages = ekus;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.subject_alt_names = uris
        .iter()
        .map(|uri| SanType::URI((*uri).try_into().unwrap()))
        .collect();
    adjust(&mut params);
    let key = KeyPair::generate().unwrap();
    let leaf = params.signed_by(&key, &ca).unwrap();
    let mut bundles = TrustBundleSet::new();
    bundles.insert(TrustBundle {
        trust_domain: TrustDomain::new("example.test").unwrap(),
        certificates: vec![ca.der().clone()],
    });
    Fixture {
        chain: vec![leaf.der().clone()],
        key: PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        bundles,
    }
}

impl Fixture {
    fn validate(&self, usage: LocalPkiUsage) -> Result<opc_types::SpiffeId, IdentityReloadError> {
        validate_local_pki_identity(&self.chain, &self.key, &self.bundles, usage)
    }
}

#[test]
fn svid_rejects_present_eku_without_both_roles() {
    for eku in [
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::Any,
    ] {
        let f = fixture(vec![eku], &[ID]);
        assert!(matches!(
            build_identity_state(f.chain, f.key, f.bundles),
            Err(IdentityReloadError::InvalidCertificateChain)
        ));
    }
}

#[test]
fn general_pki_validates_exact_role_and_svid_keeps_dual_role_rules() {
    use ExtendedKeyUsagePurpose::{ClientAuth, ServerAuth};
    use LocalPkiUsage::{Client, ClientAndServer, Server};
    for (ekus, client, server) in [
        (vec![ClientAuth], true, false),
        (vec![ServerAuth], false, true),
        (vec![ClientAuth, ServerAuth], true, true),
        (vec![], true, true),
    ] {
        let f = fixture(ekus, &[ID]);
        for (usage, accepted) in [
            (Client, client),
            (Server, server),
            (ClientAndServer, client && server),
        ] {
            if accepted {
                assert_eq!(f.validate(usage).unwrap().as_str(), ID);
            } else {
                assert_eq!(
                    f.validate(usage),
                    Err(IdentityReloadError::InvalidCertificateChain)
                );
            }
        }
        assert_eq!(
            build_identity_state(f.chain, f.key, f.bundles).is_ok(),
            client && server
        );
    }
}

#[test]
fn general_pki_accepts_other_uri_schemes_without_weakening_svid_or_ambiguity_checks() {
    for uris in [
        [ID, "https://example.test/api"],
        ["https://example.test/api", ID],
    ] {
        let f = fixture(vec![ExtendedKeyUsagePurpose::ClientAuth], &uris);
        assert_eq!(f.validate(LocalPkiUsage::Client).unwrap().as_str(), ID);
        assert_eq!(
            extract_spiffe_id_from_pki_cert_der(&f.chain[0])
                .unwrap()
                .as_str(),
            ID
        );
        assert_eq!(
            extract_spiffe_id_from_cert_der(&f.chain[0]),
            Err(SpiffeSanError::MultipleUriSans)
        );
        assert!(build_identity_state(f.chain, f.key, f.bundles).is_err());
    }
    for other in [
        ID,
        "spiffe://example.test/other",
        "SPIFFE://example.test/other",
    ] {
        let f = fixture(vec![], &[ID, other]);
        assert_eq!(
            extract_spiffe_id_from_pki_cert_der(&f.chain[0]),
            Err(SpiffeSanError::MultipleSpiffeIds)
        );
        assert_eq!(
            f.validate(LocalPkiUsage::Client),
            Err(IdentityReloadError::MalformedSpiffeId)
        );
    }
    for (uris, expected) in [
        (
            vec!["https://example.test/api"],
            SpiffeSanError::MissingSpiffeId,
        ),
        (
            vec!["spiffe:not-an-authority"],
            SpiffeSanError::MalformedSpiffeId,
        ),
        (
            vec!["SPIFFE://example.test/other"],
            SpiffeSanError::MalformedSpiffeId,
        ),
    ] {
        let f = fixture(vec![], &uris);
        assert_eq!(
            extract_spiffe_id_from_pki_cert_der(&f.chain[0]),
            Err(expected)
        );
    }
}

#[test]
fn general_pki_does_not_bypass_trust_key_time_or_certificate_shape() {
    let mut f = fixture(vec![], &[ID]);
    let other = fixture(vec![], &[ID]);
    assert_eq!(
        validate_local_pki_identity(&f.chain, &other.key, &f.bundles, LocalPkiUsage::Client),
        Err(IdentityReloadError::PrivateKeyMismatch)
    );
    assert_eq!(
        validate_local_pki_identity(&f.chain, &f.key, &other.bundles, LocalPkiUsage::Client),
        Err(IdentityReloadError::InvalidCertificateChain)
    );
    assert_eq!(
        validate_local_pki_identity(
            &f.chain,
            &f.key,
            &TrustBundleSet::new(),
            LocalPkiUsage::Client
        ),
        Err(IdentityReloadError::UnknownTrustDomain)
    );
    let domain = TrustDomain::new("example.test").unwrap();
    f.bundles.bundles.get_mut(&domain).unwrap().trust_domain =
        TrustDomain::new("foreign.test").unwrap();
    assert_eq!(
        f.validate(LocalPkiUsage::Client),
        Err(IdentityReloadError::InvalidTrustDomain)
    );
    for expired in [true, false] {
        let f = fixture_with(vec![], &[ID], |params| {
            let now = time::OffsetDateTime::now_utc();
            if expired {
                params.not_before = now - time::Duration::days(2);
                params.not_after = now - time::Duration::days(1);
            } else {
                params.not_before = now + time::Duration::days(1);
                params.not_after = now + time::Duration::days(2);
            }
        });
        assert_eq!(
            f.validate(LocalPkiUsage::Client),
            Err(IdentityReloadError::InvalidCertificateChain)
        );
    }
    let f = fixture_with(vec![], &[ID], |params| {
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    });
    assert_eq!(
        f.validate(LocalPkiUsage::Client),
        Err(IdentityReloadError::InvalidCertificateChain)
    );
    let f = fixture(vec![], &[ID]);
    let mut malformed = f.chain[0].to_vec();
    malformed.push(0);
    assert_eq!(
        extract_spiffe_id_from_pki_cert_der(&malformed),
        Err(SpiffeSanError::MalformedCertificate)
    );
    let malformed_uri = "https://example.test/api";
    let f = fixture(vec![], &[ID, malformed_uri]);
    let mut malformed = f.chain[0].to_vec();
    let offset = malformed
        .windows(malformed_uri.len())
        .position(|bytes| bytes == malformed_uri.as_bytes())
        .unwrap();
    malformed[offset] = 0xff;
    assert_eq!(
        extract_spiffe_id_from_pki_cert_der(&malformed),
        Err(SpiffeSanError::MalformedCertificate)
    );
}
