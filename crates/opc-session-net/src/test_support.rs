use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};

pub(crate) static SESSION_CONNECTION_METRICS_TEST_LOCK: std::sync::LazyLock<
    tokio::sync::Mutex<()>,
> = std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

pub(crate) struct RotatableServerMaterial {
    ca: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
    spiffe_id: String,
    source: tokio::sync::watch::Sender<Option<opc_identity::IdentityState>>,
    config: opc_tls::AuthenticatedServerConfig,
}

pub(crate) struct RotatableClientMaterial {
    ca: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
    spiffe_id: String,
    source: tokio::sync::watch::Sender<Option<opc_identity::IdentityState>>,
    config: opc_tls::AuthenticatedClientConfig,
}

impl RotatableClientMaterial {
    pub(crate) fn new(spiffe_id: impl Into<String>) -> Self {
        let spiffe_id = spiffe_id.into();
        let ca_key = rcgen::KeyPair::generate().expect("generate test CA key");
        let mut parameters = rcgen::CertificateParams::default();
        parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        parameters
            .distinguished_name
            .push(rcgen::DnType::CommonName, "session client material test CA");
        let ca = rcgen::CertifiedIssuer::self_signed(parameters, ca_key).expect("sign test CA");
        let initial = identity_state(&ca, &spiffe_id);
        let (source, receiver) = tokio::sync::watch::channel(Some(initial));
        let config = opc_tls::TlsConfigBuilder::new(receiver)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .expect("build authenticated client config");
        Self {
            ca,
            spiffe_id,
            source,
            config,
        }
    }

    pub(crate) fn config(&self) -> opc_tls::AuthenticatedClientConfig {
        self.config.clone()
    }

    pub(crate) fn rotate(&self) {
        let previous = self.config.material_status().epoch();
        self.source
            .send_replace(Some(identity_state(&self.ca, &self.spiffe_id)));
        let current = self.config.material_status();
        assert_ne!(
            current.epoch(),
            previous,
            "test client material epoch must advance"
        );
        assert_eq!(
            current.availability(),
            opc_tls::TlsMaterialAvailability::Ready
        );
    }
}

impl RotatableServerMaterial {
    pub(crate) fn new(spiffe_id: impl Into<String>) -> Self {
        let spiffe_id = spiffe_id.into();
        let ca_key = rcgen::KeyPair::generate().expect("generate test CA key");
        let mut parameters = rcgen::CertificateParams::default();
        parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        parameters
            .distinguished_name
            .push(rcgen::DnType::CommonName, "session bootstrap race test CA");
        let ca = rcgen::CertifiedIssuer::self_signed(parameters, ca_key).expect("sign test CA");
        let initial = identity_state(&ca, &spiffe_id);
        let (source, receiver) = tokio::sync::watch::channel(Some(initial));
        let config = opc_tls::TlsConfigBuilder::new(receiver)
            .allow_any_trusted_peer()
            .build_authenticated_server_config()
            .expect("build authenticated server config");
        Self {
            ca,
            spiffe_id,
            source,
            config,
        }
    }

    pub(crate) fn config(&self) -> opc_tls::AuthenticatedServerConfig {
        self.config.clone()
    }

    pub(crate) fn rotate(&self) {
        let previous = self.config.material_status().epoch();
        self.source
            .send_replace(Some(identity_state(&self.ca, &self.spiffe_id)));
        let current = self.config.material_status();
        assert_ne!(
            current.epoch(),
            previous,
            "test material epoch must advance"
        );
        assert_eq!(
            current.availability(),
            opc_tls::TlsMaterialAvailability::Ready
        );
    }
}

fn identity_state(
    ca: &rcgen::CertifiedIssuer<'_, impl rcgen::SigningKey>,
    spiffe_id: &str,
) -> opc_identity::IdentityState {
    let mut parameters = rcgen::CertificateParams::default();
    parameters
        .distinguished_name
        .push(rcgen::DnType::CommonName, "session bootstrap race leaf");
    parameters.subject_alt_names.push(rcgen::SanType::URI(
        rcgen::string::Ia5String::try_from(spiffe_id).expect("test SPIFFE URI"),
    ));
    let now = time::OffsetDateTime::now_utc();
    parameters.not_before = now - time::Duration::days(1);
    parameters.not_after = now + time::Duration::days(1);
    let key = rcgen::KeyPair::generate().expect("generate test leaf key");
    let certificate = parameters.signed_by(&key, ca).expect("sign test leaf");
    let certificates =
        parse_certs_pem(&(certificate.pem() + &ca.pem())).expect("parse test certificate chain");
    let private_key = parse_key_pem(&key.serialize_pem()).expect("parse test private key");
    let mut bundles = opc_identity::TrustBundleSet::new();
    bundles.insert(TrustBundle {
        trust_domain: opc_identity::TrustDomain::new("test-domain").expect("test trust domain"),
        certificates: parse_certs_pem(&ca.pem()).expect("parse test CA"),
    });
    build_identity_state(certificates, private_key, bundles).expect("build test identity state")
}
