use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};

#[derive(Clone, Copy)]
pub(crate) struct ConnectionOutcomeMetricSnapshot {
    pub(crate) idle_retirements: u64,
    pub(crate) timeout_failures: u64,
    pub(crate) successes: u64,
    pub(crate) drain_started: u64,
    pub(crate) drain_completed: u64,
}

#[derive(Debug, Default)]
pub(crate) struct ConnectionOutcomeTestAccounting {
    idle_retirements: AtomicU64,
    timeout_failures: AtomicU64,
    successes: AtomicU64,
    drain_started: AtomicU64,
    drain_completed: AtomicU64,
}

impl ConnectionOutcomeTestAccounting {
    pub(crate) fn snapshot(&self) -> ConnectionOutcomeMetricSnapshot {
        ConnectionOutcomeMetricSnapshot {
            idle_retirements: self.idle_retirements.load(Ordering::Relaxed),
            timeout_failures: self.timeout_failures.load(Ordering::Relaxed),
            successes: self.successes.load(Ordering::Relaxed),
            drain_started: self.drain_started.load(Ordering::Relaxed),
            drain_completed: self.drain_completed.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn record_retirement(&self, reason: crate::lifecycle::RetirementReason) {
        if reason == crate::lifecycle::RetirementReason::IdleTimeout {
            self.idle_retirements.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn record_drain_started(&self) {
        self.drain_started.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_drain_completed(&self) {
        self.drain_completed.fetch_add(1, Ordering::Relaxed);
    }
}

// Tokio task-local state deliberately excludes unrelated spawned test writers. Lifecycle
// instances capture this `Arc` when constructed so their eventual drop stays attributed.
tokio::task_local! {
    pub(crate) static CONNECTION_OUTCOME_TEST_ACCOUNTING: Arc<ConnectionOutcomeTestAccounting>;
}

pub(crate) fn current_connection_outcome_test_accounting(
) -> Option<Arc<ConnectionOutcomeTestAccounting>> {
    CONNECTION_OUTCOME_TEST_ACCOUNTING.try_with(Arc::clone).ok()
}

pub(crate) fn record_connection_success() {
    let _ = CONNECTION_OUTCOME_TEST_ACCOUNTING.try_with(|accounting| {
        accounting.successes.fetch_add(1, Ordering::Relaxed);
    });
}

pub(crate) fn record_connection_timeout_failure() {
    let _ = CONNECTION_OUTCOME_TEST_ACCOUNTING.try_with(|accounting| {
        accounting.timeout_failures.fetch_add(1, Ordering::Relaxed);
    });
}

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

    pub(crate) fn trusted_server_config(
        &self,
        spiffe_id: impl Into<String>,
    ) -> opc_tls::AuthenticatedServerConfig {
        let state = identity_state(&self.ca, &spiffe_id.into());
        let (_source, receiver) = tokio::sync::watch::channel(Some(state));
        opc_tls::TlsConfigBuilder::new(receiver)
            .allow_any_trusted_peer()
            .build_authenticated_server_config()
            .expect("build server config trusted by test client material")
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

    pub(crate) fn publish_rejected_update(&self) {
        let previous = self.config.material_status().epoch();
        self.source.send_replace(None);
        let current = self.config.material_status();
        assert_eq!(
            current.epoch(),
            previous,
            "a rejected test publication must retain the admitted epoch"
        );
        assert_eq!(
            current.availability(),
            opc_tls::TlsMaterialAvailability::RetainingLastGood
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

    pub(crate) fn trusted_client_config(
        &self,
        spiffe_id: impl Into<String>,
    ) -> opc_tls::AuthenticatedClientConfig {
        let state = identity_state(&self.ca, &spiffe_id.into());
        let (_source, receiver) = tokio::sync::watch::channel(Some(state));
        opc_tls::TlsConfigBuilder::new(receiver)
            .allow_any_trusted_peer()
            .build_authenticated_client_config()
            .expect("build client config trusted by test server material")
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
