use super::ConsensusConfigStore;
use crate::consensus::pem::load_certs_from_pem;
use crate::consensus::types::{NodeIdentity, ParsedSpiffeId};
use crate::error::PersistError;
use std::collections::HashSet;
use std::sync::Arc;
use x509_parser::prelude::*;

pub fn parse_spiffe_id(spiffe_id: &str) -> Result<ParsedSpiffeId, PersistError> {
    let rest = spiffe_id.strip_prefix("spiffe://").ok_or_else(|| {
        PersistError::inconsistent_state("unauthenticated: invalid SPIFFE ID scheme")
    })?;
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.len() < 11 || parts.iter().any(|part| part.is_empty()) {
        return Err(PersistError::inconsistent_state(
            "unauthenticated: invalid SPIFFE ID format",
        ));
    }

    let trust_domain = parts[0].to_string();
    let path = &parts[1..];
    let (legacy_path_prefix, workload_path) = if path.first() == Some(&"trust-domain") {
        (vec!["trust-domain".to_string()], &path[1..])
    } else {
        (Vec::new(), path)
    };

    if workload_path.len() != 10 {
        return Err(PersistError::inconsistent_state(
            "unauthenticated: invalid SPIFFE workload path",
        ));
    }
    if workload_path[0] != "tenant"
        || workload_path[2] != "ns"
        || workload_path[4] != "sa"
        || workload_path[6] != "nf"
        || workload_path[8] != "instance"
    {
        return Err(PersistError::inconsistent_state(
            "unauthenticated: invalid SPIFFE workload labels",
        ));
    }

    let instance_id = workload_path[9].parse::<usize>().map_err(|_| {
        PersistError::inconsistent_state("unauthenticated: invalid node ID suffix in SPIFFE ID")
    })?;

    Ok(ParsedSpiffeId {
        trust_domain,
        legacy_path_prefix,
        tenant_id: workload_path[1].to_string(),
        namespace: workload_path[3].to_string(),
        service_account: workload_path[5].to_string(),
        nf_kind: workload_path[7].to_string(),
        instance_id,
    })
}

pub fn extract_spiffe_id_from_cert_der(cert_der: &[u8]) -> Result<String, PersistError> {
    let (_, x509) = X509Certificate::from_der(cert_der).map_err(|_| {
        PersistError::inconsistent_state("unauthenticated: invalid certificate encoding")
    })?;

    for ext in x509.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                if let GeneralName::URI(uri) = name {
                    if uri.starts_with("spiffe://") {
                        return Ok((*uri).to_string());
                    }
                }
            }
        }
    }

    Err(PersistError::inconsistent_state(
        "unauthenticated: no SPIFFE ID found in certificate SubjectAltName",
    ))
}

pub fn parse_local_spiffe_profile(identity: &NodeIdentity) -> Result<ParsedSpiffeId, PersistError> {
    let certs = load_certs_from_pem(&identity.cert_chain_pem).map_err(|e| {
        PersistError::inconsistent_state(format!("failed to load local cert chain: {e}"))
    })?;
    let leaf = certs.first().ok_or_else(|| {
        PersistError::inconsistent_state("local identity certificate chain is empty")
    })?;
    let spiffe_id = extract_spiffe_id_from_cert_der(leaf.as_ref())?;
    parse_spiffe_id(&spiffe_id)
}

pub fn create_identity_state_receiver(
    identity: &NodeIdentity,
) -> tokio::sync::watch::Receiver<Option<opc_identity::IdentityState>> {
    let ca_certs = match opc_identity::parse_certs_pem(&identity.ca_cert_pem) {
        Ok(c) => c,
        Err(_) => {
            let (_tx, rx) = tokio::sync::watch::channel(None);
            return rx;
        }
    };
    let cert_chain = match opc_identity::parse_certs_pem(&identity.cert_chain_pem) {
        Ok(c) => c,
        Err(_) => {
            let (_tx, rx) = tokio::sync::watch::channel(None);
            return rx;
        }
    };
    let private_key = match opc_identity::parse_key_pem(&identity.private_key_pem) {
        Ok(k) => k,
        Err(_) => {
            let (_tx, rx) = tokio::sync::watch::channel(None);
            return rx;
        }
    };

    let leaf_der = match cert_chain.first() {
        Some(d) => d,
        None => {
            let (_tx, rx) = tokio::sync::watch::channel(None);
            return rx;
        }
    };
    let (_, x509) = match x509_parser::prelude::X509Certificate::from_der(leaf_der.as_ref()) {
        Ok(res) => res,
        Err(_) => {
            let (_tx, rx) = tokio::sync::watch::channel(None);
            return rx;
        }
    };
    let mut spiffe_id_str = None;
    for ext in x509.extensions() {
        if let x509_parser::prelude::ParsedExtension::SubjectAlternativeName(san) =
            ext.parsed_extension()
        {
            for name in &san.general_names {
                if let x509_parser::prelude::GeneralName::URI(uri) = name {
                    if uri.starts_with("spiffe://") {
                        spiffe_id_str = Some((*uri).to_string());
                        break;
                    }
                }
            }
        }
    }
    let spiffe_id_str = match spiffe_id_str {
        Some(s) => s,
        None => {
            let (_tx, rx) = tokio::sync::watch::channel(None);
            return rx;
        }
    };
    let spiffe_id = match opc_types::SpiffeId::new(&spiffe_id_str) {
        Ok(s) => s,
        Err(_) => {
            let (_tx, rx) = tokio::sync::watch::channel(None);
            return rx;
        }
    };
    let trust_domain = match opc_identity::TrustDomain::new(spiffe_id.trust_domain()) {
        Ok(td) => td,
        Err(_) => {
            let (_tx, rx) = tokio::sync::watch::channel(None);
            return rx;
        }
    };

    let mut trust_bundles = opc_identity::TrustBundleSet::new();
    trust_bundles.insert(opc_identity::TrustBundle {
        trust_domain: trust_domain.clone(),
        certificates: ca_certs,
    });

    let workload_id =
        match opc_identity::WorkloadIdentity::from_cert_der(leaf_der.as_ref(), &trust_bundles) {
            Ok(id) => id,
            Err(_) => {
                let (_tx, rx) = tokio::sync::watch::channel(None);
                return rx;
            }
        };

    let state = opc_identity::IdentityState {
        identity: workload_id,
        svid: opc_identity::SvidDocument {
            spiffe_id,
            cert_chain,
            private_key,
            expires_at: opc_types::Timestamp::now_utc(),
        },
        trust_bundles,
    };

    let (_tx, rx) = tokio::sync::watch::channel(Some(state));
    rx
}

pub fn build_client_tls_connector(
    identity: &NodeIdentity,
    expected_node_id: usize,
) -> Result<tokio_rustls::TlsConnector, PersistError> {
    let rx = create_identity_state_receiver(identity);
    let policy = consensus_peer_policy(identity, Some(expected_node_id))?;

    let builder = opc_tls::TlsConfigBuilder::new(rx).with_policy(policy);
    let client_config = builder.build_client_config().map_err(|e| {
        PersistError::inconsistent_state(format!("Failed to build client config: {e}"))
    })?;

    Ok(tokio_rustls::TlsConnector::from(Arc::new(client_config)))
}

pub fn build_server_tls_acceptor(
    identity: &NodeIdentity,
) -> Result<tokio_rustls::TlsAcceptor, PersistError> {
    let rx = create_identity_state_receiver(identity);
    let policy = consensus_peer_policy(identity, None)?;
    let builder = opc_tls::TlsConfigBuilder::new(rx).with_policy(policy);
    let server_config = builder.build_server_config().map_err(|e| {
        PersistError::inconsistent_state(format!("Failed to build server config: {e}"))
    })?;

    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(server_config)))
}

pub(super) fn consensus_peer_policy(
    identity: &NodeIdentity,
    expected_node_id: Option<usize>,
) -> Result<opc_tls::PeerPolicy, PersistError> {
    let profile = parse_local_spiffe_profile(identity)?;
    let allowed_trust_domains = Some(HashSet::from([opc_identity::TrustDomain::new(
        profile.trust_domain,
    )
    .map_err(|_| PersistError::inconsistent_state("local identity has invalid trust domain"))?]));
    let allowed_tenants = Some(HashSet::from([opc_types::TenantId::new(profile.tenant_id)
        .map_err(|_| {
            PersistError::inconsistent_state("local identity has invalid tenant")
        })?]));
    let allowed_nf_kinds = Some(HashSet::from([opc_types::NfKind::new(profile.nf_kind)
        .map_err(|_| {
            PersistError::inconsistent_state("local identity has invalid NF kind")
        })?]));
    let allowed_instances = if let Some(node_id) = expected_node_id {
        Some(HashSet::from([opc_types::InstanceId::new(
            node_id.to_string(),
        )
        .map_err(|_| {
            PersistError::inconsistent_state("expected node id is not a valid instance id")
        })?]))
    } else {
        None
    };

    Ok(opc_tls::PeerPolicy {
        allowed_trust_domains,
        allowed_tenants,
        allowed_nf_kinds,
        allowed_instances,
    })
}

impl ConsensusConfigStore {
    pub async fn set_identity(&self, identity: NodeIdentity) -> Result<(), PersistError> {
        let acceptor = build_server_tls_acceptor(&identity)?;
        {
            let mut guard = self.identity.write().await;
            *guard = Some(identity.clone());
        }
        {
            let mut guard = self.tls_acceptor.write().await;
            *guard = Some(acceptor);
        }
        let peers = self.peers.read().await;
        for peer in peers.values() {
            let _ = peer.set_identity(identity.clone()).await;
        }
        Ok(())
    }

    pub async fn build_tls_connector(&self) -> Result<tokio_rustls::TlsConnector, PersistError> {
        let identity_guard = self.identity.read().await;
        let identity = identity_guard
            .as_ref()
            .ok_or_else(|| PersistError::inconsistent_state("local identity not initialized"))?;
        build_client_tls_connector(identity, self.node_id)
    }

    pub async fn build_tls_acceptor(&self) -> Result<tokio_rustls::TlsAcceptor, PersistError> {
        let guard = self.tls_acceptor.read().await;
        if let Some(ref acceptor) = *guard {
            Ok(acceptor.clone())
        } else {
            let identity_guard = self.identity.read().await;
            let identity = identity_guard.as_ref().ok_or_else(|| {
                PersistError::inconsistent_state("local identity not initialized")
            })?;
            build_server_tls_acceptor(identity)
        }
    }
}
