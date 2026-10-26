//! Explicit general-PKI validation, separate from reloadable X.509-SVID state.

use crate::{IdentityReloadError, SpiffeSanError, TrustBundleSet, TrustDomain};
use opc_types::SpiffeId;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// Intended TLS role of a local general-PKI certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalPkiUsage {
    /// Validate the chain for TLS client authentication.
    Client,
    /// Validate the chain for TLS server authentication.
    Server,
    /// Validate the chain independently for both TLS roles.
    ClientAndServer,
}

/// Extract exactly one canonical SPIFFE ID, allowing other URI SAN schemes.
///
/// Duplicate SPIFFE URIs, including identical values, remain ambiguous. A
/// noncanonical SPIFFE-scheme URI is rejected, not treated as another scheme.
/// This parses identity only; it does not authenticate the certificate or
/// validate service names in other SANs. SVID callers must use the strict
/// [`crate::extract_spiffe_id_from_cert_der`] instead.
pub fn extract_spiffe_id_from_pki_cert_der(cert_der: &[u8]) -> Result<SpiffeId, SpiffeSanError> {
    crate::extract_spiffe_id(cert_der, false)
}

/// Validate local general-PKI material for an explicit TLS role at the current time.
///
/// The single SPIFFE ID selects its configured trust-domain bundle. Certificate
/// path, validity, role-specific EKU and private-key correspondence are checked;
/// other URI SAN schemes are allowed. Returns the authenticated local identity.
///
/// This does not create an SVID or [`crate::IdentityState`]. The SVID watchers and
/// `opc-tls` material controller retain their strict profile. General-PKI callers
/// own material reload, peer authorization, revocation and TLS configuration.
/// This helper alone does not validate the complete TS 33.310 NF certificate profile.
pub fn validate_local_pki_identity(
    cert_chain: &[CertificateDer<'static>],
    private_key: &PrivateKeyDer<'_>,
    trust_bundles: &TrustBundleSet,
    usage: LocalPkiUsage,
) -> Result<SpiffeId, IdentityReloadError> {
    let leaf = cert_chain
        .first()
        .ok_or(IdentityReloadError::MalformedSpiffeId)?;
    let identity = extract_spiffe_id_from_pki_cert_der(leaf)
        .map_err(|_| IdentityReloadError::MalformedSpiffeId)?;
    let domain = TrustDomain::new(identity.trust_domain())
        .map_err(|_| IdentityReloadError::InvalidTrustDomain)?;
    crate::validate_leaf_chains_to_bundle(&domain, cert_chain, trust_bundles, usage)?;
    crate::validate_private_key_matches_leaf(cert_chain, private_key)?;
    Ok(identity)
}
