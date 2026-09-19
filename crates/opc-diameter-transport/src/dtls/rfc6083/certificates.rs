//! Additional certificate constraints on the cryptographically selected path.

use super::*;
use x509_parser::der_parser::ber::Tag;
use x509_parser::extensions::{DistributionPointName, ParsedExtension};
use x509_parser::x509::{X509Name, X509Version};

/// An optional, immutable certificate constraint in addition to SPIFFE and trust.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CertificateProfile {
    /// The bounded ECDSA P-256/P-384 TLS-entity subset documented in
    /// `docs/rfc6083-certificate-profile.md`, based on TS 33.310 V18.8.0.
    ///
    /// Requires current complete direct CRLs and validates both the local and
    /// peer paths. Both identities' trust-domain bundles must be supplied.
    /// This is not full NDS/AF conformance: RSA, remote CRL retrieval and OCSP
    /// are not supplied by this profile. Names/organization fields add no
    /// application authority. Credential selection remains caller-owned.
    NdsAfEcdsa,
}

impl CertificateProfile {
    pub(in crate::dtls) fn verify(
        self,
        path: &webpki::VerifiedPath<'_>,
        roots: &[CertificateDer<'_>],
        usage: PeerUsage,
    ) -> Result<Timestamp, DiameterTlsError> {
        let mut certificates = vec![path.end_entity().der()];
        certificates.extend(path.intermediate_certificates().map(|cert| cert.der()));
        // TrustAnchor deliberately omits certificate extensions. Recover the
        // exact configured certificate; do not invent its CA/profile fields.
        // Distinct certificates with the same anchor are ambiguous here.
        let mut matches = roots.iter().filter(|root| {
            webpki::anchor_from_trusted_cert(root).is_ok_and(|v| v == *path.anchor())
        });
        let root = matches.next().ok_or(DiameterTlsError::Authentication)?;
        if matches.any(|other| other != root) {
            return Err(DiameterTlsError::Authentication);
        }
        certificates.push(root.clone());
        match self {
            Self::NdsAfEcdsa => verify_path(&certificates, usage),
        }
    }
}

fn verify_path(
    certificates: &[CertificateDer<'_>],
    usage: PeerUsage,
) -> Result<Timestamp, DiameterTlsError> {
    let fail = || DiameterTlsError::Authentication;
    validate_dtls_certificate_chain_bounds(certificates).map_err(|_| fail())?;
    let mut previous: Option<(X509Certificate<'_>, u16)> = None;
    let mut expiry = None;
    for (position, der) in certificates.iter().enumerate() {
        let (rest, cert) = X509Certificate::from_der(der).map_err(|_| fail())?;
        if !rest.is_empty() || cert.version() != X509Version::V3 {
            return Err(fail());
        }
        cert.extensions_map().map_err(|_| fail())?;
        if cert.signature_algorithm != cert.tbs_certificate.signature
            || cert.signature_algorithm.parameters.is_some()
            || !matches!(
                cert.signature_algorithm.algorithm.to_id_string().as_str(),
                "1.2.840.10045.4.3.2" | "1.2.840.10045.4.3.3"
            )
        {
            return Err(fail());
        }
        let strength = ec_strength(&cert)?;
        validate_name(cert.subject())?;
        validate_name(cert.issuer())?;
        if !cert.validity().is_valid() {
            return Err(fail());
        }
        let current_expiry = certificate_expiry(der)?;
        expiry = Some(expiry.map_or(current_expiry, |v: Timestamp| v.min(current_expiry)));
        let ca = position > 0;
        for ext in cert.extensions() {
            // Only these role-specific extensions are mandated critical.
            let mandated = ext.oid.to_id_string() == "2.5.29.15"
                || (ca && ext.oid.to_id_string() == "2.5.29.19");
            if ext.critical != mandated
                || matches!(ext.parsed_extension(), ParsedExtension::ParseError { .. })
            {
                return Err(fail());
            }
        }
        let ku = cert.key_usage().map_err(|_| fail())?.ok_or_else(fail)?;
        if !ku.critical {
            return Err(fail());
        }
        if ca {
            let bc = cert
                .basic_constraints()
                .map_err(|_| fail())?
                .ok_or_else(fail)?;
            if !ku.value.key_cert_sign() || !ku.value.crl_sign() || !bc.critical || !bc.value.ca {
                return Err(fail());
            }
            if position == 1 {
                if bc.value.path_len_constraint != Some(0) {
                    return Err(fail());
                }
            } else if bc.value.path_len_constraint.is_some_and(|limit| {
                usize::try_from(limit).map_or(true, |limit| limit < position - 1)
            }) {
                return Err(fail());
            }
        } else {
            if !ku.value.digital_signature() {
                return Err(fail());
            }
            let mut points = cert.extensions().iter().filter_map(|ext| {
                if let ParsedExtension::CRLDistributionPoints(points) = ext.parsed_extension() {
                    Some(points)
                } else {
                    None
                }
            });
            let points = points.next().ok_or_else(fail)?;
            if points.is_empty()
                || points.iter().any(|point| {
                    // The existing publisher admits direct complete CRLs only.
                    point.reasons.is_some()
                        || point.crl_issuer.is_some()
                        || match &point.distribution_point {
                            Some(DistributionPointName::FullName(names)) => names.is_empty(),
                            Some(DistributionPointName::NameRelativeToCRLIssuer(name)) => {
                                name.iter().next().is_none()
                            }
                            None => true,
                        }
                })
            {
                return Err(fail());
            }
        }
        if let Some(eku) = cert.extended_key_usage().map_err(|_| fail())? {
            let allowed = match usage {
                PeerUsage::Client => eku.value.client_auth,
                PeerUsage::Server => eku.value.server_auth,
            };
            if eku.critical || !allowed {
                return Err(fail());
            }
        }
        if let Some((child, child_strength)) = &previous {
            if cert.subject() != child.issuer() || strength < *child_strength {
                return Err(fail());
            }
        }
        previous = Some((cert, strength));
    }
    expiry.ok_or_else(fail)
}

fn ec_strength(cert: &X509Certificate<'_>) -> Result<u16, DiameterTlsError> {
    let fail = || DiameterTlsError::Authentication;
    let key = cert.public_key();
    if key.algorithm.algorithm.to_id_string() != "1.2.840.10045.2.1"
        || key.subject_public_key.unused_bits != 0
    {
        return Err(fail());
    }
    let curve = key
        .algorithm
        .parameters
        .as_ref()
        .ok_or_else(fail)?
        .as_oid()
        .map_err(|_| fail())?;
    match curve.to_id_string().as_str() {
        "1.2.840.10045.3.1.7" => Ok(128),
        "1.3.132.0.34" => Ok(192),
        _ => Err(fail()),
    }
}

fn validate_name(name: &X509Name<'_>) -> Result<(), DiameterTlsError> {
    let fail = || DiameterTlsError::Authentication;
    let mut attributes = Vec::new();
    for rdn in name.iter_rdn() {
        let mut values = rdn.iter();
        let value = values.next().ok_or_else(fail)?;
        if values.next().is_some() || value.as_str().map_err(|_| fail())?.is_empty() {
            return Err(fail());
        }
        attributes.push(value);
    }
    let types: Vec<_> = attributes
        .iter()
        .map(|v| v.attr_type().to_id_string())
        .collect();
    let types: Vec<_> = types.iter().map(String::as_str).collect();
    // DER order, most general first. The LDAP spelling of the second form
    // presents this sequence in reverse. No value is used as peer authority.
    match types.as_slice() {
        ["2.5.4.10", "2.5.4.3"] | ["2.5.4.6", "2.5.4.10", "2.5.4.3"] => {
            for value in &attributes {
                if value.attr_type().to_id_string() == "2.5.4.6" {
                    let text = value.as_str().map_err(|_| fail())?;
                    if value.attr_value().tag() != Tag::PrintableString
                        || text.len() != 2
                        || !text.bytes().all(|v| v.is_ascii_alphabetic())
                    {
                        return Err(fail());
                    }
                } else if value.attr_value().tag() != Tag::Utf8String {
                    return Err(fail());
                }
            }
        }
        _ => {
            const DC: &str = "0.9.2342.19200300.100.1.25";
            let domains = types.iter().take_while(|v| **v == DC).count();
            if domains < 2 || !matches!(&types[domains..], ["2.5.4.3"] | ["2.5.4.11", "2.5.4.3"]) {
                return Err(fail());
            }
            for value in &attributes[..domains] {
                let text = value.as_str().map_err(|_| fail())?;
                if value.attr_value().tag() != Tag::Ia5String
                    || text.contains('.')
                    || ServerName::new(text).is_err()
                {
                    return Err(fail());
                }
            }
            for value in &attributes[domains..] {
                if value.attr_value().tag() != Tag::Utf8String {
                    return Err(fail());
                }
            }
            let host = attributes
                .last()
                .ok_or_else(fail)?
                .as_str()
                .map_err(|_| fail())?;
            if ServerName::new(host).is_err() {
                return Err(fail());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dtls_tests::generic::certificates::{der, rows, verifying_material, Fixture};

    #[tokio::test]
    async fn independent_selected_certificate_path_corpus() {
        let mut counts = (0, 0);
        for row in rows() {
            let (_source, controller, publisher) = verifying_material(&row);
            let prepared = prepare_material(&controller).await.unwrap();
            let binding = publisher.source().bind(prepared.handshake.epoch()).unwrap();
            let validation = HandshakeValidation {
                expected_peer: opc_identity::extract_spiffe_id_from_cert_der(&der(row[3])).unwrap(),
                trust_bundles: prepared.trust_bundles,
                usage: if row[0] == "client" {
                    PeerUsage::Client
                } else {
                    PeerUsage::Server
                },
                revocation: Some(Arc::clone(&binding.snapshot)),
                server_name: None,
                certificate_profile: Some(CertificateProfile::NdsAfEcdsa),
            };
            let mut chain = vec![der(row[3])];
            if !row[5].is_empty() {
                chain.push(der(row[5]));
            }
            let result = validate_peer_certificate_chain(&chain, &validation);
            assert_eq!(
                result.is_ok(),
                row[2] == "admit",
                "{} {}: {:?}",
                row[0],
                row[1],
                result
            );
            if result.is_ok() {
                counts.0 += 1;
            } else {
                counts.1 += 1;
            }
        }
        assert_eq!(counts, (22, 124));
    }

    #[tokio::test]
    async fn peer_profile_is_independent_of_adversarial_local_profile_bypass() {
        let policy = Policy::ordered_stream_zero(PayloadProtocol::Ngap, 4096).unwrap();
        for client in [true, false] {
            for case in [
                "missing-crldp",
                "leaf-noncritical-ku",
                "tls-ca-depth-one",
                "root-noncritical-ku",
                "root-too-weak",
                "ambiguous-anchor",
            ] {
                let mut fixture = Fixture::new(
                    if client { case } else { "valid" },
                    if client { "valid" } else { case },
                    policy,
                );
                // The test peer skips only its own added certificate checks.
                // Its genuine mutual DTLS engine, signatures, SPIFFE, SNI and
                // CRL verification remain active. The honest endpoint must
                // independently enforce the selected peer's profile.
                if client {
                    fixture.connector.0.certificate_profile = None;
                } else {
                    fixture.acceptor.0.certificate_profile = None;
                }
                let (a, b, log) = fixture.pair().await;
                let observed = if client { b.err() } else { a.err() };
                assert_eq!(
                    observed,
                    Some(Error::Authentication),
                    "client={client} {case}"
                );
                crate::dtls_tests::generic::sni::no_application(&log);
            }
        }
    }

    #[tokio::test]
    async fn certificate_profile_uses_only_selected_anchor_and_refuses_ambiguous_der() {
        use crate::dtls_tests::generic::certificates::row;
        let peer = row("client", "valid");
        let (_source, controller, publisher) = verifying_material(&peer);
        let prepared = prepare_material(&controller).await.unwrap();
        let binding = publisher.source().bind(prepared.handshake.epoch()).unwrap();
        let domain = TrustDomain::new("example.test").unwrap();
        let original = prepared
            .trust_bundles
            .get(&domain)
            .unwrap()
            .certificates
            .clone();
        for (role, case, allowed) in [
            ("server", "root-noncritical-ku", true),
            ("client", "valid", true),
            ("client", "root-noncritical-ku", false),
        ] {
            let mut certificates = original.clone();
            certificates.push(CertificateDer::from(der(row(role, case)[6])));
            let mut trust_bundles = TrustBundleSet::new();
            trust_bundles.insert(opc_identity::TrustBundle {
                trust_domain: domain.clone(),
                certificates,
            });
            let validation = HandshakeValidation {
                expected_peer: opc_identity::extract_spiffe_id_from_cert_der(&der(peer[3]))
                    .unwrap(),
                trust_bundles,
                usage: PeerUsage::Client,
                revocation: Some(Arc::clone(&binding.snapshot)),
                server_name: None,
                certificate_profile: Some(CertificateProfile::NdsAfEcdsa),
            };
            assert_eq!(
                validate_peer_certificate_chain(&[der(peer[3]), der(peer[5])], &validation).is_ok(),
                allowed,
                "{role} {case}"
            );
        }
    }
}
