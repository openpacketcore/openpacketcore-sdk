//! Explicit name selection layered on the existing mutual identity contract.

use super::*;

/// One exact DNS name required in SNI and the server certificate's DNS SAN.
///
/// Names are ASCII, at most 253 bytes with labels of at most 63 bytes, and
/// compared without ASCII case. IP literals, wildcards, trailing dots and
/// Unicode input are refused. A-label conversion is caller-owned. The name
/// adds a check; it never substitutes for the pinned SPIFFE peer or trust epoch.
#[derive(Clone, PartialEq, Eq)]
pub struct ServerName(pub(super) dimpl::ServerName);

impl ServerName {
    /// Validate the bounded name; errors contain no input values.
    pub fn new(name: &str) -> Result<Self, Error> {
        dimpl::ServerName::new(name)
            .map(Self)
            .map_err(|_| Error::PolicyRejected)
    }

    /// Explicitly inspect the canonical name; do not log it.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub(in crate::dtls) fn verify_certificate(&self, der: &[u8]) -> Result<(), DiameterTlsError> {
        let (remaining, certificate) =
            X509Certificate::from_der(der).map_err(|_| DiameterTlsError::Authentication)?;
        if !remaining.is_empty() {
            return Err(DiameterTlsError::Authentication);
        }
        let san = certificate
            .subject_alternative_name()
            .map_err(|_| DiameterTlsError::Authentication)?
            .ok_or(DiameterTlsError::PeerIdentityMismatch)?;
        let matched = san.value.general_names.iter().any(|name| {
            if let x509_parser::extensions::GeneralName::DNSName(value) = name {
                Self::new(value).is_ok_and(|name| name == *self)
            } else {
                false
            }
        });
        if !matched {
            return Err(DiameterTlsError::PeerIdentityMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for ServerName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServerName([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dtls_tests::generic::sni::{connect_pair, fixture, no_application, NAME};

    #[tokio::test]
    async fn connector_checks_dns_san_even_when_authenticated_peer_acknowledges_wrong_certificate()
    {
        let policy = Policy::ordered_stream_zero(PayloadProtocol::Ngap, 4096).unwrap();
        for names in [vec![], vec!["wrong.example.test"], vec!["*.example.test"]] {
            let (_material, connector, mut acceptor) = fixture(&names, policy);
            // Adversarial test peer: keep its real wire SNI acknowledgement,
            // trust chain and SPIFFE identity, bypass only its local SAN guard.
            // The production connector must independently reject its certificate.
            acceptor.0.server_name = None;
            let (client, server, log) = connect_pair(&connector, &acceptor).await;
            assert_eq!(client.err(), Some(Error::PeerIdentityMismatch));
            assert!(server.is_err());
            no_application(&log);
        }
        let (_material, connector, mut acceptor) = fixture(&[NAME], policy);
        acceptor.0.server_name = None;
        let (client, server, _) = connect_pair(&connector, &acceptor).await;
        assert!(
            client.is_ok(),
            "same adversarial peer with matching SAN succeeds"
        );
        assert!(server.is_ok());
    }
}
