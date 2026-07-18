#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("frame too large: {0} bytes")]
    FrameTooLarge(usize),
    #[error("version mismatch: local={local}, remote={remote}")]
    VersionMismatch { local: u32, remote: u32 },
    #[error("session protocol contract profile mismatch")]
    ContractMismatch,
    #[error("session protocol value is outside the fixed-width contract")]
    InvalidWireValue,
    #[error("peer authentication failed")]
    Authentication,
    #[error("unexpected protocol response")]
    UnexpectedResponse,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("backend unavailable: {0}")]
    BackendUnavailable(String),
}

/// Preserve TLS failure categories when `tokio-rustls` reports through its
/// `io::Error` wrapper.
///
/// TCP and ordinary socket failures remain transport failures. Certificate,
/// trust, and peer-authentication failures collapse to the existing
/// redaction-safe authentication category; every other rustls failure is a TLS
/// protocol failure.
pub(crate) fn classify_tls_io_error(error: std::io::Error) -> ProtocolError {
    let Some(rustls_error) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<tokio_rustls::rustls::Error>())
    else {
        return ProtocolError::Io(error);
    };
    if tls_error_is_authentication(rustls_error) {
        ProtocolError::Authentication
    } else {
        ProtocolError::UnexpectedResponse
    }
}

fn tls_error_is_authentication(error: &tokio_rustls::rustls::Error) -> bool {
    use tokio_rustls::rustls::{AlertDescription, Error};

    match error {
        Error::InvalidCertificate(_)
        | Error::InvalidCertRevocationList(_)
        | Error::NoCertificatesPresented
        | Error::UnsupportedNameType => true,
        Error::AlertReceived(alert) => matches!(
            alert,
            AlertDescription::NoCertificate
                | AlertDescription::BadCertificate
                | AlertDescription::UnsupportedCertificate
                | AlertDescription::CertificateRevoked
                | AlertDescription::CertificateExpired
                | AlertDescription::CertificateUnknown
                | AlertDescription::UnknownCA
                | AlertDescription::AccessDenied
                | AlertDescription::CertificateUnobtainable
                | AlertDescription::BadCertificateStatusResponse
                | AlertDescription::BadCertificateHashValue
                | AlertDescription::CertificateRequired
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn wrapped_rustls_error(error: tokio_rustls::rustls::Error) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::InvalidData, error)
    }

    #[test]
    fn tls_accept_errors_distinguish_authentication_protocol_and_transport() {
        use tokio_rustls::rustls::{
            AlertDescription, CertRevocationListError, CertificateError, Error, InvalidMessage,
        };

        for authentication_error in [
            Error::InvalidCertificate(CertificateError::UnknownIssuer),
            Error::InvalidCertRevocationList(CertRevocationListError::ParseError),
            Error::NoCertificatesPresented,
            Error::UnsupportedNameType,
            Error::AlertReceived(AlertDescription::BadCertificate),
            Error::AlertReceived(AlertDescription::AccessDenied),
            Error::AlertReceived(AlertDescription::CertificateUnobtainable),
        ] {
            assert!(matches!(
                classify_tls_io_error(wrapped_rustls_error(authentication_error)),
                ProtocolError::Authentication
            ));
        }

        for protocol_error in [
            Error::General("redacted test failure".to_owned()),
            Error::InvalidMessage(InvalidMessage::MessageTooShort),
            Error::PeerSentOversizedRecord,
            Error::NoApplicationProtocol,
            Error::AlertReceived(AlertDescription::NoApplicationProtocol),
        ] {
            assert!(matches!(
                classify_tls_io_error(wrapped_rustls_error(protocol_error)),
                ProtocolError::UnexpectedResponse
            ));
        }

        let transport_failure =
            std::io::Error::new(std::io::ErrorKind::ConnectionReset, "redacted test failure");
        assert!(matches!(
            classify_tls_io_error(transport_failure),
            ProtocolError::Io(error) if error.kind() == std::io::ErrorKind::ConnectionReset
        ));
    }

    #[tokio::test]
    async fn tokio_rustls_accept_without_a_client_certificate_is_authentication() {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};
        use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
        use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};

        let ca_key = KeyPair::generate().expect("generate CA key");
        let mut ca_parameters = CertificateParams::default();
        ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_parameters
            .distinguished_name
            .push(DnType::CommonName, "TLS accept classifier CA");
        let ca = rcgen::CertifiedIssuer::self_signed(ca_parameters, ca_key).expect("sign CA");
        let server_key = KeyPair::generate().expect("generate server key");
        let mut server_parameters = CertificateParams::default();
        server_parameters.subject_alt_names.push(SanType::DnsName(
            rcgen::string::Ia5String::try_from("localhost").expect("localhost DNS name"),
        ));
        let server_certificate = server_parameters
            .signed_by(&server_key, &ca)
            .expect("sign server certificate");

        let mut roots = RootCertStore::empty();
        roots.add(ca.der().clone()).expect("add test CA");
        let client_verifier =
            tokio_rustls::rustls::server::WebPkiClientVerifier::builder(Arc::new(roots.clone()))
                .build()
                .expect("client verifier");
        let server_config = ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(
                vec![server_certificate.der().clone(), ca.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
            )
            .expect("server config");
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let address = listener.local_addr().expect("test listener address");
        let accept = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept TCP");
            tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
                .accept(tcp)
                .await
                .expect_err("server must reject a missing client certificate")
        });
        let tcp = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect TCP");
        let connect = tokio_rustls::TlsConnector::from(Arc::new(client_config)).connect(
            ServerName::try_from("localhost")
                .expect("server name")
                .to_owned(),
            tcp,
        );
        let (client_result, accept_result) =
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                tokio::join!(connect, accept)
            })
            .await
            .expect("TLS accept classification must not hang");
        drop(client_result);
        let accept_error = accept_result.expect("join TLS accept");
        assert!(matches!(
            classify_tls_io_error(accept_error),
            ProtocolError::Authentication
        ));
    }
}
