//! Bounded RFC 6066 host_name for the explicit DTLS 1.2 SCTP profile.

use std::fmt;

use crate::{ConfigError, Error};

/// One ASCII DNS server name, with value-free diagnostic formatting.
///
/// Wildcards, IP literals, trailing dots and non-ASCII input are unsupported.
/// International names must already use ASCII A-labels. Matching ignores ASCII
/// case. This value selects a name; certificate authentication belongs to the
/// embedding transport and is not established by the extension itself.
#[derive(Clone, PartialEq, Eq)]
pub struct ServerName(String);

impl ServerName {
    /// Validate a DNS name before allocating the canonical lowercase copy.
    pub fn new(name: &str) -> Result<Self, Error> {
        if !valid_name(name) {
            return Err(Error::ConfigError(ConfigError::ServerNameProfile));
        }
        Ok(Self(name.to_ascii_lowercase()))
    }

    /// Explicitly borrow the configured name; do not log identity values.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn matches(&self, name: &[u8]) -> bool {
        std::str::from_utf8(name)
            .ok()
            .is_some_and(|name| valid_name(name) && self.0.eq_ignore_ascii_case(name))
    }

    pub(crate) fn encode(&self, output: &mut crate::buffer::Buf) {
        // Construction bounds the lengths to 253 and 256 respectively.
        output.extend_from_slice(&((self.0.len() + 3) as u16).to_be_bytes());
        output.push(0);
        output.extend_from_slice(&(self.0.len() as u16).to_be_bytes());
        output.extend_from_slice(self.0.as_bytes());
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.is_ascii()
        && name.parse::<std::net::IpAddr>().is_err()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

impl fmt::Debug for ServerName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServerName([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sni_configuration_requires_the_mutual_certificate_sctp_profile() {
        let name = ServerName::new("amf.example.test").unwrap();
        let ordinary = crate::Config::builder().build().unwrap();
        assert_eq!(
            ordinary.with_server_name(name.clone()).unwrap_err(),
            Error::ConfigError(ConfigError::ServerNameProfile)
        );
        let no_mutual = crate::Config::builder()
            .rfc6083_sctp()
            .dtls13_cipher_suites(&[])
            .build()
            .unwrap();
        assert_eq!(
            no_mutual.with_server_name(name.clone()).unwrap_err(),
            Error::ConfigError(ConfigError::ServerNameProfile)
        );
        let mutual = crate::Config::builder()
            .rfc6083_sctp()
            .require_server_certificate_request(true)
            .dtls13_cipher_suites(&[])
            .build()
            .unwrap();
        assert!(mutual.server_name().is_none());
        let configured = mutual.with_server_name(name.clone()).unwrap();
        assert_eq!(configured.server_name(), Some(&name));
        assert!(!format!("{configured:?}").contains(name.as_str()));
    }
}
