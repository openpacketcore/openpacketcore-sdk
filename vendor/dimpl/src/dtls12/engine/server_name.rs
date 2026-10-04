//! Strict single-name negotiation; configuration is immutable across rekey.

use super::*;
use crate::dtls12::message::{ExtensionType, ExtensionVec};

impl Engine {
    pub(crate) fn verify_server_name(
        &self,
        extensions: &[crate::dtls12::message::Extension],
        bytes: &[u8],
        client_hello: bool,
    ) -> Result<(), Error> {
        let mut names = extensions
            .iter()
            .filter(|e| e.extension_type == ExtensionType::ServerName);
        let extension = names.next();
        let refuse = Error::SecurityError(crate::SecurityError::ServerNameMismatch);
        if names.next().is_some() {
            return Err(refuse);
        }
        let required = self.config().server_name();
        let Some(extension) = extension else {
            return if required.is_some() {
                Err(refuse)
            } else {
                Ok(())
            };
        };
        let body = bytes
            .get(extension.extension_data_range.clone())
            .ok_or(refuse.clone())?;
        if !client_hello {
            return if required.is_some() && body.is_empty() {
                Ok(())
            } else {
                Err(refuse)
            };
        }
        // One host_name only: the list and host lengths must consume the body.
        // Unknown name types are outside this bounded endpoint profile.
        if body.len() < 6
            || u16::from_be_bytes([body[0], body[1]]) as usize != body.len() - 2
            || body[2] != 0
            || u16::from_be_bytes([body[3], body[4]]) as usize != body.len() - 5
        {
            return Err(refuse);
        }
        let name = std::str::from_utf8(&body[5..]).map_err(|_| refuse.clone())?;
        if crate::ServerName::new(name).is_err()
            || required.is_some_and(|required| !required.matches(&body[5..]))
        {
            return Err(refuse);
        }
        Ok(())
    }

    pub(crate) fn add_server_name(
        &self,
        extensions: &mut ExtensionVec,
        bytes: &mut Buf,
        client_hello: bool,
    ) -> Result<(), Error> {
        if let Some(name) = self.config().server_name() {
            let start = bytes.len();
            if client_hello {
                name.encode(bytes);
            }
            extensions
                .try_push(crate::dtls12::message::Extension {
                    extension_type: ExtensionType::ServerName,
                    extension_data_range: start..bytes.len(),
                })
                .map_err(|_| Error::SecurityError(crate::SecurityError::ServerNameMismatch))?;
        }
        Ok(())
    }
}

#[cfg(test)]
pub(in crate::dtls12) mod tests {
    use super::*;

    pub(in crate::dtls12) struct Fixture {
        pub configured: &'static str,
        pub label: &'static str,
        pub accept: bool,
        pub extensions: Vec<u8>,
        pub record: Vec<u8>,
    }

    pub(in crate::dtls12) fn fixtures(role: &str) -> Vec<Fixture> {
        include_str!("../../../tests/dtls12/rfc6066_reference.tsv")
            .lines()
            .filter(|row| !row.starts_with('#'))
            .filter_map(|row| {
                let f: Vec<_> = row.split('\t').collect();
                assert_eq!(f.len(), 6);
                let decode = |hex: &str| -> Vec<u8> {
                    if hex == "-" {
                        return Vec::new();
                    }
                    (0..hex.len())
                        .step_by(2)
                        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                        .collect()
                };
                (f[0] == role).then(|| Fixture {
                    configured: f[1],
                    label: f[2],
                    accept: f[3] == "1",
                    extensions: decode(f[4]),
                    record: decode(f[5]),
                })
            })
            .collect()
    }

    pub(in crate::dtls12) fn receiver(client: bool, configured: &str) -> Engine {
        let mut engine = super::super::tests::rekey_fixture_receiver(client);
        if configured != "-" {
            engine.config = Arc::new(
                engine
                    .config
                    .as_ref()
                    .clone()
                    .with_server_name(crate::ServerName::new(configured).unwrap())
                    .unwrap(),
            );
        }
        engine
    }

    #[test]
    fn independent_sni_extensions_enforce_complete_single_name_and_empty_ack() {
        let mut total = 0;
        let mut admitted = 0;
        for role in ["client", "server"] {
            for Fixture {
                configured,
                label,
                accept,
                extensions: wire,
                ..
            } in fixtures(role)
            {
                let engine = receiver(role == "client", configured);
                let mut extensions = Vec::new();
                let mut offset = 0;
                while offset < wire.len() {
                    let (remaining, extension) =
                        crate::dtls12::message::Extension::parse(&wire[offset..], offset).unwrap();
                    offset = wire.len() - remaining.len();
                    extensions.push(extension);
                }
                let actual = engine.verify_server_name(&extensions, &wire, role == "server");
                assert_eq!(actual.is_ok(), accept, "{role}/{configured}/{label}");
                total += 1;
                admitted += usize::from(actual.is_ok());
            }
        }
        assert_eq!((total, admitted), (109, 11));
    }
}
