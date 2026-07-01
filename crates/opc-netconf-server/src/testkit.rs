//! Testkit helpers for NETCONF-over-SSH listener fixtures.
//!
//! This module is available only for crate tests or with the `testkit` feature.
//! It owns temporary SSH key generation so downstream integration tests do not
//! need direct `russh` dependencies or checked-in private keys.

use std::{
    fmt, fs, io,
    path::{Path, PathBuf},
};

use opc_types::TenantId;
use russh::keys::{self, PrivateKey};
use thiserror::Error;

use crate::ssh::{SshAuthorizedKey, SshHostKey, SshListenerConfig, SshListenerKeyMaterial};

/// Redaction-safe test fixture containing one host key and one authorized key.
#[derive(Clone)]
pub struct NetconfSshTestKeyFixture {
    host_key: SshHostKey,
    authorized_key: SshAuthorizedKey,
    host_private_key_openssh: String,
    host_public_key_openssh: String,
    client_private_key_openssh: String,
    authorized_public_key_openssh: String,
}

impl NetconfSshTestKeyFixture {
    /// Generate one Ed25519 SSH host key and one Ed25519 authorized client key.
    ///
    /// # Errors
    ///
    /// Returns [`NetconfSshTestKeyFixtureError`] if key generation or OpenSSH
    /// encoding fails.
    pub fn generate() -> Result<Self, NetconfSshTestKeyFixtureError> {
        let host_key = PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .map_err(|_| NetconfSshTestKeyFixtureError::HostKeyGenerate)?;
        let client_key = PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .map_err(|_| NetconfSshTestKeyFixtureError::ClientKeyGenerate)?;
        let host_private_key_openssh = host_key
            .to_openssh(keys::ssh_key::LineEnding::LF)
            .map_err(|_| NetconfSshTestKeyFixtureError::HostKeyEncode)?
            .to_string();
        let host_public_key_openssh = host_key
            .public_key()
            .to_openssh()
            .map_err(|_| NetconfSshTestKeyFixtureError::HostPublicKeyEncode)?;
        let client_private_key_openssh = client_key
            .to_openssh(keys::ssh_key::LineEnding::LF)
            .map_err(|_| NetconfSshTestKeyFixtureError::ClientKeyEncode)?
            .to_string();
        let authorized_public_key_openssh = client_key
            .public_key()
            .to_openssh()
            .map_err(|_| NetconfSshTestKeyFixtureError::ClientPublicKeyEncode)?;

        Ok(Self {
            host_key,
            authorized_key: client_key.public_key().clone(),
            host_private_key_openssh,
            host_public_key_openssh,
            client_private_key_openssh,
            authorized_public_key_openssh,
        })
    }

    /// Return listener key material for direct in-memory listener config tests.
    #[must_use]
    pub fn listener_key_material(&self) -> SshListenerKeyMaterial {
        SshListenerKeyMaterial {
            host_keys: vec![self.host_key.clone()],
            authorized_keys: vec![self.authorized_key.clone()],
        }
    }

    /// Build a listener config from this fixture.
    #[must_use]
    pub fn listener_config(&self, tenant: TenantId) -> SshListenerConfig {
        let material = self.listener_key_material();
        SshListenerConfig::new(tenant, material.host_keys, material.authorized_keys)
    }

    /// Return the host public key record that clients should trust.
    #[must_use]
    pub fn host_public_key_openssh(&self) -> &str {
        &self.host_public_key_openssh
    }

    /// Return the authorized public key record suitable for `authorized_keys`.
    #[must_use]
    pub fn authorized_public_key_openssh(&self) -> &str {
        &self.authorized_public_key_openssh
    }

    /// Return the client private key matching [`Self::authorized_public_key_openssh`].
    ///
    /// This is intended only for live smoke clients and tests. The fixture's
    /// `Debug` implementation and assertion helpers keep private bytes out of
    /// diagnostics.
    #[must_use]
    pub fn client_private_key_openssh(&self) -> &str {
        &self.client_private_key_openssh
    }

    /// Write host and authorized-key files into `dir`.
    ///
    /// The returned paths are suitable for
    /// [`crate::ssh::load_ssh_listener_key_files`].
    ///
    /// # Errors
    ///
    /// Returns [`NetconfSshTestKeyFixtureError`] if either file cannot be
    /// written.
    pub fn write_key_files<P: AsRef<Path>>(
        &self,
        dir: P,
    ) -> Result<NetconfSshTestKeyFiles, NetconfSshTestKeyFixtureError> {
        let dir = dir.as_ref();
        let host_key_path = dir.join("netconf_test_host_ed25519_key");
        let authorized_keys_path = dir.join("authorized_keys");
        fs::write(&host_key_path, self.host_private_key_openssh.as_bytes())
            .map_err(|_| NetconfSshTestKeyFixtureError::HostKeyWrite)?;
        fs::write(
            &authorized_keys_path,
            format!("{} netconf-testkit\n", self.authorized_public_key_openssh).as_bytes(),
        )
        .map_err(|_| NetconfSshTestKeyFixtureError::AuthorizedKeysWrite)?;
        Ok(NetconfSshTestKeyFiles {
            host_key_path,
            authorized_keys_path,
        })
    }

    fn private_key_markers(&self) -> [&str; 2] {
        [
            &self.host_private_key_openssh,
            &self.client_private_key_openssh,
        ]
    }
}

impl fmt::Debug for NetconfSshTestKeyFixture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetconfSshTestKeyFixture")
            .field("host_key", &"<redacted>")
            .field("authorized_key", &"<redacted>")
            .field(
                "authorized_public_key_len",
                &self.authorized_public_key_openssh.len(),
            )
            .finish()
    }
}

/// Paths written by [`NetconfSshTestKeyFixture::write_key_files`].
#[derive(Clone, PartialEq, Eq)]
pub struct NetconfSshTestKeyFiles {
    /// Host private key file path.
    pub host_key_path: PathBuf,
    /// Authorized public keys file path.
    pub authorized_keys_path: PathBuf,
}

impl fmt::Debug for NetconfSshTestKeyFiles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetconfSshTestKeyFiles")
            .field("has_host_key_path", &true)
            .field("has_authorized_keys_path", &true)
            .finish()
    }
}

/// Redaction-safe test key fixture error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum NetconfSshTestKeyFixtureError {
    /// Host key generation failed.
    #[error("netconf_ssh_testkit_host_key_generate")]
    HostKeyGenerate,
    /// Client key generation failed.
    #[error("netconf_ssh_testkit_client_key_generate")]
    ClientKeyGenerate,
    /// Client private key OpenSSH encoding failed.
    #[error("netconf_ssh_testkit_client_key_encode")]
    ClientKeyEncode,
    /// Host private key OpenSSH encoding failed.
    #[error("netconf_ssh_testkit_host_key_encode")]
    HostKeyEncode,
    /// Host public key OpenSSH encoding failed.
    #[error("netconf_ssh_testkit_host_public_key_encode")]
    HostPublicKeyEncode,
    /// Client public key OpenSSH encoding failed.
    #[error("netconf_ssh_testkit_client_public_key_encode")]
    ClientPublicKeyEncode,
    /// Host private key file write failed.
    #[error("netconf_ssh_testkit_host_key_write")]
    HostKeyWrite,
    /// Authorized public keys file write failed.
    #[error("netconf_ssh_testkit_authorized_keys_write")]
    AuthorizedKeysWrite,
}

impl NetconfSshTestKeyFixtureError {
    /// Return the stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HostKeyGenerate => "netconf_ssh_testkit_host_key_generate",
            Self::ClientKeyGenerate => "netconf_ssh_testkit_client_key_generate",
            Self::ClientKeyEncode => "netconf_ssh_testkit_client_key_encode",
            Self::HostKeyEncode => "netconf_ssh_testkit_host_key_encode",
            Self::HostPublicKeyEncode => "netconf_ssh_testkit_host_public_key_encode",
            Self::ClientPublicKeyEncode => "netconf_ssh_testkit_client_public_key_encode",
            Self::HostKeyWrite => "netconf_ssh_testkit_host_key_write",
            Self::AuthorizedKeysWrite => "netconf_ssh_testkit_authorized_keys_write",
        }
    }
}

/// Assert that SSH listener debug output does not contain generated private key
/// material.
///
/// # Panics
///
/// Panics with a redacted message when `value`'s [`fmt::Debug`] output contains
/// private key material from `fixture`.
pub fn assert_ssh_listener_debug_redacted<T: fmt::Debug + ?Sized>(
    value: &T,
    fixture: &NetconfSshTestKeyFixture,
) {
    let debug = format!("{value:?}");
    for marker in fixture.private_key_markers() {
        if debug.contains(marker) {
            panic!("netconf SSH listener debug leaked private key material");
        }
    }
}

/// Write one intentionally truncated host private key file.
///
/// # Errors
///
/// Returns [`io::Error`] when the file cannot be written.
pub fn write_truncated_host_key<P: AsRef<Path>>(path: P) -> io::Result<()> {
    fs::write(path, b"-----BEGIN OPENSSH PRIVATE KEY-----\n")
}

/// Write one intentionally truncated authorized public-key file.
///
/// # Errors
///
/// Returns [`io::Error`] when the file cannot be written.
pub fn write_truncated_authorized_key<P: AsRef<Path>>(
    path: P,
    fixture: &NetconfSshTestKeyFixture,
) -> io::Result<()> {
    let mut tokens = fixture.authorized_public_key_openssh.split_whitespace();
    let algorithm = tokens.next().unwrap_or("ssh-ed25519");
    let blob = tokens.next().unwrap_or_default();
    let truncated_blob = blob
        .strip_suffix(blob.chars().last().unwrap_or_default())
        .unwrap_or(blob);
    fs::write(path, format!("{algorithm} {truncated_blob}\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_debug_and_errors_are_redaction_safe() {
        let fixture = NetconfSshTestKeyFixture::generate().expect("fixture");

        let debug = format!("{fixture:?}");
        assert!(!debug.contains("OPENSSH PRIVATE KEY"));
        assert!(!debug.contains(fixture.authorized_public_key_openssh()));
        assert_ssh_listener_debug_redacted(&fixture, &fixture);

        let error = NetconfSshTestKeyFixtureError::HostKeyWrite;
        assert_eq!(error.as_str(), "netconf_ssh_testkit_host_key_write");
        assert_eq!(error.to_string(), error.as_str());
        assert!(!format!("{error:?}").contains("OPENSSH"));
        assert!(!format!("{error}").contains("OPENSSH"));
    }
}
