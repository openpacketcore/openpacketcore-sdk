use hmac::{Hmac, Mac};
use opc_data_governance::{DataClass, IdentifierType};
use sha2::Sha256;
use std::fmt;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// A 256-bit key used for tenant-scoped privacy digests.
///
/// This type is deliberately separate from AEAD keys to satisfy RFC 003 §9.1
/// key-purpose separation. The inner material is stored in a [`Zeroizing`]
/// buffer and is not publicly accessible; `Clone` is deliberately omitted so
/// the key cannot be silently duplicated outside the crate boundary.
pub struct DigestKey(Zeroizing<[u8; 32]>);

impl DigestKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

impl fmt::Debug for DigestKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DigestKey")
            .field("material", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DigestError {
    #[error("digest computation failed")]
    ComputationFailed,
}

/// Compute a tenant-scoped keyed digest per RFC 010 §5.
///
/// ```text
/// digest = HMAC(tenant_privacy_key, data_class || identifier_type || raw_value)
/// ```
///
/// The output is a stable lowercase hex string. Rotating the digest key changes
/// correlation IDs; this must be documented in operational runbooks.
pub fn compute_digest(
    key: &DigestKey,
    class: DataClass,
    id_type: IdentifierType,
    raw_value: &str,
) -> String {
    let mut mac =
        HmacSha256::new_from_slice(&*key.0).expect("HMAC-SHA256 accepts keys of any size");
    mac.update(class.as_str().as_bytes());
    mac.update(b"\x00");
    mac.update(id_type.as_str().as_bytes());
    mac.update(b"\x00");
    mac.update(raw_value.as_bytes());
    let result = mac.finalize();
    hex_encode(&result.into_bytes())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_data_governance::{DataClass, IdentifierType};

    #[test]
    fn digest_is_stable_for_same_inputs() {
        let key = DigestKey::new([0x42; 32]);
        let d1 = compute_digest(
            &key,
            DataClass::SubscriberId,
            IdentifierType::Supi,
            "123456789012345",
        );
        let d2 = compute_digest(
            &key,
            DataClass::SubscriberId,
            IdentifierType::Supi,
            "123456789012345",
        );
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 64); // SHA256 hex = 64 chars
    }

    #[test]
    fn digest_changes_with_key() {
        let k1 = DigestKey::new([0x42; 32]);
        let k2 = DigestKey::new([0x43; 32]);
        let d1 = compute_digest(&k1, DataClass::SubscriberId, IdentifierType::Supi, "same");
        let d2 = compute_digest(&k2, DataClass::SubscriberId, IdentifierType::Supi, "same");
        assert_ne!(d1, d2);
    }

    #[test]
    fn digest_changes_with_class() {
        let key = DigestKey::new([0x42; 32]);
        let d1 = compute_digest(&key, DataClass::SubscriberId, IdentifierType::Supi, "same");
        let d2 = compute_digest(
            &key,
            DataClass::SubscriberSession,
            IdentifierType::Supi,
            "same",
        );
        assert_ne!(d1, d2);
    }

    #[test]
    fn digest_changes_with_identifier_type() {
        let key = DigestKey::new([0x42; 32]);
        let d1 = compute_digest(&key, DataClass::SubscriberId, IdentifierType::Supi, "same");
        let d2 = compute_digest(&key, DataClass::SubscriberId, IdentifierType::Gpsi, "same");
        assert_ne!(d1, d2);
    }

    #[test]
    fn digest_key_debug_is_redacted() {
        let key = DigestKey::new([0x42; 32]);
        let debug = format!("{key:?}");
        assert!(debug.contains("DigestKey"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("42"));
    }
}
