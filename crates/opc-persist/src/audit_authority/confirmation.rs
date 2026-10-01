//! Private plaintext format inside provider-encrypted confirmation ownership.
//! Parsing this body alone grants no authority. The caller first authenticates
//! the exact retained envelope, expected tenant, original effect AAD and digest.

use sha2::{digest::CtOutput, Digest, Sha256};
use zeroize::Zeroizing;

use super::{AuditAuthorityError, AUDIT_OPERATION_MAX_BYTES};

const PREFIX: &[u8; 8] = b"OPCNCO\x01\0";
const HEADER_BYTES: usize = 8 + 1 + 16 + 4;

pub(crate) fn bounded_token(token: Option<&str>) -> Result<(), AuditAuthorityError> {
    if token.is_some_and(|value| value.is_empty() || value.len() > AUDIT_OPERATION_MAX_BYTES) {
        return Err(AuditAuthorityError::InvalidInput);
    }
    Ok(())
}

/// Encode a bounded credential only inside zeroizing storage. A fresh encrypted
/// salt prevents the existing public plaintext digest from acting as a stable
/// credential fingerprint or a direct verifier for guessed credentials.
pub(crate) fn encode(token: Option<&str>) -> Result<Zeroizing<Vec<u8>>, AuditAuthorityError> {
    bounded_token(token)?;
    let credential = token.unwrap_or_default().as_bytes();
    let mut body = Zeroizing::new(Vec::with_capacity(HEADER_BYTES + credential.len()));
    body.extend_from_slice(PREFIX);
    body.push(u8::from(token.is_some()));
    body.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    body.extend_from_slice(&(credential.len() as u32).to_be_bytes());
    body.extend_from_slice(credential);
    Ok(body)
}

/// Verify only the format and credential equality of an already authenticated
/// plaintext. Original caller/session/pending authority is checked separately.
pub(crate) fn verify(
    body: &[u8],
    persistent: bool,
    token: Option<&str>,
) -> Result<(), AuditAuthorityError> {
    bounded_token(token)?;
    let bad = AuditAuthorityError::BindingMismatch;
    if body.len() < HEADER_BYTES
        || body.len() > HEADER_BYTES + AUDIT_OPERATION_MAX_BYTES
        || body[..8] != *PREFIX
        || body[8] != u8::from(persistent)
        || token.is_some() != persistent
    {
        return Err(bad);
    }
    let count = u32::from_be_bytes(body[25..29].try_into().map_err(|_| bad)?) as usize;
    if count != body.len() - HEADER_BYTES || persistent != (count != 0) {
        return Err(bad);
    }
    // RustCrypto's existing fixed-size CtOutput equality performs the secret
    // comparison. No local comparison algorithm or additional key is used.
    let expected = CtOutput::<Sha256>::new(Sha256::digest(&body[HEADER_BYTES..]));
    let supplied = CtOutput::<Sha256>::new(Sha256::digest(token.unwrap_or_default().as_bytes()));
    if expected != supplied {
        return Err(bad);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirmation_credential_format_requires_exact_mode_and_secret() {
        for token in [
            None,
            Some("synthetic-confirmation-token"),
            Some("\u{1f512}\0value"),
        ] {
            let body = encode(token).unwrap();
            assert_eq!(verify(&body, token.is_some(), token), Ok(()));
            assert!(verify(&body, token.is_none(), token).is_err());
            if token.is_some() {
                assert!(verify(&body, true, None).is_err());
                assert!(verify(&body, true, Some("different-token")).is_err());
            } else {
                assert!(verify(&body, false, Some("unexpected-token")).is_err());
            }
        }
    }

    #[test]
    fn confirmation_credential_format_refuses_noncanonical_and_unbounded_bodies() {
        let body = encode(Some("synthetic-confirmation-token")).unwrap();
        for length in 0..body.len() {
            assert!(verify(&body[..length], true, Some("synthetic-confirmation-token")).is_err());
        }
        for offset in [0, 6, 7, 8, 25, 26, 27, 28] {
            let mut modified = body.to_vec();
            modified[offset] ^= 1;
            assert!(verify(&modified, true, Some("synthetic-confirmation-token")).is_err());
        }
        let mut trailing = body.to_vec();
        trailing.push(0);
        assert!(verify(&trailing, true, Some("synthetic-confirmation-token")).is_err());
        assert!(encode(Some("")).is_err());
        let oversized = "x".repeat(AUDIT_OPERATION_MAX_BYTES + 1);
        assert!(encode(Some(&oversized)).is_err());
        assert!(verify(&body, true, Some(&oversized)).is_err());
        let limit = "x".repeat(AUDIT_OPERATION_MAX_BYTES);
        let bounded = encode(Some(&limit)).unwrap();
        assert_eq!(bounded.len(), HEADER_BYTES + AUDIT_OPERATION_MAX_BYTES);
        assert_eq!(verify(&bounded, true, Some(&limit)), Ok(()));
    }

    #[test]
    fn confirmation_credential_format_salts_public_plaintext_fingerprints() {
        let a = encode(Some("synthetic-confirmation-token")).unwrap();
        let b = encode(Some("synthetic-confirmation-token")).unwrap();
        assert_ne!(a[9..25], b[9..25]);
        assert_ne!(Sha256::digest(&*a), Sha256::digest(&*b));
        assert_eq!(
            verify(&a, true, Some("synthetic-confirmation-token")),
            Ok(())
        );
        assert_eq!(
            verify(&b, true, Some("synthetic-confirmation-token")),
            Ok(())
        );
    }
}
