//! RSA signing uses ring's private-key implementation in both built-in providers.

use der::Decode;
use ring::{rand::SystemRandom, signature};
use x509_cert::Certificate;

use super::SigningKey;
use crate::buffer::Buf;
use crate::types::{HashAlgorithm, SignatureAlgorithm, SignatureScheme};
use crate::{CryptoError, CryptoOperation};

struct RsaSigningKey(signature::RsaKeyPair);

impl std::fmt::Debug for RsaSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RsaSigningKey([redacted])")
    }
}

pub(super) fn load_key(der: &[u8]) -> Option<Box<dyn SigningKey>> {
    signature::RsaKeyPair::from_pkcs8(der)
        .or_else(|_| signature::RsaKeyPair::from_der(der))
        .ok()
        .map(|key| Box::new(RsaSigningKey(key)) as Box<dyn SigningKey>)
}

fn algorithms(
    scheme: SignatureScheme,
) -> Result<
    (
        &'static dyn signature::RsaEncoding,
        &'static signature::RsaParameters,
    ),
    CryptoError,
> {
    match scheme {
        SignatureScheme::RSA_PSS_RSAE_SHA256 => Ok((
            &signature::RSA_PSS_SHA256,
            &signature::RSA_PSS_2048_8192_SHA256,
        )),
        SignatureScheme::RSA_PSS_RSAE_SHA384 => Ok((
            &signature::RSA_PSS_SHA384,
            &signature::RSA_PSS_2048_8192_SHA384,
        )),
        SignatureScheme::RSA_PKCS1_SHA256 => Ok((
            &signature::RSA_PKCS1_SHA256,
            &signature::RSA_PKCS1_2048_8192_SHA256,
        )),
        SignatureScheme::RSA_PKCS1_SHA384 => Ok((
            &signature::RSA_PKCS1_SHA384,
            &signature::RSA_PKCS1_2048_8192_SHA384,
        )),
        _ => Err(CryptoError::UnsupportedSignaturePair {
            signature: SignatureAlgorithm::RSA,
            hash: scheme.hash_algorithm(),
        }),
    }
}

impl SigningKey for RsaSigningKey {
    fn supports_scheme(&self, scheme: SignatureScheme) -> bool {
        algorithms(scheme).is_ok()
    }

    fn sign_with_scheme(
        &mut self,
        data: &[u8],
        scheme: SignatureScheme,
        out: &mut Buf,
    ) -> Result<(), CryptoError> {
        let (encoding, _) = algorithms(scheme)?;
        out.clear();
        out.resize(self.0.public().modulus_len(), 0);
        self.0
            .sign(encoding, &SystemRandom::new(), data, out)
            .map_err(|_| CryptoError::OperationFailed(CryptoOperation::Sign))
    }

    fn sign(&mut self, data: &[u8], hash: HashAlgorithm, out: &mut Buf) -> Result<(), CryptoError> {
        self.sign_with_scheme(
            data,
            SignatureScheme::from_u16(((hash.as_u8() as u16) << 8) | 1),
            out,
        )
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
    fn hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }
    fn supported_hash_algorithms(&self) -> &[HashAlgorithm] {
        &[HashAlgorithm::SHA256, HashAlgorithm::SHA384]
    }
}

pub(super) fn verify(
    cert: &[u8],
    data: &[u8],
    sig: &[u8],
    scheme: SignatureScheme,
) -> Result<(), CryptoError> {
    let (_, algorithm) = algorithms(scheme)?;
    let cert = Certificate::from_der(cert).map_err(|_| CryptoError::CertificateParseFailed)?;
    let spki = &cert.tbs_certificate.subject_public_key_info;
    // rsa_pss_rsae and rsa_pkcs1 require rsaEncryption, not an RSASSA-PSS constrained key.
    if spki.algorithm.oid != spki::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1")
        || spki
            .algorithm
            .parameters
            .as_ref()
            .is_some_and(|parameters| !parameters.is_null())
    {
        return Err(CryptoError::UnsupportedPublicKeyAlgorithm);
    }
    let key = spki
        .subject_public_key
        .as_bytes()
        .ok_or(CryptoError::InvalidSubjectPublicKey)?;
    signature::UnparsedPublicKey::new(algorithm, key)
        .verify(data, sig)
        .map_err(|_| CryptoError::OperationFailed(CryptoOperation::VerifySignature))
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Encode;

    #[test]
    fn independent_rsa_signatures_require_the_exact_scheme_data_and_key() {
        let cert = include_bytes!("validation/rsa_cert.der");
        let data = include_bytes!("validation/test_data.bin");
        let cases = [
            (
                SignatureScheme::RSA_PKCS1_SHA256,
                include_bytes!("validation/rsa_sha256.sig").as_slice(),
            ),
            (
                SignatureScheme::RSA_PKCS1_SHA384,
                include_bytes!("validation/rsa_sha384.sig").as_slice(),
            ),
            (
                SignatureScheme::RSA_PSS_RSAE_SHA256,
                include_bytes!("validation/rsa_pss_sha256.sig").as_slice(),
            ),
            (
                SignatureScheme::RSA_PSS_RSAE_SHA384,
                include_bytes!("validation/rsa_pss_sha384.sig").as_slice(),
            ),
        ];
        for (scheme, signature) in cases {
            verify(cert, data, signature, scheme).expect("independent OpenSSL signature");
            assert!(verify(cert, b"different transcript", signature, scheme).is_err());
            let mut corrupt = signature.to_vec();
            corrupt[0] ^= 1;
            assert!(verify(cert, data, &corrupt, scheme).is_err());
            assert!(
                verify(
                    include_bytes!("validation/p256_cert.der"),
                    data,
                    signature,
                    scheme
                )
                .is_err()
            );
            for (other, _) in cases {
                if scheme != other {
                    assert!(verify(cert, data, signature, other).is_err());
                }
            }
        }
        let mut constrained = Certificate::from_der(cert).unwrap();
        constrained
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .parameters = Some(der::asn1::Any::new(der::Tag::OctetString, vec![0]).unwrap());
        assert!(verify(&constrained.to_der().unwrap(), data, cases[2].1, cases[2].0).is_err());
        constrained
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .parameters = Some(der::asn1::Any::null());
        constrained
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .oid = spki::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
        assert!(verify(&constrained.to_der().unwrap(), data, cases[2].1, cases[2].0).is_err());
    }

    #[test]
    fn rsa_signing_rejects_weak_keys_and_unsupported_schemes() {
        let weak = openssl::rsa::Rsa::generate(1024).unwrap();
        assert!(load_key(&weak.private_key_to_der().unwrap()).is_none());
        let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
        let key = openssl::pkey::PKey::from_rsa(rsa).unwrap();
        let mut signer = load_key(&key.private_key_to_pkcs8().unwrap()).unwrap();
        assert_eq!(format!("{signer:?}"), "RsaSigningKey([redacted])");
        for scheme in [
            SignatureScheme::from_u16(0x0201),
            SignatureScheme::RSA_PSS_PSS_SHA256,
            SignatureScheme::ECDSA_SECP256R1_SHA256,
        ] {
            assert!(!signer.supports_scheme(scheme));
            assert!(
                signer
                    .sign_with_scheme(b"transcript", scheme, &mut Buf::new())
                    .is_err()
            );
        }
        for scheme in [
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PSS_RSAE_SHA256,
            SignatureScheme::RSA_PSS_RSAE_SHA384,
        ] {
            let mut sig = Buf::new();
            signer
                .sign_with_scheme(b"transcript", scheme, &mut sig)
                .unwrap();
            let hash = if scheme.hash_algorithm() == HashAlgorithm::SHA256 {
                openssl::hash::MessageDigest::sha256()
            } else {
                openssl::hash::MessageDigest::sha384()
            };
            let mut verifier = openssl::sign::Verifier::new(hash, &key).unwrap();
            if matches!(
                scheme,
                SignatureScheme::RSA_PSS_RSAE_SHA256 | SignatureScheme::RSA_PSS_RSAE_SHA384
            ) {
                verifier
                    .set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)
                    .unwrap();
                verifier
                    .set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::DIGEST_LENGTH)
                    .unwrap();
            }
            verifier.update(b"transcript").unwrap();
            assert!(verifier.verify(&sig).unwrap());
        }
    }
}
