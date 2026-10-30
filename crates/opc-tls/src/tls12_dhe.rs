//! RFC 7919 named FFDHE for explicit TLS 1.2 compatibility.

use crypto_bigint::{
    modular::{BoxedMontyForm, BoxedMontyParams},
    BoxedUint, Odd,
};
use rustls::{
    crypto::{
        ActiveKeyExchange, CryptoProvider, KeyExchangeAlgorithm, SharedSecret, SupportedKxGroup,
    },
    ffdhe_groups::{FfdheGroup, FFDHE2048, FFDHE4096},
    CipherSuite, CipherSuiteCommon, Error, NamedGroup, PeerMisbehaved, ProtocolVersion,
    SupportedCipherSuite, Tls12CipherSuite,
};
use zeroize::Zeroizing;

// Reuse ring's RSA signatures, PRF and record protection; only key agreement changes.
static DHE_RSA_AES128_GCM: Tls12CipherSuite =
    match rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
        SupportedCipherSuite::Tls12(source) => Tls12CipherSuite {
            common: CipherSuiteCommon {
                suite: CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
                hash_provider: source.common.hash_provider,
                confidentiality_limit: source.common.confidentiality_limit,
            },
            kx: KeyExchangeAlgorithm::DHE,
            sign: source.sign,
            aead_alg: source.aead_alg,
            prf_provider: source.prf_provider,
        },
        _ => panic!("ring TLS 1.2 suite changed version"),
    };

static GROUP4096: Ffdhe = Ffdhe {
    name: NamedGroup::FFDHE4096,
    parameters: FFDHE4096,
};
static GROUP2048: Ffdhe = Ffdhe {
    name: NamedGroup::FFDHE2048,
    parameters: FFDHE2048,
};

pub(super) fn provider(legacy_dhe_rsa: bool) -> CryptoProvider {
    let mut provider = rustls::crypto::ring::default_provider();
    if legacy_dhe_rsa {
        provider
            .cipher_suites
            .push(SupportedCipherSuite::Tls12(&DHE_RSA_AES128_GCM));
        provider
            .kx_groups
            .extend([&GROUP4096 as &dyn SupportedKxGroup, &GROUP2048]);
    }
    provider
}

#[derive(Debug)]
struct Ffdhe {
    name: NamedGroup,
    parameters: FfdheGroup<'static>,
}

impl Ffdhe {
    fn params(&self) -> Result<BoxedMontyParams, Error> {
        let prime = BoxedUint::from_be_slice_vartime(self.parameters.p);
        let odd = Odd::new(prime)
            .into_option()
            .ok_or_else(|| Error::General("invalid FFDHE prime".into()))?;
        Ok(BoxedMontyParams::new_vartime(odd))
    }
}

impl SupportedKxGroup for Ffdhe {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let mut entropy = Zeroizing::new([0u8; 64]);
        rustls::crypto::ring::default_provider()
            .secure_random
            .fill(&mut *entropy)
            .map_err(|_| Error::FailedToGetRandomBytes)?;
        // A fixed 512-bit exponent exceeds both RFC 7919 minimum lengths.
        entropy[0] |= 0x80;
        let secret = Zeroizing::new(
            BoxedUint::from_be_slice(&*entropy, 512)
                .map_err(|_| Error::General("invalid FFDHE exponent".into()))?,
        );
        let params = self.params()?;
        let generator = BoxedUint::from_be_slice(self.parameters.g, params.bits_precision())
            .map_err(|_| Error::General("invalid FFDHE generator".into()))?;
        let public = power(generator, &secret, &params).to_be_bytes();
        Ok(Box::new(FfdheExchange {
            name: self.name,
            parameters: self.parameters,
            params,
            secret,
            public,
        }))
    }

    fn name(&self) -> NamedGroup {
        self.name
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        Some(self.parameters)
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_2
    }
}

struct FfdheExchange {
    name: NamedGroup,
    parameters: FfdheGroup<'static>,
    params: BoxedMontyParams,
    secret: Zeroizing<BoxedUint>,
    public: Box<[u8]>,
}

fn power(base: BoxedUint, exponent: &BoxedUint, params: &BoxedMontyParams) -> Zeroizing<BoxedUint> {
    let base = Zeroizing::new(BoxedMontyForm::new(base, params));
    let powered = Zeroizing::new(base.pow(exponent));
    Zeroizing::new(powered.retrieve())
}

impl ActiveKeyExchange for FfdheExchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let invalid = || Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);
        if peer_pub_key.is_empty() || peer_pub_key.len() > self.parameters.p.len() {
            return Err(invalid());
        }
        let peer = BoxedUint::from_be_slice(peer_pub_key, self.params.bits_precision())
            .map_err(|_| invalid())?;
        let one = BoxedUint::one_with_precision(self.params.bits_precision());
        let maximum = self.params.modulus().as_ref().wrapping_sub(&one);
        // RFC 7919 §5.1: these safe primes require 1 < Y < p-1.
        if peer <= one || peer >= maximum {
            return Err(invalid());
        }
        let shared = power(peer, &self.secret, &self.params);
        let bytes = Zeroizing::new(shared.to_be_bytes());
        Ok(SharedSecret::from(bytes.as_ref()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        self.name
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        Some(self.parameters)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_groups_match_independent_libressl_and_python_vectors() {
        #[derive(serde::Deserialize)]
        struct Vector {
            bits: u32,
            private: String,
            public: String,
            peer: String,
            shared: String,
        }
        #[derive(serde::Deserialize)]
        struct Vectors {
            vectors: Vec<Vector>,
        }
        fn hex(value: &str) -> Vec<u8> {
            (0..value.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
                .collect()
        }
        let vectors: Vectors =
            serde_json::from_str(include_str!("../tests/data/ffdhe.json")).unwrap();
        assert_eq!(vectors.vectors.len(), 2);
        for vector in vectors.vectors {
            let group = match vector.bits {
                2048 => &GROUP2048,
                4096 => &GROUP4096,
                _ => panic!("unexpected fixture group"),
            };
            let secret =
                Zeroizing::new(BoxedUint::from_be_slice(&hex(&vector.private), 512).unwrap());
            let params = group.params().unwrap();
            let generator = BoxedUint::from_be_slice(group.parameters.g, vector.bits).unwrap();
            let public = power(generator, &secret, &params).to_be_bytes();
            assert_eq!(&*public, hex(&vector.public));
            let exchange = Box::new(FfdheExchange {
                name: group.name,
                parameters: group.parameters,
                params,
                secret,
                public,
            });
            let shared = exchange.complete(&hex(&vector.peer)).unwrap();
            assert_eq!(shared.secret_bytes(), hex(&vector.shared));
        }
    }

    fn fixed_exchange(group: &Ffdhe, secret: u8) -> Box<FfdheExchange> {
        Box::new(FfdheExchange {
            name: group.name,
            parameters: group.parameters,
            params: group.params().unwrap(),
            secret: Zeroizing::new(BoxedUint::from_be_slice(&[secret], 512).unwrap()),
            public: Box::new([]),
        })
    }

    #[test]
    fn named_groups_agree_with_fresh_ephemeral_keys() {
        for group in [&GROUP2048, &GROUP4096] {
            let first = group.start().unwrap();
            let second = group.start().unwrap();
            let first_public = first.pub_key().to_vec();
            let second_public = second.pub_key().to_vec();
            assert_eq!(first_public.len(), group.parameters.p.len());
            assert_ne!(first_public, second_public);
            let first_secret = first.complete(&second_public).unwrap();
            let second_secret = second.complete(&first_public).unwrap();
            assert_eq!(first_secret.secret_bytes(), second_secret.secret_bytes());
            assert_eq!(first_secret.secret_bytes().len(), group.parameters.p.len());
        }
    }

    #[test]
    fn malformed_and_small_order_public_keys_are_rejected() {
        for group in [&GROUP2048, &GROUP4096] {
            let mut minus_one = group.parameters.p.to_vec();
            *minus_one.last_mut().unwrap() -= 1;
            for peer in [
                vec![],
                vec![0],
                vec![1],
                minus_one,
                group.parameters.p.to_vec(),
                vec![2; group.parameters.p.len() + 1],
            ] {
                assert!(matches!(
                    fixed_exchange(group, 3).complete(&peer),
                    Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))
                ));
            }
        }
    }

    #[test]
    fn tls12_strips_shared_secret_zeros_and_accepts_short_peer_values() {
        for group in [&GROUP2048, &GROUP4096] {
            // Independent integer result: 2^3 mod either RFC 7919 prime is 8.
            let padded = fixed_exchange(group, 3).complete(&[2]).unwrap();
            assert_eq!(padded.secret_bytes().len(), group.parameters.p.len());
            assert!(padded.secret_bytes()[..group.parameters.p.len() - 1]
                .iter()
                .all(|byte| *byte == 0));
            assert_eq!(padded.secret_bytes().last(), Some(&8));
            let tls12 = fixed_exchange(group, 3)
                .complete_for_tls_version(&[0, 2], &rustls::version::TLS12)
                .unwrap();
            assert_eq!(tls12.secret_bytes(), &[8]);
        }
    }

    #[test]
    fn compatibility_is_explicit_and_never_adds_tls13_groups() {
        let strict = provider(false);
        assert!(!strict
            .cipher_suites
            .iter()
            .any(|suite| suite.suite() == DHE_RSA_AES128_GCM.common.suite));
        assert!(strict
            .kx_groups
            .iter()
            .all(|group| group.ffdhe_group().is_none()));
        let compatible = provider(true);
        let groups: Vec<_> = compatible
            .kx_groups
            .iter()
            .filter(|group| group.ffdhe_group().is_some())
            .collect();
        assert_eq!(
            groups.iter().map(|group| group.name()).collect::<Vec<_>>(),
            [NamedGroup::FFDHE4096, NamedGroup::FFDHE2048]
        );
        for group in groups {
            assert!(group.usable_for_version(ProtocolVersion::TLSv1_2));
            assert!(!group.usable_for_version(ProtocolVersion::TLSv1_3));
            assert!(!group.fips());
        }
    }
}
