//! RFC 7919 named groups for DTLS 1.2. Parameters also remain available to custom providers.

use crate::types::NamedGroup;

pub(crate) fn prime(group: NamedGroup) -> Option<&'static [u8]> {
    match group {
        NamedGroup::FFDHE2048 => Some(include_bytes!("ffdhe2048.bin")),
        NamedGroup::FFDHE4096 => Some(include_bytes!("ffdhe4096.bin")),
        _ => None,
    }
}

pub(crate) fn group_for_parameters(p: &[u8], g: &[u8]) -> Option<NamedGroup> {
    let trim = |bytes: &[u8]| bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    if g[trim(g)..] != [2] {
        return None;
    }
    [NamedGroup::FFDHE4096, NamedGroup::FFDHE2048]
        .into_iter()
        .find(|group| prime(*group) == Some(&p[trim(p)..]))
}

#[cfg(feature = "_crypto-common")]
pub(crate) use implementation::{FFDHE2048, FFDHE4096};

#[cfg(feature = "_crypto-common")]
mod implementation {
    use super::*;
    use crate::buffer::Buf;
    use crate::crypto::{ActiveKeyExchange, SupportedKxGroup};
    use crate::{CryptoError, CryptoOperation};
    use crypto_bigint::{
        BoxedUint, Odd,
        modular::{BoxedMontyForm, BoxedMontyParams},
    };
    use ring::rand::SecureRandom;
    use zeroize::{Zeroize, Zeroizing};

    pub(crate) static FFDHE2048: Ffdhe = Ffdhe(NamedGroup::FFDHE2048);
    pub(crate) static FFDHE4096: Ffdhe = Ffdhe(NamedGroup::FFDHE4096);

    #[derive(Debug)]
    pub(crate) struct Ffdhe(NamedGroup);

    impl Ffdhe {
        fn params(&self) -> Result<BoxedMontyParams, CryptoError> {
            let p = prime(self.0).ok_or(CryptoError::UnsupportedKeyExchangeGroup(self.0))?;
            let odd = Odd::new(BoxedUint::from_be_slice_vartime(p))
                .into_option()
                .ok_or(CryptoError::UnsupportedKeyExchangeGroup(self.0))?;
            Ok(BoxedMontyParams::new_vartime(odd))
        }
    }

    impl SupportedKxGroup for Ffdhe {
        fn name(&self) -> NamedGroup {
            self.0
        }

        fn start_exchange(&self, mut buf: Buf) -> Result<Box<dyn ActiveKeyExchange>, CryptoError> {
            let mut entropy = Zeroizing::new([0u8; 64]);
            ring::rand::SystemRandom::new()
                .fill(&mut *entropy)
                .map_err(|_| CryptoError::OperationFailed(CryptoOperation::FillRandom))?;
            // Fixed 512-bit exponents exceed RFC 7919's minimum for both groups.
            entropy[0] |= 0x80;
            let secret =
                Zeroizing::new(BoxedUint::from_be_slice(&*entropy, 512).map_err(|_| {
                    CryptoError::OperationFailed(CryptoOperation::GenerateEphemeralKey)
                })?);
            let params = self.params()?;
            let generator = BoxedUint::from_be_slice(&[2], params.bits_precision())
                .map_err(|_| CryptoError::OperationFailed(CryptoOperation::ComputePublicKey))?;
            let public = power(generator, &secret, &params).to_be_bytes();
            buf.clear();
            buf.extend_from_slice(&public);
            Ok(Box::new(Exchange {
                group: self.0,
                params,
                secret,
                public: buf,
            }))
        }
    }

    struct Exchange {
        group: NamedGroup,
        params: BoxedMontyParams,
        secret: Zeroizing<BoxedUint>,
        public: Buf,
    }

    impl std::fmt::Debug for Exchange {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("FfdheExchange")
                .field("group", &self.group)
                .finish_non_exhaustive()
        }
    }

    fn power(
        base: BoxedUint,
        exponent: &BoxedUint,
        params: &BoxedMontyParams,
    ) -> Zeroizing<BoxedUint> {
        let base = Zeroizing::new(BoxedMontyForm::new(base, params));
        let powered = Zeroizing::new(base.pow(exponent));
        Zeroizing::new(powered.retrieve())
    }

    impl ActiveKeyExchange for Exchange {
        fn pub_key(&self) -> &[u8] {
            &self.public
        }
        fn group(&self) -> NamedGroup {
            self.group
        }

        fn complete(self: Box<Self>, peer_pub: &[u8], out: &mut Buf) -> Result<(), CryptoError> {
            out.as_mut().zeroize();
            out.clear();
            let invalid = || CryptoError::InvalidPublicKey(self.group);
            if peer_pub.is_empty() || peer_pub.len() > self.params.bits_precision() as usize / 8 {
                return Err(invalid());
            }
            let peer = BoxedUint::from_be_slice(peer_pub, self.params.bits_precision())
                .map_err(|_| invalid())?;
            let one = BoxedUint::one_with_precision(self.params.bits_precision());
            let maximum = self.params.modulus().as_ref().wrapping_sub(&one);
            if peer <= one || peer >= maximum {
                return Err(invalid());
            }
            let shared = power(peer, &self.secret, &self.params);
            let bytes = Zeroizing::new(shared.to_be_bytes());
            // RFC 5246 section 8.1.2 strips leading zero octets from the DH premaster secret.
            let start = bytes.iter().position(|b| *b != 0).ok_or_else(invalid)?;
            out.extend_from_slice(&bytes[start..]);
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn hex(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }

        fn fixed(group: &Ffdhe, secret: &[u8]) -> Box<Exchange> {
            Box::new(Exchange {
                group: group.0,
                params: group.params().unwrap(),
                secret: Zeroizing::new(BoxedUint::from_be_slice(secret, 512).unwrap()),
                public: Buf::new(),
            })
        }

        #[test]
        fn independent_libressl_python_vectors_and_named_parameters() {
            for line in include_str!("ffdhe-vectors.txt").lines() {
                let v: Vec<_> = line.split_whitespace().collect();
                assert_eq!(v.len(), 5);
                let group = match v[0] {
                    "2048" => &FFDHE2048,
                    "4096" => &FFDHE4096,
                    _ => panic!("fixture group"),
                };
                let mut exchange = fixed(group, &hex(v[1]));
                let generator =
                    BoxedUint::from_be_slice(&[2], exchange.params.bits_precision()).unwrap();
                exchange.public.extend_from_slice(
                    &power(generator, &exchange.secret, &exchange.params).to_be_bytes(),
                );
                assert_eq!(exchange.pub_key(), hex(v[2]));
                let mut shared = Buf::new();
                exchange.complete(&hex(v[3]), &mut shared).unwrap();
                assert_eq!(shared.as_ref(), hex(v[4]));
                let p = prime(group.0).unwrap();
                assert_eq!(group_for_parameters(p, &[2]), Some(group.0));
                assert_eq!(group_for_parameters(p, &[3]), None);
                assert_eq!(group_for_parameters(&p[1..], &[2]), None);
                let padded: Vec<_> = [vec![0], p.to_vec()].concat();
                assert_eq!(group_for_parameters(&padded, &[0, 2]), Some(group.0));
            }
        }

        #[test]
        fn fresh_ephemeral_keys_agree_and_invalid_peers_clear_output() {
            for group in [&FFDHE2048, &FFDHE4096] {
                let alice = group.start_exchange(Buf::new()).unwrap();
                let bob = group.start_exchange(Buf::new()).unwrap();
                let ap = alice.pub_key().to_vec();
                let bp = bob.pub_key().to_vec();
                assert_ne!(ap, bp);
                let mut a = Buf::new();
                let mut b = Buf::new();
                alice.complete(&bp, &mut a).unwrap();
                bob.complete(&ap, &mut b).unwrap();
                assert_eq!(a.as_ref(), b.as_ref());
                let p = prime(group.0).unwrap();
                let mut minus_one = p.to_vec();
                *minus_one.last_mut().unwrap() -= 1;
                for peer in [
                    vec![],
                    vec![0],
                    vec![1],
                    minus_one,
                    p.to_vec(),
                    vec![2; p.len() + 1],
                ] {
                    a.extend_from_slice(b"old secret");
                    assert_eq!(
                        fixed(group, &[2]).complete(&peer, &mut a),
                        Err(CryptoError::InvalidPublicKey(group.0))
                    );
                    assert!(a.is_empty());
                }
                fixed(group, &[2]).complete(&[2], &mut a).unwrap();
                assert_eq!(a.as_ref(), &[4], "TLS 1.2 removes DH secret padding");
            }
        }
    }
}
