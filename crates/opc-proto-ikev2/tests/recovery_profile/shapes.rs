//! An authenticated unsupported fragment needs a distinguishable local refusal.

use opc_proto_ikev2::{
    open_protected_payloads, recovery::Ikev2WindowError as Error,
    Ikev2ProtectedPayloadDirection as Direction, Ikev2SaInitCryptoProfile as Profile,
    Ikev2SaInitKeyMaterial as Keys, Ikev2SaInitProtectedPayloadProvider as Provider, Message,
    PayloadChain, PayloadType, ProtectedPayloadKind,
};
use opc_protocol::{BorrowDecode, DecodeContext};

use super::wire::Wire;
use crate::canonical_fixtures::{opposite, Fixture, ALGORITHMS, DIRECTIONS};

fn check_shapes(
    profile: Profile,
    keys: &Keys,
    spis: (u64, u64),
    direction: Direction,
    open: impl Fn(&[u8]) -> Result<(), Error>,
) {
    let peer = Wire::new(profile, keys, spis, opposite(direction));
    for exchange in 35..=37 {
        for response in [false, true] {
            // Neither fragment is a complete inner payload chain: classify only
            // after authentication, before ordinary cleartext-chain validation.
            for (number, first, chunk) in [
                (1, PayloadType::Delete, &[0, 0, 0, 12, 3][..]),
                (2, PayloadType::NoNext, &[4, 0, 1, 1, 2, 3, 4][..]),
            ] {
                let wire = peer.seal_fragment(
                    0,
                    response,
                    exchange,
                    (number, 2),
                    PayloadChain::new(first, chunk),
                );
                let (_, decoded) = Message::decode(&wire, DecodeContext::default()).unwrap();
                let provider = Provider::new(profile, keys, opposite(direction));
                let opened =
                    open_protected_payloads(&decoded, &wire, DecodeContext::default(), &provider)
                        .unwrap();
                assert_eq!(opened.len(), 1);
                assert_eq!(opened[0].kind, ProtectedPayloadKind::EncryptedFragment);
                assert_eq!(opened[0].cleartext.as_ref(), chunk);
                assert_eq!(
                    open(&wire),
                    Err(Error::UnsupportedShape),
                    "authenticated SKF must not be indistinguishable from noise"
                );
            }
        }
    }
}

fn check_noise(
    profile: Profile,
    keys: &Keys,
    spis: (u64, u64),
    direction: Direction,
    open: impl Fn(&[u8]) -> Result<(), Error>,
) {
    let peer = Wire::new(profile, keys, spis, opposite(direction));
    let wire = peer.seal_fragment(
        0,
        false,
        37,
        (1, 2),
        PayloadChain::new(PayloadType::Delete, &[0, 0, 0, 12, 3]),
    );
    for changed in [0, 8, 19, wire.len() - 1] {
        let mut invalid = wire.to_vec();
        invalid[changed] ^= 8;
        assert_eq!(open(&invalid), Err(Error::Drop));
    }
    for spis in [(spis.0 ^ 1, spis.1), (spis.0, spis.1 ^ 1)] {
        let foreign = Wire::new(profile, keys, spis, opposite(direction));
        let packet = foreign.seal_fragment(
            0,
            false,
            37,
            (1, 2),
            PayloadChain::new(PayloadType::Delete, &[0, 0, 0, 12, 3]),
        );
        assert_eq!(open(&packet), Err(Error::Drop));
    }
    let wrong_exchange = peer.seal_fragment(
        0,
        false,
        34,
        (1, 2),
        PayloadChain::new(PayloadType::Delete, &[0, 0, 0, 12, 3]),
    );
    assert_eq!(open(&wrong_exchange), Err(Error::Drop));
}

#[test]
fn authenticated_partial_skf_has_a_typed_refusal() {
    crate::support::ensure_ike_crypto();
    for (algorithm, encryption) in ALGORITHMS.into_iter().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            let f = Fixture::new(
                80_000 + (algorithm * 2 + role) as u64,
                encryption,
                direction,
            );
            let before = f.window.record().clone();
            check_shapes(f.profile, &f.keys, f.spis, direction, |wire| {
                f.window.open_peer(f.profile, &f.keys, wire).map(|_| ())
            });
            assert_eq!(f.window.record(), &before);
        }
    }
}

#[test]
fn unauthenticated_or_foreign_skf_stays_an_ordinary_drop() {
    crate::support::ensure_ike_crypto();
    for (algorithm, encryption) in ALGORITHMS.into_iter().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            let f = Fixture::new(
                80_100 + (algorithm * 2 + role) as u64,
                encryption,
                direction,
            );
            let before = f.window.record().clone();
            check_noise(f.profile, &f.keys, f.spis, direction, |wire| {
                f.window.open_peer(f.profile, &f.keys, wire).map(|_| ())
            });
            assert_eq!(f.window.record(), &before);
        }
    }
}

#[test]
fn all_cbc_profiles_distinguish_authenticated_partial_skf_from_noise() {
    assert_eq!(super::cbc::profiles().count(), 48);
    for (algorithm, profile) in super::cbc::profiles().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            let f = super::cbc::Fixture::new(
                profile,
                direction,
                80_200 + (algorithm * 2 + role) as u64,
            );
            let window = f.window();
            let before = window.record().clone();
            let open = |wire: &[u8]| window.open_peer(profile, &f.keys, wire).map(|_| ());
            check_shapes(profile, &f.keys, f.spis, direction, open);
            check_noise(profile, &f.keys, f.spis, direction, open);
            assert_eq!(window.record(), &before);
        }
    }
}
