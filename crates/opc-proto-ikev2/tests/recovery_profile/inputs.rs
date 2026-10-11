//! Fresh test row inputs; constructing data grants no runtime or IV authority.

use super::{row::Row, store::RowKey};
use opc_proto_ikev2::{
    Ikev2MessageIdSyncMode as Mode, Ikev2ProtectedPayloadDirection as Direction,
    Ikev2SaInitCryptoProfile as Profile, Ikev2SaInitKeyMaterial as Keys,
};

pub fn profiles() -> impl Iterator<Item = Profile> {
    crate::canonical_fixtures::ALGORITHMS
        .into_iter()
        .map(crate::canonical_fixtures::profile)
        .chain(super::cbc::profiles())
}

pub fn fresh(tag: u64, profile: Profile, direction: Direction, mode: Mode) -> Row {
    super::module::install();
    let key = |len, byte| {
        let mut value = vec![byte; len];
        if len >= 8 {
            value[..8].copy_from_slice(&tag.to_be_bytes());
        }
        value
    };
    let n = profile.prf().output_len();
    let a = profile.integrity_key_len();
    let e = profile.encryption().key_material_len();
    let keys = Keys::from_established_keys(
        profile,
        false,
        &key(n, 1),
        &key(a, 2),
        &key(a, 3),
        &key(e, 4),
        &key(e, 5),
        &key(n, 6),
        &key(n, 7),
    )
    .unwrap();
    Row::fresh(
        RowKey(tag),
        7,
        profile,
        keys,
        crate::canonical_fixtures::SPIS,
        direction,
        mode,
    )
}
