//! Public-API inputs for the complete CBC encryption/integrity/PRF matrix.

use opc_proto_ikev2::{
    recovery::{
        Ikev2CbcEpochInputs, Ikev2CbcEpochRecord as Epoch, Ikev2CbcRecoveryProfile as Cbc,
        Ikev2CommittedWindow as Window, Ikev2CommittedWindowDomain as Domain,
        Ikev2CommittedWindowRecord as Record,
    },
    Ikev2DhGroup, Ikev2EncryptionAlgorithm as Encryption, Ikev2IntegrityAlgorithm as Integrity,
    Ikev2PrfAlgorithm as Prf, Ikev2ProtectedPayloadDirection as Direction,
    Ikev2SaInitCryptoProfile as Profile, Ikev2SaInitKeyMaterial as Keys,
};

pub fn profiles() -> impl Iterator<Item = Profile> {
    [
        Encryption::AesCbc128,
        Encryption::AesCbc192,
        Encryption::AesCbc256,
    ]
    .into_iter()
    .flat_map(|encryption| {
        [2, 12, 13, 14].into_iter().flat_map(move |integrity| {
            [2, 5, 6, 7].into_iter().map(move |prf| {
                Profile::new_encrypt_then_mac(
                    Prf::from_transform_id(prf).unwrap(),
                    Ikev2DhGroup::Modp2048,
                    encryption,
                    Integrity::from_transform_id(integrity).unwrap(),
                )
                .unwrap()
            })
        })
    })
}

pub struct Fixture {
    pub profile: Profile,
    pub keys: Keys,
    pub epoch: Epoch,
    pub domain: Domain<Cbc>,
    pub spis: (u64, u64),
}

impl Fixture {
    pub fn new(profile: Profile, direction: Direction, tag: u64) -> Self {
        crate::support::ensure_ike_crypto();
        let key = |len, byte| {
            let mut value = vec![byte; len];
            value[..8].copy_from_slice(&tag.to_be_bytes());
            value
        };
        let n = profile.prf().output_len();
        let e = profile.encryption().encryption_key_len();
        let a = profile.integrity_key_len();
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
        let spis = (0x0102_0304_0506_0708, 0x1112_1314_1516_1718);
        let epoch = Epoch::fresh(Ikev2CbcEpochInputs {
            initiator_spi: spis.0,
            responder_spi: spis.1,
            sending_direction: direction,
            profile,
            keys: &keys,
        })
        .unwrap();
        let domain = Domain::from_cbc_epoch(&epoch);
        Self {
            profile,
            keys,
            epoch,
            domain,
            spis,
        }
    }

    pub fn window(&self) -> Window<Cbc> {
        Window::<Cbc>::restore(
            &self.domain,
            self.profile,
            &self.keys,
            &Record::initial(self.domain.clone(), 0, 0),
            &self.epoch,
        )
        .unwrap()
    }
}
