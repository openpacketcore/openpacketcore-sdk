#![allow(clippy::unwrap_used)]

use super::profile::Ikev2CbcRecoveryProfile;
use super::Ikev2CommittedWindowDomain as Domain;
use crate::recovery::{
    Ikev2CbcEpochInputs, Ikev2CbcEpochRecord as Epoch, Ikev2CommittedWindow as Window,
    Ikev2CommittedWindowRecord as Record, Ikev2SyncDisposition, Ikev2SyncResponderRecord,
};
use crate::{
    Ikev2DhGroup, Ikev2EncryptionAlgorithm as Encryption, Ikev2IntegrityAlgorithm as Integrity,
    Ikev2MessageIdSyncAgreement as Agreement, Ikev2MessageIdSyncMode as Mode,
    Ikev2MessageIdSyncRole as Role, Ikev2MessageIdSyncSa as Sa, Ikev2PrfAlgorithm as Prf,
};
use crate::{
    Ikev2ProtectedPayloadDirection as Direction, Ikev2SaInitCryptoProfile as Profile,
    Ikev2SaInitKeyMaterial as Keys,
};

pub(crate) type Cbc = Ikev2CbcRecoveryProfile;
pub(crate) const DELETE: &[u8] = &[0, 0, 0, 8, 1, 0, 0, 0];
pub(crate) const DIRECTIONS: [Direction; 2] = [
    Direction::InitiatorToResponder,
    Direction::ResponderToInitiator,
];

pub(crate) fn opposite(direction: Direction) -> Direction {
    if direction == DIRECTIONS[0] {
        DIRECTIONS[1]
    } else {
        DIRECTIONS[0]
    }
}

pub(crate) fn profiles() -> impl Iterator<Item = Profile> {
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

pub(crate) struct Fixture {
    pub(crate) profile: Profile,
    pub(crate) keys: Keys,
    pub(crate) epoch: Epoch,
    pub(crate) domain: Domain<Cbc>,
}
impl Fixture {
    pub(crate) fn new(profile: Profile, direction: Direction, tag: u64) -> Self {
        crate::test_support::ensure_ike_crypto();
        Self::admitted(profile, direction, tag)
    }
    pub(crate) fn admitted(profile: Profile, direction: Direction, tag: u64) -> Self {
        let key = |len: usize, byte: u8| {
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
        let epoch = Epoch::fresh(Ikev2CbcEpochInputs {
            initiator_spi: 0x101,
            responder_spi: 0x202,
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
        }
    }
    pub(crate) fn restore(&self, record: &Record<Cbc>) -> Window<Cbc> {
        Window::restore(&self.domain, self.profile, &self.keys, record, &self.epoch).unwrap()
    }
    pub(crate) fn window(&self) -> Window<Cbc> {
        self.restore(&Record::initial(self.domain.clone(), 1, 1))
    }
    pub(crate) fn synced(&self) -> Window<Cbc> {
        self.synced_at(1, 1)
    }
    pub(crate) fn synced_at(&self, send: u32, receive: u32) -> Window<Cbc> {
        let role = if self.epoch.direction() == DIRECTIONS[0] {
            Role::Initiator
        } else {
            Role::Responder
        };
        let agreement =
            Agreement::from_persisted(Sa::new(0x101, 0x202, role).unwrap(), Mode::Negotiated);
        let sync = Ikev2SyncResponderRecord::<Cbc>::from_persisted_cbc(
            agreement,
            // Advertised floors are not proof that intervening requests arrived.
            Some(0),
            Some(0),
            None,
            None,
            Ikev2SyncDisposition::Continue,
        )
        .unwrap();
        self.restore(
            &Record::initial(self.domain.clone(), send, receive)
                .with_sync_state(sync)
                .unwrap(),
        )
    }

    // Adversarial peer fixture only: build admitted/authenticated random-IV-class
    // packets with deterministic IV/padding, never production sending authority.
    pub(crate) fn peer_wire(
        &self,
        id: u32,
        payloads: crate::PayloadChain<'_>,
        padding_byte: u8,
    ) -> bytes::Bytes {
        self.peer_packet(id, false, payloads, padding_byte)
    }

    pub(crate) fn peer_packet(
        &self,
        id: u32,
        response: bool,
        payloads: crate::PayloadChain<'_>,
        padding_byte: u8,
    ) -> bytes::Bytes {
        use crate::{
            crypto_module::{execute_cbc_encrypt, execute_integrity_checksum},
            encode_header, Header, HeaderFlags, Ikev2ExchangeKind, PayloadType,
        };
        let padding = crate::ikev2_aes_cbc_padding_len(payloads.bytes().len()).unwrap();
        let mut plaintext = payloads.bytes().to_vec();
        plaintext.extend(std::iter::repeat_n(padding_byte, usize::from(padding)));
        plaintext.push(padding);
        let iv = [0x81; 16];
        let (e, a) = if self.epoch.direction() == Direction::InitiatorToResponder {
            (self.keys.sk_er(), self.keys.sk_ar())
        } else {
            (self.keys.sk_ei(), self.keys.sk_ai())
        };
        let ciphertext =
            execute_cbc_encrypt(self.profile.encryption(), e, &iv, &plaintext).unwrap();
        let length = 32 + 16 + ciphertext.len() + self.profile.integrity_icv_len();
        let mut header = Header::new(
            self.epoch.initiator_spi(),
            self.epoch.responder_spi(),
            PayloadType::Encrypted,
            Ikev2ExchangeKind::Informational.as_u8(),
            HeaderFlags::from_bits(
                self.epoch.direction() == Direction::ResponderToInitiator,
                response,
                false,
            ),
            id,
        );
        header.length = u32::try_from(length).unwrap();
        let mut wire = bytes::BytesMut::new();
        encode_header(&header, &mut wire, opc_protocol::EncodeContext::default()).unwrap();
        wire.extend_from_slice(&[payloads.first_payload().as_u8(), 0]);
        wire.extend_from_slice(&u16::try_from(length - 28).unwrap().to_be_bytes());
        wire.extend_from_slice(&iv);
        wire.extend_from_slice(&ciphertext);
        let tag =
            execute_integrity_checksum(self.profile.integrity().unwrap(), a, &wire, &[]).unwrap();
        wire.extend_from_slice(&tag);
        wire.freeze()
    }

    pub(crate) fn request(
        &self,
        id: u32,
        padding_byte: u8,
    ) -> super::Ikev2AuthenticatedOrdinary<Cbc> {
        let wire = self.peer_wire(
            id,
            crate::PayloadChain::new(crate::PayloadType::NoNext, &[]),
            padding_byte,
        );
        super::packet::open(&self.domain, self.profile, &self.keys, &wire, true).unwrap()
    }
}
