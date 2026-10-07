#![allow(
    dead_code,
    reason = "shared by independent canonical integration targets"
)]

use bytes::Bytes;
use opc_proto_ikev2::{
    recovery::{
        Ikev2AuthenticatedOrdinary as Request, Ikev2CommittedWindow as Window,
        Ikev2CommittedWindowDomain as Domain, Ikev2CommittedWindowRecord as WindowRecord,
    },
    seal_ikev2_sa_init_protected_payload, Ikev2AesGcmEpochInputs as Inputs,
    Ikev2AesGcmIvAllocator as Allocator, Ikev2AesGcmIvLimits as Limits,
    Ikev2AesGcmIvPurpose as Purpose, Ikev2AesGcmIvRecord as IvRecord, Ikev2DhGroup,
    Ikev2EncryptionAlgorithm as Encryption, Ikev2PrfAlgorithm,
    Ikev2ProtectedPayloadDirection as Direction, Ikev2SaInitCryptoProfile as Profile,
    Ikev2SaInitKeyMaterial as Keys, PayloadChain, PayloadType, ProtectedPayloadKind,
    ProtectedPayloadSealContext,
};

pub const ALGORITHMS: [Encryption; 3] = [
    Encryption::AesGcm16_128,
    Encryption::AesGcm16_192,
    Encryption::AesGcm16_256,
];
pub const DIRECTIONS: [Direction; 2] = [
    Direction::InitiatorToResponder,
    Direction::ResponderToInitiator,
];
pub const SPIS: (u64, u64) = (0x0102_0304_0506_0708, 0x1112_1314_1516_1718);
pub const DELETE: &[u8] = &[0, 0, 0, 8, 1, 0, 0, 0];

pub fn empty() -> PayloadChain<'static> {
    PayloadChain::new(PayloadType::NoNext, &[])
}

pub fn delete() -> PayloadChain<'static> {
    PayloadChain::new(PayloadType::Delete, DELETE)
}

pub fn opposite(direction: Direction) -> Direction {
    if direction == DIRECTIONS[0] {
        DIRECTIONS[1]
    } else {
        DIRECTIONS[0]
    }
}

pub fn profile(encryption: Encryption) -> Profile {
    Profile::new_aead(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2DhGroup::Ecp256,
        encryption,
    )
    .unwrap()
}

pub fn key_material(profile: Profile, tag: u64) -> Keys {
    let len = profile.encryption().key_material_len() - 4;
    let mut ei: Vec<u8> = (0..u8::try_from(len).unwrap()).collect();
    let mut er: Vec<u8> = (128..128 + u8::try_from(len).unwrap()).collect();
    // Tag zero is the independently pinned public vector key pair. Other tags
    // isolate tests in the process-wide, deliberately non-resettable ledger.
    for (index, byte) in tag.to_be_bytes().iter().enumerate() {
        ei[index] ^= byte;
        er[index] ^= byte;
    }
    ei.extend_from_slice(&[1, 2, 3, 4]);
    er.extend_from_slice(&[0xa1, 0xa2, 0xa3, 0xa4]);
    Keys::from_established_keys(
        profile,
        false,
        &[0x11; 32],
        &[],
        &[],
        &ei,
        &er,
        &[0x22; 32],
        &[0x33; 32],
    )
    .unwrap()
}

pub struct Fixture {
    pub profile: Profile,
    pub keys: Keys,
    pub direction: Direction,
    pub spis: (u64, u64),
    pub iv: IvRecord,
    pub allocator: Allocator,
    pub window: Window,
}

impl Fixture {
    pub fn new(tag: u64, algorithm: Encryption, direction: Direction) -> Self {
        let profile = profile(algorithm);
        let keys = key_material(profile, tag);
        Self::from_keys(profile, keys, direction, SPIS)
    }

    pub fn from_keys(profile: Profile, keys: Keys, direction: Direction, spis: (u64, u64)) -> Self {
        let mut allocator = Allocator::fresh(
            Inputs {
                initiator_spi: spis.0,
                responder_spi: spis.1,
                sending_direction: direction,
                profile,
                keys: &keys,
            },
            Limits::new(1024, 2, 1, 2).unwrap(),
        )
        .unwrap();
        let prepared = allocator.prepare(64, Purpose::Ordinary).unwrap();
        let iv = prepared.record().clone();
        prepared.activate_after_commit(&iv).unwrap();
        let domain = Domain::from_iv_record(&iv);
        let record = WindowRecord::initial(domain.clone(), 0, 0);
        let window = Window::restore(&domain, profile, &keys, &record, &iv).unwrap();
        Self {
            profile,
            keys,
            direction,
            spis,
            iv,
            allocator,
            window,
        }
    }

    pub fn from_persisted_keys(
        profile: Profile,
        keys: Keys,
        direction: Direction,
        spis: (u64, u64),
        end: u64,
    ) -> Self {
        let iv = IvRecord::from_persisted(
            Inputs {
                initiator_spi: spis.0,
                responder_spi: spis.1,
                sending_direction: direction,
                profile,
                keys: &keys,
            },
            Limits::new(1024, 2, 1, 2).unwrap(),
            end,
            Some(1),
        )
        .unwrap();
        let allocator = Allocator::restore(iv.domain(), &iv).unwrap();
        let domain = Domain::from_iv_record(&iv);
        let record = WindowRecord::initial(domain.clone(), 0, 0);
        let window = Window::restore(&domain, profile, &keys, &record, &iv).unwrap();
        Self {
            profile,
            keys,
            direction,
            spis,
            iv,
            allocator,
            window,
        }
    }

    pub fn inputs(&self) -> Inputs<'_> {
        Inputs {
            initiator_spi: self.spis.0,
            responder_spi: self.spis.1,
            sending_direction: self.direction,
            profile: self.profile,
            keys: &self.keys,
        }
    }

    pub fn stored(&self, marker: Option<u8>, end: u64) -> IvRecord {
        IvRecord::from_persisted(self.inputs(), self.iv.limits(), end, marker).unwrap()
    }

    pub fn restore(&self, iv: &IvRecord) -> Window {
        let domain = Domain::from_iv_record(iv);
        Window::restore(
            &domain,
            self.profile,
            &self.keys,
            &WindowRecord::initial(domain.clone(), 0, 0),
            iv,
        )
        .unwrap()
    }

    pub fn request(&self, id: u32) -> Request {
        let wire = self.peer(id, false, 37, empty(), 0, 0x1000 + u64::from(id));
        self.window
            .open_peer(self.profile, &self.keys, &wire)
            .unwrap()
    }

    pub fn peer(
        &self,
        id: u32,
        response: bool,
        exchange: u8,
        payload: PayloadChain<'_>,
        padding: u8,
        iv: u64,
    ) -> Bytes {
        self.packet(
            opposite(self.direction),
            id,
            response,
            exchange,
            payload,
            padding,
            iv,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "independent wire-fixture dimensions"
    )]
    pub fn packet(
        &self,
        direction: Direction,
        id: u32,
        response: bool,
        exchange: u8,
        payload: PayloadChain<'_>,
        padding: u8,
        iv: u64,
    ) -> Bytes {
        let mut aad = vec![0; 32];
        aad[..8].copy_from_slice(&self.spis.0.to_be_bytes());
        aad[8..16].copy_from_slice(&self.spis.1.to_be_bytes());
        aad[16] = 46;
        aad[17] = 0x20;
        aad[18] = exchange;
        aad[19] =
            (if direction == DIRECTIONS[0] { 8 } else { 0 }) | (if response { 0x20 } else { 0 });
        aad[20..24].copy_from_slice(&id.to_be_bytes());
        let length = 57 + u32::try_from(payload.bytes().len()).unwrap() + u32::from(padding);
        aad[24..28].copy_from_slice(&length.to_be_bytes());
        aad[28] = payload.first_payload().as_u8();
        aad[30..32].copy_from_slice(&u16::try_from(length - 28).unwrap().to_be_bytes());
        let body = seal_ikev2_sa_init_protected_payload(
            self.profile,
            &self.keys,
            direction,
            ProtectedPayloadSealContext {
                kind: ProtectedPayloadKind::Encrypted,
                message_prefix: &aad,
            },
            payload.bytes(),
            padding,
            iv.to_be_bytes(),
        )
        .unwrap();
        aad.extend_from_slice(&body);
        aad.into()
    }
}

pub fn hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}
