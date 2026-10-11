//! Shared packet/crypto adapter only: no window, recovery or sync-counter code.

use std::cell::Cell;

use bytes::Bytes;
use opc_proto_ikev2::{
    ikev2_aes_cbc_protected_body_len, open_protected_payloads,
    seal_ikev2_sa_init_aes_cbc_protected_payload_with_iv_for_test_vector,
    seal_ikev2_sa_init_protected_payload, Header, Ikev2ProtectedPayloadDirection as Direction,
    Ikev2SaInitCryptoProfile as Profile, Ikev2SaInitKeyMaterial as Keys,
    Ikev2SaInitProtectedPayloadProvider as Provider, Message, PayloadChain, PayloadType,
    ProtectedPayloadKind, ProtectedPayloadSealContext,
};
use opc_protocol::{BorrowDecode, DecodeContext};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    AuthenticationOrFraming,
    Binding,
    CryptoModule(opc_proto_ikev2::Ikev2CryptoModuleError),
}

pub struct Packet {
    pub header: Header,
    pub first: PayloadType,
    pub body: Bytes,
    pub wire: Bytes,
}

/// Cipher/framing adapter. The peer state machine has no cipher dependency.
pub struct Wire<'a> {
    profile: Profile,
    keys: &'a Keys,
    spis: (u64, u64),
    sending: Direction,
    next_iv: Cell<u64>,
}

impl<'a> Wire<'a> {
    pub fn new(profile: Profile, keys: &'a Keys, spis: (u64, u64), sending: Direction) -> Self {
        Self {
            profile,
            keys,
            spis,
            sending,
            // Independent peer IVs; never borrow the SDK window's allocator.
            next_iv: Cell::new(1 << 40),
        }
    }

    pub fn seal(&self, id: u32, response: bool, exchange: u8, payload: PayloadChain<'_>) -> Bytes {
        self.seal_frame(id, response, exchange, payload, None)
    }

    /// Fault input for the unfragmented profile, using only the generic cipher.
    pub fn seal_fragment(
        &self,
        id: u32,
        response: bool,
        exchange: u8,
        fragment: (u16, u16),
        payload: PayloadChain<'_>,
    ) -> Bytes {
        self.seal_frame(id, response, exchange, payload, Some(fragment))
    }

    fn seal_frame(
        &self,
        id: u32,
        response: bool,
        exchange: u8,
        payload: PayloadChain<'_>,
        fragment: Option<(u16, u16)>,
    ) -> Bytes {
        let mut prefix = vec![0; if fragment.is_some() { 36 } else { 32 }];
        prefix[..8].copy_from_slice(&self.spis.0.to_be_bytes());
        prefix[8..16].copy_from_slice(&self.spis.1.to_be_bytes());
        prefix[16] = if fragment.is_some() { 53 } else { 46 };
        prefix[17] = 0x20;
        prefix[18] = exchange;
        prefix[19] = (u8::from(self.sending == Direction::InitiatorToResponder) * 8)
            | (u8::from(response) * 32);
        prefix[20..24].copy_from_slice(&id.to_be_bytes());
        let body_len = if self.profile.encryption().is_aead() {
            25 + payload.bytes().len()
        } else {
            ikev2_aes_cbc_protected_body_len(self.profile, payload.bytes().len()).unwrap()
        };
        let length = u32::try_from(prefix.len() + body_len).unwrap();
        prefix[24..28].copy_from_slice(&length.to_be_bytes());
        prefix[28] = payload.first_payload().as_u8();
        prefix[30..32].copy_from_slice(&u16::try_from(length - 28).unwrap().to_be_bytes());
        if let Some((number, total)) = fragment {
            prefix[32..34].copy_from_slice(&number.to_be_bytes());
            prefix[34..36].copy_from_slice(&total.to_be_bytes());
        }
        let iv = self.next_iv.get();
        self.next_iv.set(iv.checked_add(1).unwrap());
        let context = ProtectedPayloadSealContext {
            kind: if fragment.is_some() {
                ProtectedPayloadKind::EncryptedFragment
            } else {
                ProtectedPayloadKind::Encrypted
            },
            message_prefix: &prefix,
        };
        let protected = if self.profile.encryption().is_aead() {
            seal_ikev2_sa_init_protected_payload(
                self.profile,
                self.keys,
                self.sending,
                context,
                payload.bytes(),
                0,
                iv.to_be_bytes(),
            )
        } else {
            // Deterministic peer fault input only. The SDK under test uses its
            // production random-IV CBC sealing path.
            let mut cbc_iv = [0xa5; 16];
            cbc_iv[8..].copy_from_slice(&iv.to_be_bytes());
            seal_ikev2_sa_init_aes_cbc_protected_payload_with_iv_for_test_vector(
                self.profile,
                self.keys,
                self.sending,
                context,
                payload.bytes(),
                cbc_iv,
            )
        }
        .unwrap();
        prefix.extend_from_slice(&protected);
        prefix.into()
    }

    pub fn open(&self, wire: &[u8]) -> Result<Packet, WireError> {
        let (rest, message) = Message::decode(wire, DecodeContext::default())
            .map_err(|_| WireError::AuthenticationOrFraming)?;
        let header = &message.header;
        if !rest.is_empty() || header.next_payload != 46 || !matches!(header.exchange_type, 35..=37)
        {
            return Err(WireError::AuthenticationOrFraming);
        }
        if (header.initiator_spi, header.responder_spi) != self.spis
            || header.flags.initiator() == (self.sending == Direction::InitiatorToResponder)
        {
            return Err(WireError::Binding);
        }
        let receiving = match self.sending {
            Direction::InitiatorToResponder => Direction::ResponderToInitiator,
            Direction::ResponderToInitiator => Direction::InitiatorToResponder,
        };
        let provider = Provider::new(self.profile, self.keys, receiving);
        let opened = open_protected_payloads(&message, wire, DecodeContext::default(), &provider)
            .map_err(|error| match error {
            opc_proto_ikev2::ProtectedPayloadOpenError::ProviderRejected(failure) => {
                match failure.provider_error {
                    opc_proto_ikev2::Ikev2ProtectedPayloadCryptoError::CryptoModuleFailure {
                        error,
                    } => WireError::CryptoModule(error),
                    _ => WireError::AuthenticationOrFraming,
                }
            }
            _ => WireError::AuthenticationOrFraming,
        })?;
        if opened.len() != 1 {
            return Err(WireError::AuthenticationOrFraming);
        }
        let opened = &opened[0];
        PayloadChain::new(opened.first_inner_payload, &opened.cleartext)
            .validate(DecodeContext::default())
            .map_err(|_| WireError::AuthenticationOrFraming)?;
        Ok(Packet {
            header: header.clone(),
            first: opened.first_inner_payload,
            body: Bytes::copy_from_slice(&opened.cleartext),
            wire: Bytes::copy_from_slice(wire),
        })
    }
}
