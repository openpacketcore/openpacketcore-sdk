use aes_gcm_siv::{
    aead::{AeadInOut, KeyInit},
    Aes256GcmSiv,
};
use hkdf::Hkdf;
use rand::{rngs::SysRng, TryRng};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{
    codec::{Decoder, Encoder},
    InventoryError,
};
use crate::durable_object::{authenticate_domain, CanonicalMacKey};

const MAGIC: [u8; 8] = *b"OPCXCI00";
pub(super) const HEADER_BYTES: usize = 118;
pub(super) const TAG_BYTES: usize = 16;
pub(super) const ENVELOPE_BYTES: usize = HEADER_BYTES + TAG_BYTES;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum NodeKind {
    Root,
    Branch,
    Leaf,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct NodeContext {
    pub(super) namespace: [u8; 40],
    pub(super) incarnation: [u8; 16],
    pub(super) device: u64,
    pub(super) inode: u64,
    pub(super) generation: u64,
    pub(super) revision: u64,
    pub(super) kind: NodeKind,
    pub(super) position: u32,
    pub(super) slot: u8,
}

pub(super) struct InventoryKey(Zeroizing<[u8; 32]>);

impl InventoryKey {
    pub(super) fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn derive(
        &self,
        context: NodeContext,
        domain: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, InventoryError> {
        let mut info = Encoder::new(128)?;
        info.bytes(&context.namespace)?;
        info.bytes(&context.incarnation)?;
        info.u64(context.device)?;
        info.u64(context.inode)?;
        let mut key = Zeroizing::new([0_u8; 32]);
        Hkdf::<Sha256>::new(Some(domain), &self.0[..])
            .expand(&info.finish(), &mut key[..])
            .map_err(|_| InventoryError::Authentication)?;
        Ok(key)
    }

    pub(super) fn locator(
        &self,
        context: NodeContext,
        domain: &[u8],
        body: &[u8],
    ) -> Result<[u8; 32], InventoryError> {
        let key = self.derive(context, b"opc-xfrm-cleanup-inventory/locator/v0")?;
        Ok(authenticate_domain(
            CanonicalMacKey::new(&key),
            domain,
            body,
        ))
    }
}

fn validate_context(context: NodeContext) -> Result<(), InventoryError> {
    if context.generation == 0
        || context.revision == 0
        || context.slot > 1
        || match context.kind {
            NodeKind::Root => context.position != 0 || context.slot != 0,
            NodeKind::Branch => context.position >= 256,
            NodeKind::Leaf => context.position >= 65536,
        }
    {
        return Err(InventoryError::Malformed);
    }
    Ok(())
}

fn encode_header(
    context: NodeContext,
    length: usize,
    nonce: [u8; 12],
) -> Result<Zeroizing<Vec<u8>>, InventoryError> {
    validate_context(context)?;
    let mut encoder = Encoder::new(HEADER_BYTES)?;
    encoder.bytes(&MAGIC)?;
    encoder.bytes(&context.namespace)?;
    encoder.bytes(&context.incarnation)?;
    encoder.u64(context.device)?;
    encoder.u64(context.inode)?;
    encoder.u64(context.generation)?;
    encoder.u64(context.revision)?;
    encoder.u8(match context.kind {
        NodeKind::Root => 0,
        NodeKind::Branch => 1,
        NodeKind::Leaf => 2,
    })?;
    encoder.u32(context.position)?;
    encoder.u8(context.slot)?;
    encoder.u32(u32::try_from(length).map_err(|_| InventoryError::Capacity)?)?;
    encoder.bytes(&nonce)?;
    Ok(encoder.finish())
}

pub(super) fn decode_header(
    frame: &[u8],
    byte_limit: usize,
) -> Result<(NodeContext, usize, [u8; 12]), InventoryError> {
    if frame.len() > byte_limit || frame.len() < ENVELOPE_BYTES {
        return Err(InventoryError::Malformed);
    }
    let mut decoder = Decoder::new(&frame[..HEADER_BYTES], HEADER_BYTES)?;
    if decoder.array::<8>()? != MAGIC {
        return Err(InventoryError::Malformed);
    }
    let namespace = decoder.array()?;
    let incarnation = decoder.array()?;
    let device = decoder.u64()?;
    let inode = decoder.u64()?;
    let generation = decoder.u64()?;
    let revision = decoder.u64()?;
    let kind = match decoder.u8()? {
        0 => NodeKind::Root,
        1 => NodeKind::Branch,
        2 => NodeKind::Leaf,
        _ => return Err(InventoryError::Malformed),
    };
    let position = decoder.u32()?;
    let slot = decoder.u8()?;
    let length = usize::try_from(decoder.u32()?).map_err(|_| InventoryError::Capacity)?;
    let nonce = decoder.array()?;
    decoder.finish()?;
    if length.checked_add(ENVELOPE_BYTES) != Some(frame.len()) {
        return Err(InventoryError::Malformed);
    }
    let context = NodeContext {
        namespace,
        incarnation,
        device,
        inode,
        generation,
        revision,
        kind,
        position,
        slot,
    };
    validate_context(context)?;
    Ok((context, length, nonce))
}

pub(super) fn ciphertext_digest(frame: &[u8]) -> [u8; 32] {
    Sha256::digest(frame).into()
}

pub(super) fn seal_node(
    key: &InventoryKey,
    context: NodeContext,
    payload: &[u8],
    byte_limit: usize,
) -> Result<Vec<u8>, InventoryError> {
    let length = payload
        .len()
        .checked_add(ENVELOPE_BYTES)
        .ok_or(InventoryError::Capacity)?;
    if length > byte_limit {
        return Err(InventoryError::Capacity);
    }
    let mut nonce = [0_u8; 12];
    SysRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| InventoryError::Unavailable)?;
    let header = encode_header(context, payload.len(), nonce)?;
    let derived = key.derive(context, b"opc-xfrm-cleanup-inventory/encryption/v0")?;
    let cipher = Aes256GcmSiv::new((&*derived).into());
    let mut frame = Zeroizing::new(Vec::new());
    frame
        .try_reserve_exact(length)
        .map_err(|_| InventoryError::Allocation)?;
    frame.extend_from_slice(&header);
    frame.extend_from_slice(payload);
    let (aad, ciphertext) = frame.split_at_mut(HEADER_BYTES);
    let tag = cipher
        .encrypt_inout_detached((&nonce).into(), aad, ciphertext.into())
        .map_err(|_| InventoryError::Authentication)?;
    frame.extend_from_slice(&tag);
    Ok(std::mem::take(&mut *frame))
}

pub(super) fn open_node(
    key: &InventoryKey,
    context: NodeContext,
    frame: &[u8],
    byte_limit: usize,
) -> Result<Zeroizing<Vec<u8>>, InventoryError> {
    let (observed, length, nonce) = decode_header(frame, byte_limit)?;
    if observed != context {
        return Err(InventoryError::WrongBinding);
    }
    let derived = key.derive(context, b"opc-xfrm-cleanup-inventory/encryption/v0")?;
    let cipher = Aes256GcmSiv::new((&*derived).into());
    let mut plaintext = Zeroizing::new(Vec::new());
    plaintext
        .try_reserve_exact(length)
        .map_err(|_| InventoryError::Allocation)?;
    plaintext.extend_from_slice(&frame[HEADER_BYTES..HEADER_BYTES + length]);
    let tag = frame[HEADER_BYTES + length..]
        .try_into()
        .map_err(|_| InventoryError::Malformed)?;
    cipher
        .decrypt_inout_detached(
            (&nonce).into(),
            &frame[..HEADER_BYTES],
            plaintext.as_mut_slice().into(),
            tag,
        )
        .map_err(|_| InventoryError::Authentication)?;
    Ok(plaintext)
}
