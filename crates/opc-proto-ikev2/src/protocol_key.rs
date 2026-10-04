//! Volatile, consume-once K_N3IWF custody for one pending IKE_AUTH operation.
//!
//! The caller owns association identity, generation assignment and admission
//! of the AMF handoff. This module binds a zeroizing import to an opaque local
//! association, a monotonically increasing generation and operation identifier,
//! and one negotiated IKE profile. No key derivation hierarchy or subscriber
//! authentication decision is made here.
//!
//! One successful import permits one attempt to compute both directional AUTH
//! MICs. This is one logical use of the MSK for RFC 7296 section 2.15; it lets a
//! caller verify the peer and construct its own AUTH without retaining the MSK.
//! Every PRF uses the existing admitted IKE module, with no caller callback or
//! byte-export adapter. The output contains only transcript-specific AUTH data.
//!
//! Release, generation replacement, operation cancellation and RAII drop retire
//! pending material. Synchronous consumption and retirement share one lock:
//! retirement returning guarantees that no later key use can start. An already
//! executing provider call finishes first. Providers must obey the existing
//! synchronous, non-reentrant IKE operation contract. A poisoned lock fails
//! closed and clears any remaining material.
//!
//! This is API-level non-exportability over zeroizing process memory, not an
//! HSM or sealed-storage claim. `opc-key::AdmittedKeyCustody` and
//! `RemoteSealProvider` seal purpose-bound envelopes; they do not currently
//! offer atomic, association-bound protocol-key consumption. Sealing, restore,
//! serialization and unsealed caching are therefore unsupported here. Existing
//! envelope `KeyHandle` values cannot be converted into protocol handles.
//!
//! @spec 3GPP TS33501 V18.12.0 6.2.2.1, 7.2.1; IETF RFC7296 2.15, 2.16
//! @req REQ-3GPP-TS33501-N3IWF-IKE-MSK-001
//! @conformance synthetic consume-once software-custody subset

use std::{
    error::Error,
    fmt,
    num::NonZeroU64,
    sync::{Arc, Mutex, MutexGuard},
};

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    crypto_module::check_prf_admission,
    ike_auth::{compute_ike_auth_shared_key_mic, validate_signed_octets},
    Ikev2AuthenticationPayload, Ikev2IkeAuthPeer, Ikev2IkeAuthSignedOctets,
    Ikev2SaInitCryptoProfile, Ikev2SaInitKeyMaterial, IKEV2_AUTH_METHOD_SHARED_KEY_MIC,
};

/// K_N3IWF width carried in the NGAP Security Key IE, in octets.
pub const N3IWF_KEY_LEN: usize = 32;

/// Purpose declared by the caller at the handoff boundary.
///
/// This is SDK metadata, not a wire tag. Unrecognized handoff purposes must be
/// mapped to `Unsupported`, never silently relabelled as K_N3IWF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2ProtocolKeyPurpose {
    /// K_N3IWF used as the IKE MSK for the pending EAP-based IKE_AUTH exchange.
    N3iwfMsk,
    /// Any purpose outside this module's supported handoff profile.
    Unsupported,
}

/// Bounded, value-free custody or AUTH refusal.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2ProtocolKeyError {
    /// The association has been released or its owner dropped.
    Released,
    /// The requested generation is stale, mismatched or non-increasing.
    GenerationMismatch,
    /// The operation belongs to another association or pending operation.
    OperationMismatch,
    /// The identifier has already been used in this association generation.
    OperationReused,
    /// Another operation still owns the single pending slot.
    OperationPending,
    /// The operation or handle was retired, consumed, or already imported.
    Retired,
    /// The caller declared a purpose other than K_N3IWF as IKE MSK.
    UnsupportedPurpose,
    /// The imported key is not 256 bits.
    InvalidKeyLength,
    /// The profile, transcript direction, key lengths or inputs are invalid.
    InvalidAuthInputs,
    /// The caller's aggregate transcript-byte cap is exceeded or overflows.
    InputLimit,
    /// IKE module admission, live readiness, algorithm or execution refused.
    CryptoUnavailable,
    /// A previous panic poisoned custody serialization.
    Unavailable,
    /// The supplied AUTH method, length or MIC does not match.
    AuthenticationFailed,
}

impl fmt::Display for Ikev2ProtocolKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Released => "protocol_key_released",
            Self::GenerationMismatch => "protocol_key_generation_mismatch",
            Self::OperationMismatch => "protocol_key_operation_mismatch",
            Self::OperationReused => "protocol_key_operation_reused",
            Self::OperationPending => "protocol_key_operation_pending",
            Self::Retired => "protocol_key_retired",
            Self::UnsupportedPurpose => "protocol_key_unsupported_purpose",
            Self::InvalidKeyLength => "protocol_key_invalid_length",
            Self::InvalidAuthInputs => "protocol_key_invalid_auth_inputs",
            Self::InputLimit => "protocol_key_input_limit",
            Self::CryptoUnavailable => "protocol_key_crypto_unavailable",
            Self::Unavailable => "protocol_key_unavailable",
            Self::AuthenticationFailed => "protocol_key_authentication_failed",
        })
    }
}

impl Error for Ikev2ProtocolKeyError {}

struct Secret {
    bytes: Zeroizing<Vec<u8>>,
    #[cfg(test)]
    audit: Option<Arc<tests::ZeroizeAudit>>,
}

impl Secret {
    fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self {
            bytes,
            #[cfg(test)]
            audit: tests::ZEROIZE_AUDIT.with(|slot| slot.borrow().clone()),
        }
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // Clear the live slice before its zeroizing allocation is released.
        // The wrapper also clears spare capacity on drop.
        self.bytes.as_mut_slice().zeroize();
        #[cfg(test)]
        if let Some(audit) = &self.audit {
            audit.observe(&self.bytes);
        }
    }
}

enum Phase {
    AwaitingImport,
    Imported(Secret),
    Retired,
}

struct Pending {
    identity: Arc<()>,
    phase: Phase,
}

struct State {
    generation: NonZeroU64,
    last_operation: u64,
    released: bool,
    pending: Option<Pending>,
}

impl State {
    fn release(&mut self) {
        self.pending = None;
        self.released = true;
    }

    fn pending(
        &mut self,
        generation: NonZeroU64,
        identity: &Arc<()>,
    ) -> Result<&mut Pending, Ikev2ProtocolKeyError> {
        if self.released {
            return Err(Ikev2ProtocolKeyError::Released);
        }
        if self.generation != generation {
            return Err(Ikev2ProtocolKeyError::GenerationMismatch);
        }
        self.pending
            .as_mut()
            .filter(|pending| Arc::ptr_eq(&pending.identity, identity))
            .ok_or(Ikev2ProtocolKeyError::Retired)
    }
}

fn lock(state: &Mutex<State>) -> Result<MutexGuard<'_, State>, Ikev2ProtocolKeyError> {
    match state.lock() {
        Ok(guard) => Ok(guard),
        Err(poisoned) => {
            poisoned.into_inner().release();
            Err(Ikev2ProtocolKeyError::Unavailable)
        }
    }
}

fn retire(state: &Mutex<State>, identity: Option<&Arc<()>>) {
    // Recovery is solely for destruction, never for resuming key use.
    let mut state = state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match identity {
        None => state.release(),
        Some(identity)
            if state
                .pending
                .as_ref()
                .is_some_and(|pending| Arc::ptr_eq(&pending.identity, identity)) =>
        {
            state.pending = None;
        }
        Some(_) => {}
    }
}

/// Owner of one local association's pending protocol-key custody.
///
/// Creating two owners with the same numeric generation still creates distinct
/// associations. Keep this owner alive for the real association and call
/// `release`/`replace_generation` when the corresponding application event
/// occurs. The SDK cannot observe external association state by itself.
pub struct Ikev2ProtocolKeyAssociation {
    state: Arc<Mutex<State>>,
}

impl Ikev2ProtocolKeyAssociation {
    /// Create an empty, live association at the caller-assigned generation.
    #[must_use]
    pub fn new(generation: NonZeroU64) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                generation,
                last_operation: 0,
                released: false,
                pending: None,
            })),
        }
    }

    /// Reserve the sole pending IKE_AUTH operation and bind its crypto profile.
    ///
    /// Identifiers must increase within each generation. These are local SDK
    /// operation identifiers, not IKE message IDs. Their monotonicity is an SDK
    /// replay guard, not a standards-mandated wire rule. Dropping the returned
    /// guard cancels it, including from a cancelled async future that owns it.
    ///
    /// # Errors
    /// Refuses released/stale state, an occupied slot, reused identifiers or an
    /// invalid profile. No key material is accepted by this method.
    pub fn begin_ike_auth(
        &self,
        generation: NonZeroU64,
        operation: NonZeroU64,
        profile: Ikev2SaInitCryptoProfile,
    ) -> Result<Ikev2ProtocolKeyOperation, Ikev2ProtocolKeyError> {
        profile
            .validate_executable()
            .map_err(|_| Ikev2ProtocolKeyError::InvalidAuthInputs)?;
        let mut state = lock(&self.state)?;
        if state.released {
            return Err(Ikev2ProtocolKeyError::Released);
        }
        if state.generation != generation {
            return Err(Ikev2ProtocolKeyError::GenerationMismatch);
        }
        if state.pending.is_some() {
            return Err(Ikev2ProtocolKeyError::OperationPending);
        }
        if operation.get() <= state.last_operation {
            return Err(Ikev2ProtocolKeyError::OperationReused);
        }
        let identity = Arc::new(());
        state.last_operation = operation.get();
        state.pending = Some(Pending {
            identity: Arc::clone(&identity),
            phase: Phase::AwaitingImport,
        });
        Ok(Ikev2ProtocolKeyOperation {
            state: Arc::clone(&self.state),
            identity,
            generation,
            profile,
        })
    }

    /// Zeroize the pending key and replace a live association generation.
    ///
    /// # Errors
    /// Both the expected current generation and strictly increasing successor
    /// are checked before mutation. A released/poisoned owner cannot reopen.
    pub fn replace_generation(
        &self,
        expected: NonZeroU64,
        replacement: NonZeroU64,
    ) -> Result<(), Ikev2ProtocolKeyError> {
        let mut state = lock(&self.state)?;
        if state.released {
            return Err(Ikev2ProtocolKeyError::Released);
        }
        if state.generation != expected || replacement <= expected {
            return Err(Ikev2ProtocolKeyError::GenerationMismatch);
        }
        state.pending = None;
        state.generation = replacement;
        state.last_operation = 0;
        Ok(())
    }

    /// Permanently release this association and zeroize any pending key.
    ///
    /// This is idempotent and also clears material from a poisoned slot.
    pub fn release(&self) {
        retire(&self.state, None);
    }
}

impl Drop for Ikev2ProtocolKeyAssociation {
    fn drop(&mut self) {
        self.release();
    }
}

/// RAII authority for one exact generation and pending IKE_AUTH operation.
///
/// No `Clone` or numeric reconstruction is available. Sharing a reference or
/// an `Arc` does not allow multiple imports or multiple consumptions.
pub struct Ikev2ProtocolKeyOperation {
    state: Arc<Mutex<State>>,
    identity: Arc<()>,
    generation: NonZeroU64,
    profile: Ikev2SaInitCryptoProfile,
}

impl Ikev2ProtocolKeyOperation {
    /// Transfer zeroizing K_N3IWF bytes into this operation's custody.
    ///
    /// The incoming allocation is moved, not copied into another key buffer.
    /// Failed inputs are zeroized too. One import attempt retires the slot on
    /// failure; callers must begin a fresh operation for another handoff. A
    /// duplicate import cannot replace a key already held by the first handle.
    ///
    /// # Errors
    /// Refuses stale/retired operations, a wrong purpose or key width, and an
    /// absent/unready IKE module or PRF that was not explicitly admitted.
    pub fn import(
        &self,
        purpose: Ikev2ProtocolKeyPurpose,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<Ikev2ProtocolKeyHandle, Ikev2ProtocolKeyError> {
        let secret = Secret::new(bytes);
        let mut state = lock(&self.state)?;
        // The inner call owns the input, so every import refusal destroys it
        // before this outer guard unlocks the association.
        self.import_into(&mut state, purpose, secret)?;
        Ok(Ikev2ProtocolKeyHandle {
            state: Arc::clone(&self.state),
            identity: Arc::clone(&self.identity),
            generation: self.generation,
        })
    }

    fn import_into(
        &self,
        state: &mut State,
        purpose: Ikev2ProtocolKeyPurpose,
        secret: Secret,
    ) -> Result<(), Ikev2ProtocolKeyError> {
        let pending = state.pending(self.generation, &self.identity)?;
        if !matches!(pending.phase, Phase::AwaitingImport) {
            return Err(Ikev2ProtocolKeyError::Retired);
        }
        pending.phase = Phase::Retired;
        if purpose != Ikev2ProtocolKeyPurpose::N3iwfMsk {
            return Err(Ikev2ProtocolKeyError::UnsupportedPurpose);
        }
        if secret.bytes.len() != N3IWF_KEY_LEN {
            return Err(Ikev2ProtocolKeyError::InvalidKeyLength);
        }
        check_prf_admission(self.profile.prf())
            .map_err(|_| Ikev2ProtocolKeyError::CryptoUnavailable)?;
        pending.phase = Phase::Imported(secret);
        Ok(())
    }

    /// Cancel this pending operation and zeroize its key, if still current.
    ///
    /// Cancelling or dropping a stale guard never affects a newer operation.
    pub fn cancel(&self) {
        retire(&self.state, Some(&self.identity));
    }
}

impl Drop for Ikev2ProtocolKeyOperation {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// Opaque, single-use imported protocol key with no key-byte access.
///
/// Only `consume_ike_auth` can use the key. The handle has no `Clone`, `Eq`,
/// `Ord`, `Hash`, `Deref`, `AsRef`, serialization, or general PRF/callback API.
///
/// ```compile_fail
/// use opc_proto_ikev2::protocol_key::Ikev2ProtocolKeyHandle;
/// fn clone_bound<T: Clone>() {}
/// clone_bound::<Ikev2ProtocolKeyHandle>();
/// ```
/// ```compile_fail
/// use opc_proto_ikev2::protocol_key::Ikev2ProtocolKeyHandle;
/// fn eq_bound<T: Eq>() {}
/// eq_bound::<Ikev2ProtocolKeyHandle>();
/// ```
/// ```compile_fail
/// use opc_proto_ikev2::protocol_key::Ikev2ProtocolKeyHandle;
/// fn ord_bound<T: Ord>() {}
/// ord_bound::<Ikev2ProtocolKeyHandle>();
/// ```
/// ```compile_fail
/// use opc_proto_ikev2::protocol_key::Ikev2ProtocolKeyHandle;
/// fn hash_bound<T: std::hash::Hash>() {}
/// hash_bound::<Ikev2ProtocolKeyHandle>();
/// ```
/// ```compile_fail
/// use opc_proto_ikev2::protocol_key::Ikev2ProtocolKeyHandle;
/// fn byte_bound<T: AsRef<[u8]>>() {}
/// byte_bound::<Ikev2ProtocolKeyHandle>();
/// ```
/// ```compile_fail
/// use opc_proto_ikev2::protocol_key::Ikev2ProtocolKeyHandle;
/// fn export(key: Ikev2ProtocolKeyHandle) -> Vec<u8> { key.into_bytes() }
/// ```
pub struct Ikev2ProtocolKeyHandle {
    state: Arc<Mutex<State>>,
    identity: Arc<()>,
    generation: NonZeroU64,
}

impl Ikev2ProtocolKeyHandle {
    /// Consume the imported MSK once for both transcript-specific AUTH MICs.
    ///
    /// `max_input_bytes` bounds the sum of both message, nonce and ID-body
    /// lengths before transcript allocation or provider calls. It is caller
    /// policy, independent of protocol lengths. The caller supplies the exact
    /// first SA_INIT messages, peer nonces, ID bodies and established SK keys
    /// belonging to this operation's real IKE association.
    ///
    /// Once the handle and guard match the live slot, the attempt retires the
    /// key even if input checks or crypto fail. Wrong guards cannot use or
    /// retire another operation's key. Retransmission reuses the resulting AUTH
    /// data or sealed packet, never this MSK. This synchronous method must not
    /// be called recursively from the admitted provider.
    ///
    /// # Errors
    /// Refuses mismatched/retired authority, malformed or oversized inputs,
    /// and any admitted crypto failure. Errors contain no supplied values.
    pub fn consume_ike_auth(
        &self,
        operation: &Ikev2ProtocolKeyOperation,
        key_material: &Ikev2SaInitKeyMaterial,
        initiator: Ikev2IkeAuthSignedOctets<'_>,
        responder: Ikev2IkeAuthSignedOctets<'_>,
        max_input_bytes: usize,
    ) -> Result<Ikev2ProtocolKeyAuth, Ikev2ProtocolKeyError> {
        if !Arc::ptr_eq(&self.state, &operation.state)
            || !Arc::ptr_eq(&self.identity, &operation.identity)
            || self.generation != operation.generation
        {
            return Err(Ikev2ProtocolKeyError::OperationMismatch);
        }
        let mut state = lock(&self.state)?;
        let pending = state.pending(self.generation, &self.identity)?;
        let Phase::Imported(secret) = std::mem::replace(&mut pending.phase, Phase::Retired) else {
            return Err(Ikev2ProtocolKeyError::Retired);
        };
        let mut total = 0_usize;
        for inputs in [initiator, responder] {
            for len in [
                inputs.ike_sa_init_message.len(),
                inputs.peer_nonce.len(),
                inputs.identity_payload_body.len(),
            ] {
                total = total
                    .checked_add(len)
                    .ok_or(Ikev2ProtocolKeyError::InputLimit)?;
            }
        }
        if total > max_input_bytes {
            return Err(Ikev2ProtocolKeyError::InputLimit);
        }
        if initiator.peer != Ikev2IkeAuthPeer::Initiator
            || responder.peer != Ikev2IkeAuthPeer::Responder
            || key_material.sk_pi().len() != operation.profile.prf().output_len()
            || key_material.sk_pr().len() != operation.profile.prf().output_len()
            || validate_signed_octets(initiator).is_err()
            || validate_signed_octets(responder).is_err()
        {
            return Err(Ikev2ProtocolKeyError::InvalidAuthInputs);
        }
        let initiator = Zeroizing::new(
            compute_ike_auth_shared_key_mic(
                operation.profile,
                key_material,
                initiator,
                &secret.bytes,
            )
            .map_err(|_| Ikev2ProtocolKeyError::CryptoUnavailable)?,
        );
        let responder = Zeroizing::new(
            compute_ike_auth_shared_key_mic(
                operation.profile,
                key_material,
                responder,
                &secret.bytes,
            )
            .map_err(|_| Ikev2ProtocolKeyError::CryptoUnavailable)?,
        );
        // The secret is destroyed while the operation lock is still held.
        drop(secret);
        drop(state);
        Ok(Ikev2ProtocolKeyAuth {
            initiator,
            responder,
        })
    }
}

impl Drop for Ikev2ProtocolKeyHandle {
    fn drop(&mut self) {
        retire(&self.state, Some(&self.identity));
    }
}

/// Two transcript-specific AUTH MICs; contains no imported MSK or padded key.
///
/// Verification is cryptographic comparison only. The caller owns EAP success,
/// subscriber authorization, identity policy and permission to send its AUTH.
pub struct Ikev2ProtocolKeyAuth {
    initiator: Zeroizing<Vec<u8>>,
    responder: Zeroizing<Vec<u8>>,
}

impl Ikev2ProtocolKeyAuth {
    /// AUTH data for the selected signing peer, for protocol serialization.
    ///
    /// These are sensitive authentication bytes; never log them.
    #[must_use]
    pub fn authentication_data(&self, peer: Ikev2IkeAuthPeer) -> &[u8] {
        match peer {
            Ikev2IkeAuthPeer::Initiator => &self.initiator,
            Ikev2IkeAuthPeer::Responder => &self.responder,
        }
    }

    /// Check AUTH method/length and compare the peer's MIC in constant time.
    ///
    /// # Errors
    /// Returns only `AuthenticationFailed` for any method, length or MIC error.
    pub fn verify(
        &self,
        peer: Ikev2IkeAuthPeer,
        authentication: &Ikev2AuthenticationPayload<'_>,
    ) -> Result<(), Ikev2ProtocolKeyError> {
        let expected = self.authentication_data(peer);
        if authentication.auth_method != IKEV2_AUTH_METHOD_SHARED_KEY_MIC
            || authentication.auth_data.len() != expected.len()
            || !bool::from(authentication.auth_data.ct_eq(expected))
        {
            return Err(Ikev2ProtocolKeyError::AuthenticationFailed);
        }
        Ok(())
    }
}

macro_rules! redacted_debug {
    ($($name:ident),+ $(,)?) => {$ (
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    )+ };
}

redacted_debug!(
    Ikev2ProtocolKeyAssociation,
    Ikev2ProtocolKeyOperation,
    Ikev2ProtocolKeyHandle,
    Ikev2ProtocolKeyAuth,
);

#[cfg(test)]
mod tests;
