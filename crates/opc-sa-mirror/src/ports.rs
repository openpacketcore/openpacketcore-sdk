//! Reusable ports for live SA keymat mirroring.

use std::fmt;

use async_trait::async_trait;
use opc_ipsec_lb::{SaId, SameSpiResume, SendIvForwardJump};

use crate::error::SaMirrorError;
use crate::keymat::{KeyEpoch, MirroredSaKeymat, SaCounterCheckpoint, SaMirrorInstall};

/// Owner-side port that mirrors live SA keymat to a designated standby.
///
/// The producer is invoked by the CNF's IKE layer with **freshly derived**
/// keymat at SA install/rekey time — never with kernel read-back (RFC 015
/// §5.1). `Ok(())` from [`Self::mirror_install`] means the standby holds the
/// keymat in memory; only then may the CNF claim live-mirror protection for
/// the SA. Mirror failure must degrade the SA to the rekey/re-attach
/// continuity tiers rather than fail the attach.
///
/// Nothing behind this port may persist: implementations forward to a
/// [`SaMirrorSink`], directly or over the mTLS transport, and both sides keep
/// keymat exclusively in zeroizing memory.
#[async_trait]
pub trait SaMirrorProducer: Send + Sync + fmt::Debug {
    /// Mirror a new key generation for an SA to the standby.
    async fn mirror_install(&self, install: SaMirrorInstall) -> Result<(), SaMirrorError>;

    /// Update the mirrored counter checkpoints for an SA (no key bytes).
    ///
    /// [`SaMirrorError::NotFound`] means the standby does not hold the SA
    /// (for example, it restarted and its in-memory custody was lost); the
    /// producer restores coverage by re-sending [`Self::mirror_install`] with
    /// the current epoch.
    async fn mirror_checkpoint(&self, checkpoint: SaCounterCheckpoint)
        -> Result<(), SaMirrorError>;

    /// Withdraw a mirrored SA on teardown.
    ///
    /// Withdrawal is idempotent, and a withdraw for an older epoch never
    /// destroys a newer mirrored generation.
    async fn mirror_withdraw(&self, sa: SaId, epoch: KeyEpoch) -> Result<(), SaMirrorError>;
}

/// Standby-side inbound port fed by the mirror transport server.
///
/// This is deliberately not a session-store trait: the only conforming
/// implementations keep keymat in memory (see [`crate::InMemoryStandbyHolder`])
/// so the receiving plane cannot be pointed at a persisting backend.
#[async_trait]
pub trait SaMirrorSink: Send + Sync + fmt::Debug {
    /// Accept custody of a new key generation.
    async fn accept_install(&self, install: SaMirrorInstall) -> Result<(), SaMirrorError>;

    /// Merge a counter checkpoint for a held SA.
    async fn accept_checkpoint(&self, checkpoint: SaCounterCheckpoint)
        -> Result<(), SaMirrorError>;

    /// Wipe a held SA whose generation is at or below the given epoch.
    async fn accept_withdraw(&self, sa: SaId, epoch: KeyEpoch) -> Result<(), SaMirrorError>;
}

/// Deployment-attested safety parameters for a live-mirrored takeover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RepinTakeoverParams {
    /// Outbound-IV forward-jump evidence.
    ///
    /// The jump must be at least the maximum packets the departed owner could
    /// have sent after its last checkpoint, and the counter mode must match
    /// the SA protocol; the mandatory floor and ESP ESN ceiling are enforced
    /// during takeover validation.
    pub forward_jump: SendIvForwardJump,
    /// Attested bound on previously accepted packets the survivor might
    /// accept again (anti-replay bounded reopening). Must be non-zero: live
    /// mirroring is asynchronous, so exact bitmap continuity can never be
    /// claimed on this path.
    pub max_reopened_packets: u64,
}

/// Keymat and pre-validated resume evidence yielded for a fenced re-pin.
#[derive(Debug)]
pub struct LiveMirroredTakeover {
    /// Opaque zeroizing key material to install on the survivor.
    pub keymat: MirroredSaKeymat,
    /// Key generation of the yielded keymat.
    pub epoch: KeyEpoch,
    /// Resume evidence with `key_source == ResumeKeySource::LiveMirrored`,
    /// already accepted by `SameSpiResume::validate_for_repin`.
    ///
    /// `restored_send_iv_next` MUST be the outbound counter actually
    /// installed on the survivor; the re-pin transition fingerprint binds it.
    pub resume: SameSpiResume,
}

/// Standby-side takeover port that yields mirrored keymat to the re-pin.
///
/// Methods are synchronous by contract: a conforming holder keeps keymat in
/// local process memory, so yielding it performs no I/O. Yielding does not
/// grant ownership — the caller must still win the ordinary fenced re-pin
/// (`RePinCoordinator`), which remains the only split-brain authority.
pub trait StandbyKeymatSource: Send + Sync + fmt::Debug {
    /// Remove and yield the mirrored keymat for `sa` with validated resume
    /// evidence.
    ///
    /// On success the entry is gone: a second local taker gets
    /// [`SaMirrorError::NotFound`]. The caller owns the buffer until it drops
    /// it (zeroize-on-drop); a failed re-pin does not lose the keymat.
    /// Validation failures leave the entry in custody.
    fn take_for_repin(
        &self,
        sa: SaId,
        params: RepinTakeoverParams,
    ) -> Result<LiveMirroredTakeover, SaMirrorError>;

    /// Return the held key generation for an SA, if any (observability; does
    /// not touch key bytes).
    fn held_epoch(&self, sa: SaId) -> Option<KeyEpoch>;
}
