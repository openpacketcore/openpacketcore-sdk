//! In-memory standby custody for live-mirrored SA keymat.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt;
use std::num::NonZeroUsize;
use std::sync::{Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use opc_ipsec_lb::{
    AntiReplayResume, IpsecLbError, ResumeKeySource, SaId, SameSpiOutboundIvResume, SameSpiResume,
};

use crate::error::SaMirrorError;
use crate::keymat::{KeyEpoch, MirroredSaKeymat, SaCounterCheckpoint, SaMirrorInstall};
use crate::ports::{LiveMirroredTakeover, RepinTakeoverParams, SaMirrorSink, StandbyKeymatSource};

/// Default maximum number of SAs held in standby custody.
// Compile-time evaluated: the unwrap cannot panic at runtime.
pub const DEFAULT_STANDBY_CAPACITY: NonZeroUsize = match NonZeroUsize::new(65_536) {
    Some(capacity) => capacity,
    None => unreachable!(),
};

struct HeldSa {
    epoch: KeyEpoch,
    keymat: MirroredSaKeymat,
    send_iv_next: u64,
    replay_highest_accepted: u64,
}

/// In-memory standby keymat holder.
///
/// The only shipped [`SaMirrorSink`]: custody is process memory, wiped on
/// drop, never serialized, never persisted. Custody rules (RFC 015 §5.3):
///
/// - installs for an older epoch are rejected (`stale_epoch`);
/// - equal-epoch reinstalls are idempotent only for byte-identical keymat
///   (constant-time comparison) and merge counters monotonically;
/// - a higher epoch replaces custody, zeroizing the previous generation;
/// - checkpoints merge with a per-field monotonic maximum within an epoch;
/// - withdraws wipe only generations at or below the withdrawn epoch and are
///   idempotent;
/// - at capacity, installs for new SAs fail closed rather than evicting
///   another SA's failover coverage.
pub struct InMemoryStandbyHolder {
    entries: Mutex<HashMap<SaId, HeldSa>>,
    capacity: NonZeroUsize,
}

impl fmt::Debug for InMemoryStandbyHolder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InMemoryStandbyHolder")
            .field("held", &self.lock().len())
            .field("capacity", &self.capacity)
            .finish()
    }
}

impl Default for InMemoryStandbyHolder {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryStandbyHolder {
    /// Build a holder with [`DEFAULT_STANDBY_CAPACITY`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_STANDBY_CAPACITY)
    }

    /// Build a holder bounded to `capacity` mirrored SAs.
    #[must_use]
    pub fn with_capacity(capacity: NonZeroUsize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<SaId, HeldSa>> {
        // No critical section below can panic, so poisoning is unreachable;
        // recover the inner map rather than propagating a panic through a
        // failover path.
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn install(&self, install: SaMirrorInstall) -> Result<(), SaMirrorError> {
        install.validate()?;
        let mut entries = self.lock();
        if !entries.contains_key(&install.sa) && entries.len() >= self.capacity.get() {
            return Err(SaMirrorError::CapacityExhausted);
        }
        match entries.entry(install.sa) {
            Entry::Vacant(slot) => {
                slot.insert(HeldSa {
                    epoch: install.epoch,
                    keymat: install.keymat,
                    send_iv_next: install.send_iv_next,
                    replay_highest_accepted: install.replay_highest_accepted,
                });
                Ok(())
            }
            Entry::Occupied(mut slot) => {
                let held = slot.get_mut();
                if install.epoch < held.epoch {
                    return Err(SaMirrorError::StaleEpoch);
                }
                if install.epoch == held.epoch {
                    // A producer retry after an ambiguous transport outcome
                    // must be idempotent; equivocating key bytes for the same
                    // generation must fail closed.
                    if !held.keymat.secret_ct_eq(&install.keymat) {
                        return Err(SaMirrorError::conflict(
                            "held keymat differs for the same epoch",
                        ));
                    }
                    held.send_iv_next = held.send_iv_next.max(install.send_iv_next);
                    held.replay_highest_accepted = held
                        .replay_highest_accepted
                        .max(install.replay_highest_accepted);
                    return Ok(());
                }
                // New keys: fresh counter space. The replaced generation is
                // dropped here and zeroizes itself.
                *held = HeldSa {
                    epoch: install.epoch,
                    keymat: install.keymat,
                    send_iv_next: install.send_iv_next,
                    replay_highest_accepted: install.replay_highest_accepted,
                };
                Ok(())
            }
        }
    }

    fn checkpoint(&self, checkpoint: SaCounterCheckpoint) -> Result<(), SaMirrorError> {
        checkpoint.validate()?;
        let mut entries = self.lock();
        let Some(held) = entries.get_mut(&checkpoint.sa) else {
            return Err(SaMirrorError::NotFound);
        };
        if checkpoint.epoch < held.epoch {
            return Err(SaMirrorError::StaleEpoch);
        }
        if checkpoint.epoch > held.epoch {
            // The checkpointed generation is not in custody (for example the
            // install for it was lost with a standby restart). Reporting
            // NotFound tells the producer to re-install the current epoch.
            return Err(SaMirrorError::NotFound);
        }
        // Monotonic merge: replayed or reordered checkpoints may raise but
        // never lower the bases used for the takeover forward-jump.
        held.send_iv_next = held.send_iv_next.max(checkpoint.send_iv_next);
        held.replay_highest_accepted = held
            .replay_highest_accepted
            .max(checkpoint.replay_highest_accepted);
        Ok(())
    }

    fn withdraw(&self, sa: SaId, epoch: KeyEpoch) {
        let mut entries = self.lock();
        if let Some(held) = entries.get(&sa) {
            // A stale withdraw must not destroy a newer mirrored generation.
            if held.epoch <= epoch {
                entries.remove(&sa);
            }
        }
    }
}

#[async_trait]
impl SaMirrorSink for InMemoryStandbyHolder {
    async fn accept_install(&self, install: SaMirrorInstall) -> Result<(), SaMirrorError> {
        self.install(install)
    }

    async fn accept_checkpoint(
        &self,
        checkpoint: SaCounterCheckpoint,
    ) -> Result<(), SaMirrorError> {
        self.checkpoint(checkpoint)
    }

    async fn accept_withdraw(&self, sa: SaId, epoch: KeyEpoch) -> Result<(), SaMirrorError> {
        self.withdraw(sa, epoch);
        Ok(())
    }
}

impl StandbyKeymatSource for InMemoryStandbyHolder {
    fn take_for_repin(
        &self,
        sa: SaId,
        params: RepinTakeoverParams,
    ) -> Result<LiveMirroredTakeover, SaMirrorError> {
        let mut entries = self.lock();
        let Some(held) = entries.get(&sa) else {
            return Err(SaMirrorError::NotFound);
        };
        let checkpointed_send_iv_next = held.send_iv_next;
        let replay_highest_accepted = held.replay_highest_accepted;

        // The restored counter is derived, never caller-chosen: a mirrored
        // checkpoint is a stale lower bound, so takeover must skip the whole
        // uncertain interval or fail closed.
        let Some(restored_send_iv_next) =
            checkpointed_send_iv_next.checked_add(params.forward_jump.forward_jump)
        else {
            return Err(SaMirrorError::Resume(IpsecLbError::unsafe_resume(
                "send IV counter exhausted during forward-jump; rekey before sending",
            )));
        };
        let resume = SameSpiResume {
            previous_sa: sa,
            resumed_sa: sa,
            outbound_iv: SameSpiOutboundIvResume::CounterBased {
                checkpointed_send_iv_next,
                restored_send_iv_next,
                forward_jump: Some(params.forward_jump),
            },
            // Live mirroring is asynchronous: bitmap continuity can never be
            // honestly claimed, so exact-window restore is unrepresentable on
            // this path.
            anti_replay: AntiReplayResume::BoundedReopening {
                checkpoint_highest_accepted: replay_highest_accepted,
                restored_highest_accepted: replay_highest_accepted,
                max_reopened_packets: params.max_reopened_packets,
            },
            key_source: ResumeKeySource::LiveMirrored,
        };
        // Validate before removing so a rejected takeover leaves custody
        // intact for a corrected retry.
        resume
            .validate_for_repin(sa)
            .map_err(SaMirrorError::Resume)?;

        // The same lock has been held since the entry was read, so it is
        // still present; fail closed regardless rather than panic.
        let Some(held) = entries.remove(&sa) else {
            return Err(SaMirrorError::NotFound);
        };
        Ok(LiveMirroredTakeover {
            keymat: held.keymat,
            epoch: held.epoch,
            resume,
        })
    }

    fn held_epoch(&self, sa: SaId) -> Option<KeyEpoch> {
        self.lock().get(&sa).map(|held| held.epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keymat::KeymatFormat;
    use opc_ipsec_lb::{SendIvCounterMode, SendIvForwardJump, MIN_SEND_IV_FORWARD_JUMP};
    use zeroize::Zeroizing;

    fn keymat(bytes: &[u8]) -> MirroredSaKeymat {
        MirroredSaKeymat::new(
            KeymatFormat::new(1).unwrap(),
            Zeroizing::new(bytes.to_vec()),
        )
        .unwrap()
    }

    fn install(sa: SaId, epoch: u64, bytes: &[u8], send_iv_next: u64) -> SaMirrorInstall {
        SaMirrorInstall {
            sa,
            epoch: KeyEpoch::new(epoch).unwrap(),
            keymat: keymat(bytes),
            send_iv_next,
            replay_highest_accepted: 20,
        }
    }

    fn esp_params() -> RepinTakeoverParams {
        RepinTakeoverParams {
            forward_jump: SendIvForwardJump {
                forward_jump: MIN_SEND_IV_FORWARD_JUMP,
                counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
                    max_peer_sequence_lag: 0,
                },
            },
            max_reopened_packets: 64,
        }
    }

    #[test]
    fn install_then_take_yields_validated_live_mirrored_resume() {
        let holder = InMemoryStandbyHolder::new();
        let sa = SaId::Esp { spi: 7 };
        holder.install(install(sa, 1, &[0xAB; 36], 100)).unwrap();
        assert_eq!(holder.held_epoch(sa), Some(KeyEpoch::new(1).unwrap()));

        let takeover = holder.take_for_repin(sa, esp_params()).unwrap();
        assert_eq!(takeover.epoch, KeyEpoch::new(1).unwrap());
        assert_eq!(takeover.keymat.expose_secret_bytes(), &[0xAB; 36]);
        assert_eq!(takeover.resume.key_source, ResumeKeySource::LiveMirrored);
        assert!(matches!(
            takeover.resume.outbound_iv,
            SameSpiOutboundIvResume::CounterBased {
                checkpointed_send_iv_next: 100,
                restored_send_iv_next,
                forward_jump: Some(_),
            } if restored_send_iv_next == 100 + MIN_SEND_IV_FORWARD_JUMP
        ));
        takeover.resume.validate_for_repin(sa).unwrap();

        // Take semantics: custody is gone after a successful yield.
        assert_eq!(holder.held_epoch(sa), None);
        assert!(matches!(
            holder.take_for_repin(sa, esp_params()),
            Err(SaMirrorError::NotFound)
        ));
    }

    #[test]
    fn ike_sa_takeover_uses_the_ike_counter_mode() {
        let holder = InMemoryStandbyHolder::new();
        let sa = SaId::Ike { responder_spi: 9 };
        holder.install(install(sa, 1, &[1; 32], 0)).unwrap();
        let params = RepinTakeoverParams {
            forward_jump: SendIvForwardJump {
                forward_jump: MIN_SEND_IV_FORWARD_JUMP,
                counter_mode: SendIvCounterMode::IkeAeadExplicitIv64,
            },
            max_reopened_packets: 8,
        };
        let takeover = holder.take_for_repin(sa, params).unwrap();
        takeover.resume.validate_for_repin(sa).unwrap();
    }

    #[test]
    fn epoch_rollback_and_equivocation_fail_closed() {
        let holder = InMemoryStandbyHolder::new();
        let sa = SaId::Esp { spi: 7 };
        holder.install(install(sa, 2, &[2; 32], 10)).unwrap();

        assert!(matches!(
            holder.install(install(sa, 1, &[1; 32], 10)),
            Err(SaMirrorError::StaleEpoch)
        ));
        assert!(matches!(
            holder.install(install(sa, 2, &[9; 32], 10)),
            Err(SaMirrorError::Conflict { .. })
        ));
        // Custody is unchanged after both rejections.
        assert_eq!(holder.held_epoch(sa), Some(KeyEpoch::new(2).unwrap()));
    }

    #[test]
    fn equal_epoch_reinstall_is_idempotent_and_merges_counters_monotonically() {
        let holder = InMemoryStandbyHolder::new();
        let sa = SaId::Esp { spi: 7 };
        holder.install(install(sa, 1, &[3; 32], 50)).unwrap();
        // Retried install with older counters must not lower the base.
        holder.install(install(sa, 1, &[3; 32], 40)).unwrap();
        let takeover = holder.take_for_repin(sa, esp_params()).unwrap();
        assert!(matches!(
            takeover.resume.outbound_iv,
            SameSpiOutboundIvResume::CounterBased {
                checkpointed_send_iv_next: 50,
                ..
            }
        ));
    }

    #[test]
    fn higher_epoch_replaces_custody_and_resets_counters() {
        let holder = InMemoryStandbyHolder::new();
        let sa = SaId::Esp { spi: 7 };
        holder.install(install(sa, 1, &[1; 32], 900)).unwrap();
        holder.install(install(sa, 2, &[2; 32], 5)).unwrap();

        let takeover = holder.take_for_repin(sa, esp_params()).unwrap();
        assert_eq!(takeover.epoch, KeyEpoch::new(2).unwrap());
        assert_eq!(takeover.keymat.expose_secret_bytes(), &[2; 32]);
        assert!(matches!(
            takeover.resume.outbound_iv,
            SameSpiOutboundIvResume::CounterBased {
                checkpointed_send_iv_next: 5,
                ..
            }
        ));
    }

    #[test]
    fn checkpoints_merge_monotonically_within_the_epoch() {
        let holder = InMemoryStandbyHolder::new();
        let sa = SaId::Esp { spi: 7 };
        holder.install(install(sa, 1, &[1; 32], 100)).unwrap();

        let epoch = KeyEpoch::new(1).unwrap();
        holder
            .checkpoint(SaCounterCheckpoint {
                sa,
                epoch,
                send_iv_next: 500,
                replay_highest_accepted: 60,
            })
            .unwrap();
        // A replayed older checkpoint must not lower either base.
        holder
            .checkpoint(SaCounterCheckpoint {
                sa,
                epoch,
                send_iv_next: 200,
                replay_highest_accepted: 30,
            })
            .unwrap();

        let takeover = holder.take_for_repin(sa, esp_params()).unwrap();
        assert!(matches!(
            takeover.resume.outbound_iv,
            SameSpiOutboundIvResume::CounterBased {
                checkpointed_send_iv_next: 500,
                ..
            }
        ));
        assert!(matches!(
            takeover.resume.anti_replay,
            AntiReplayResume::BoundedReopening {
                checkpoint_highest_accepted: 60,
                restored_highest_accepted: 60,
                max_reopened_packets: 64,
            }
        ));
    }

    #[test]
    fn checkpoint_epoch_mismatches_signal_reinstall_or_stale() {
        let holder = InMemoryStandbyHolder::new();
        let sa = SaId::Esp { spi: 7 };

        assert!(matches!(
            holder.checkpoint(SaCounterCheckpoint {
                sa,
                epoch: KeyEpoch::new(1).unwrap(),
                send_iv_next: 5,
                replay_highest_accepted: 0,
            }),
            Err(SaMirrorError::NotFound)
        ));

        holder.install(install(sa, 2, &[1; 32], 10)).unwrap();
        assert!(matches!(
            holder.checkpoint(SaCounterCheckpoint {
                sa,
                epoch: KeyEpoch::new(1).unwrap(),
                send_iv_next: 5,
                replay_highest_accepted: 0,
            }),
            Err(SaMirrorError::StaleEpoch)
        ));
        // A checkpoint for a generation the standby never received asks the
        // producer to re-install.
        assert!(matches!(
            holder.checkpoint(SaCounterCheckpoint {
                sa,
                epoch: KeyEpoch::new(3).unwrap(),
                send_iv_next: 5,
                replay_highest_accepted: 0,
            }),
            Err(SaMirrorError::NotFound)
        ));
    }

    #[test]
    fn withdraw_is_idempotent_and_never_destroys_a_newer_generation() {
        let holder = InMemoryStandbyHolder::new();
        let sa = SaId::Esp { spi: 7 };

        // Absent SA: idempotent no-op.
        holder.withdraw(sa, KeyEpoch::new(1).unwrap());

        holder.install(install(sa, 3, &[1; 32], 10)).unwrap();
        holder.withdraw(sa, KeyEpoch::new(2).unwrap());
        assert_eq!(holder.held_epoch(sa), Some(KeyEpoch::new(3).unwrap()));

        holder.withdraw(sa, KeyEpoch::new(3).unwrap());
        assert_eq!(holder.held_epoch(sa), None);
    }

    #[test]
    fn capacity_rejects_new_sas_but_not_rekeys_of_held_sas() {
        let holder = InMemoryStandbyHolder::with_capacity(NonZeroUsize::new(1).unwrap());
        let held = SaId::Esp { spi: 7 };
        holder.install(install(held, 1, &[1; 32], 10)).unwrap();

        assert!(matches!(
            holder.install(install(SaId::Esp { spi: 8 }, 1, &[2; 32], 10)),
            Err(SaMirrorError::CapacityExhausted)
        ));
        // Rekeying an already-held SA does not add an entry and must succeed.
        holder.install(install(held, 2, &[3; 32], 1)).unwrap();
    }

    #[test]
    fn unsafe_takeover_params_fail_closed_and_keep_custody() {
        let holder = InMemoryStandbyHolder::new();
        let sa = SaId::Esp { spi: 7 };
        holder.install(install(sa, 1, &[1; 32], 100)).unwrap();

        let below_floor = RepinTakeoverParams {
            forward_jump: SendIvForwardJump {
                forward_jump: MIN_SEND_IV_FORWARD_JUMP - 1,
                counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
                    max_peer_sequence_lag: 0,
                },
            },
            max_reopened_packets: 64,
        };
        assert!(matches!(
            holder.take_for_repin(sa, below_floor),
            Err(SaMirrorError::Resume(_))
        ));

        let zero_reopen_bound = RepinTakeoverParams {
            max_reopened_packets: 0,
            ..esp_params()
        };
        assert!(matches!(
            holder.take_for_repin(sa, zero_reopen_bound),
            Err(SaMirrorError::Resume(_))
        ));

        let wrong_counter_mode = RepinTakeoverParams {
            forward_jump: SendIvForwardJump {
                forward_jump: MIN_SEND_IV_FORWARD_JUMP,
                counter_mode: SendIvCounterMode::IkeAeadExplicitIv64,
            },
            max_reopened_packets: 64,
        };
        assert!(matches!(
            holder.take_for_repin(sa, wrong_counter_mode),
            Err(SaMirrorError::Resume(_))
        ));

        // Every rejection left the keymat in custody; a corrected takeover
        // still succeeds.
        assert_eq!(holder.held_epoch(sa), Some(KeyEpoch::new(1).unwrap()));
        holder.take_for_repin(sa, esp_params()).unwrap();
    }

    #[test]
    fn counter_exhaustion_near_u64_max_requires_rekey() {
        let holder = InMemoryStandbyHolder::new();
        let sa = SaId::Esp { spi: 7 };
        holder
            .install(install(sa, 1, &[1; 32], u64::MAX - 1))
            .unwrap();
        assert!(matches!(
            holder.take_for_repin(sa, esp_params()),
            Err(SaMirrorError::Resume(_))
        ));
        assert_eq!(holder.held_epoch(sa), Some(KeyEpoch::new(1).unwrap()));
    }

    #[test]
    fn debug_output_never_contains_key_bytes() {
        let holder = InMemoryStandbyHolder::new();
        holder
            .install(install(
                SaId::Esp { spi: 7 },
                1,
                b"top-secret-keymat-bytes!",
                1,
            ))
            .unwrap();
        let debug = format!("{holder:?}");
        assert!(!debug.contains("top-secret"));
    }
}
