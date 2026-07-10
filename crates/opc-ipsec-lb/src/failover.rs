//! Pure failover safety guards.

use crate::error::IpsecLbError;
use crate::model::SaId;

/// Minimum outbound IV forward-jump accepted for same-SPI failover.
///
/// RFC 6311 gives `2^30` as an example skip for stale failover counters. The
/// floor is not itself a traffic bound: callers MUST still ensure that the
/// configured jump is at least the maximum packets the departed owner could
/// have sent after its last counter checkpoint.
pub const MIN_SEND_IV_FORWARD_JUMP: u64 = 1_u64 << 30;

/// Maximum outbound forward-jump accepted for an ESP SA using ESN.
///
/// RFC 4303 Appendix A2.2 reconstructs the untransmitted high-order ESN bits
/// from the receiver's current low-order value (`Tl`) and replay-window width
/// (`W`), and its algorithm assumes `W <= 2^31`. This evidence does not carry
/// trustworthy peer `Tl`/`W` state, so the SDK uses the universal half-space
/// bound. This constant is only the absolute ceiling when the caller attests
/// zero peer receive lag. If `checkpoint_next` is `c`, the peer's highest
/// authenticated sequence may be `c - 1 - lag`, while the first resumed
/// sequence is `c + jump`. Their delta is `jump + 1 + lag`, so validation
/// requires that checked sum to be at most `2^31`.
///
/// This limit is specific to ESP ESN reconstruction. IKE's independent 64-bit
/// AEAD explicit-IV counter is limited only by checked `u64` arithmetic.
pub const MAX_ESP_SEND_IV_FORWARD_JUMP: u64 = (1_u64 << 31) - 1;

/// Send IV/counter state used to avoid AEAD nonce reuse on resume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct SendIvCounter {
    next: u64,
}

impl SendIvCounter {
    /// Build a counter from the next value to send.
    #[must_use]
    pub const fn new(next: u64) -> Self {
        Self { next }
    }

    /// Next value to send.
    #[must_use]
    pub const fn next(self) -> u64 {
        self.next
    }

    /// Resume from the highest IV/counter value the departed owner could have
    /// transmitted.
    ///
    /// SAFETY CONTRACT: `last_sent` MUST be a proven upper bound on every IV the
    /// departed owner actually sent, not a stale checkpoint. Asynchronous
    /// mirroring or periodic persistence records only a *lower* bound — the owner
    /// keeps sending after each sync — so resuming from a raw checkpoint would
    /// reuse AES-GCM IVs, which is catastrophic (RFC 5282: nonce reuse breaks
    /// confidentiality and enables forgery). A caller holding only a checkpoint
    /// MUST add an in-flight margin via [`Self::resume_with_margin`] instead.
    pub fn resume_after(last_sent: u64) -> Result<IvResumeDecision, IpsecLbError> {
        match last_sent.checked_add(1) {
            Some(next) => Ok(IvResumeDecision::Resume(Self { next })),
            None => Ok(IvResumeDecision::RekeyRequired),
        }
    }

    /// Resume from a checkpoint plus an in-flight safety margin.
    ///
    /// `checkpoint_next` is the last synced "next to send" counter (a lower
    /// bound). `in_flight_margin` MUST be greater than or equal to the maximum
    /// number of IVs the departed owner could have consumed since that
    /// checkpoint (for example `max_send_pps * sync_interval_seconds`, with
    /// headroom). After `k <= in_flight_margin` packets, the largest IV the old
    /// owner could have used is `checkpoint_next + k - 1`; resuming at
    /// `checkpoint_next + in_flight_margin` is therefore strictly beyond every
    /// possibly-used IV, including the `k == in_flight_margin` boundary. Returns
    /// [`IvResumeDecision::RekeyRequired`] when the jump would overflow the
    /// counter — the SA must be rekeyed before sending rather than wrap.
    pub fn resume_with_margin(
        checkpoint_next: u64,
        in_flight_margin: u64,
    ) -> Result<IvResumeDecision, IpsecLbError> {
        match checkpoint_next.checked_add(in_flight_margin) {
            Some(next) => Ok(IvResumeDecision::Resume(Self { next })),
            None => Ok(IvResumeDecision::RekeyRequired),
        }
    }

    /// Validate that a restored next counter does not roll back below a proven
    /// upper bound on transmitted IVs.
    ///
    /// SAFETY CONTRACT: `previously_observed_next` MUST be an upper bound on every
    /// IV the departed owner could have sent (see [`Self::resume_after`]). This
    /// enforces monotonicity only; it cannot detect reuse if the caller passes a
    /// stale lower-bound checkpoint. Derive a safe restored value from a
    /// checkpoint with [`Self::resume_with_margin`].
    pub fn validate_restored_next(
        restored_next: u64,
        previously_observed_next: u64,
    ) -> Result<Self, IpsecLbError> {
        if restored_next < previously_observed_next {
            return Err(IpsecLbError::unsafe_resume(
                "send IV counter rollback would risk nonce reuse",
            ));
        }
        Ok(Self {
            next: restored_next,
        })
    }
}

/// IV resume decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IvResumeDecision {
    /// It is safe to resume at this next value.
    Resume(SendIvCounter),
    /// Counter exhausted; rekey before sending.
    RekeyRequired,
}

/// Caller-supplied safety evidence for a same-SPI outbound IV forward-jump.
///
/// Both live-mirrored and durably persisted counters can be stale when an
/// active owner fails. This evidence deliberately says nothing about key
/// provenance: every same-SPI takeover must skip the uncertain outbound IV
/// interval. Fields remain public so untrusted or decoded evidence can be
/// represented and rejected at [`Self::validate_restored_next`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SendIvForwardJump {
    /// Number of counter values reserved past the checkpointed next IV.
    ///
    /// The caller attests this is at least the maximum packets the old owner
    /// could have sent after the checkpoint. Values below
    /// [`MIN_SEND_IV_FORWARD_JUMP`] are rejected even if locally attested. ESP
    /// ESN values cannot exceed the lag-zero ceiling
    /// [`MAX_ESP_SEND_IV_FORWARD_JUMP`], and non-zero peer receive lag reduces
    /// the permitted jump further. The IKE counter mode does not share that
    /// ESP-specific reconstruction constraint.
    pub forward_jump: u64,
    /// Protocol-specific 64-bit outbound counter mode used by the resumed SA.
    pub counter_mode: SendIvCounterMode,
}

impl SendIvForwardJump {
    /// Validate the proof and the exact counter installed on the survivor.
    ///
    /// `sa` must match [`Self::counter_mode`]. `checkpointed_next` is the stale
    /// lower-bound "next to send" value. It must be non-zero for ESP because
    /// RFC 4303 sequence numbers start at 1; IKE explicit-IV counters may use
    /// zero. The restored counter must equal `checkpointed_next + forward_jump`;
    /// accepting a different value would disconnect the installed SA state from
    /// this proof. The SA identifier must be non-zero. Arithmetic overflow, ESP
    /// reconstruction-bound failure, or counter exhaustion requires a rekey
    /// rather than same-SPI resume.
    pub fn validate_restored_next(
        self,
        sa: SaId,
        checkpointed_next: u64,
        restored_next: u64,
    ) -> Result<SendIvCounter, IpsecLbError> {
        if matches!(sa, SaId::Esp { spi: 0 } | SaId::Ike { responder_spi: 0 }) {
            return Err(IpsecLbError::unsafe_resume(
                "same-SPI resume requires a non-zero SA identifier",
            ));
        }

        let max_peer_sequence_lag = match (self.counter_mode, sa) {
            (
                SendIvCounterMode::EspExtendedSequenceNumbers {
                    max_peer_sequence_lag,
                },
                SaId::Esp { .. },
            ) => Some(max_peer_sequence_lag),
            (SendIvCounterMode::IkeAeadExplicitIv64, SaId::Ike { .. }) => None,
            _ => {
                return Err(IpsecLbError::unsafe_resume(
                    "send IV counter mode does not match the resumed SA protocol",
                ));
            }
        };

        if self.forward_jump < MIN_SEND_IV_FORWARD_JUMP {
            return Err(IpsecLbError::unsafe_resume(
                "send IV forward-jump is below the mandatory safety floor",
            ));
        }

        if let Some(max_peer_sequence_lag) = max_peer_sequence_lag {
            let Some(last_sequence_at_checkpoint) = checkpointed_next.checked_sub(1) else {
                return Err(IpsecLbError::unsafe_resume(
                    "ESP checkpointed next sequence must be non-zero",
                ));
            };
            if last_sequence_at_checkpoint
                .checked_sub(max_peer_sequence_lag)
                .is_none()
            {
                return Err(IpsecLbError::unsafe_resume(
                    "ESP peer receive lag exceeds the checkpointed sequence history",
                ));
            }
            let Some(resumed_sequence_delta) = self
                .forward_jump
                .checked_add(1)
                .and_then(|delta| delta.checked_add(max_peer_sequence_lag))
            else {
                return Err(IpsecLbError::unsafe_resume(
                    "ESP ESN forward-jump and peer receive lag overflow",
                ));
            };
            if resumed_sequence_delta > (1_u64 << 31) {
                return Err(IpsecLbError::unsafe_resume(
                    "ESP ESN forward-jump and peer receive lag exceed the reconstruction limit",
                ));
            }
        }

        let expected =
            match SendIvCounter::resume_with_margin(checkpointed_next, self.forward_jump)? {
                IvResumeDecision::Resume(counter) => counter,
                IvResumeDecision::RekeyRequired => {
                    return Err(IpsecLbError::unsafe_resume(
                        "send IV counter exhausted during forward-jump; rekey before sending",
                    ));
                }
            };
        if restored_next != expected.next() {
            return Err(IpsecLbError::unsafe_resume(
                "restored send IV counter does not match the proven forward-jump",
            ));
        }
        Ok(expected)
    }
}

/// Protocol-specific 64-bit counter mode for same-SPI IV forward-jump.
///
/// The variants are deliberately explicit: ESP requires Extended Sequence
/// Numbers, while IKE uses its independent 64-bit AEAD explicit-IV counter.
/// A legacy 32-bit ESP sequence space has no valid variant and must rekey.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SendIvCounterMode {
    /// ESP Child SA with 64-bit Extended Sequence Numbers enabled.
    EspExtendedSequenceNumbers {
        /// Caller-attested maximum number of sequence values by which the
        /// peer's highest authenticated sequence may trail
        /// `checkpointed_next - 1`.
        ///
        /// This must include pre-checkpoint packet loss or receive lag. Zero is
        /// an explicit attestation that the peer authenticated that sequence;
        /// omitting the evidence is impossible for this variant. Validation
        /// also requires this lag to be no greater than
        /// `checkpointed_next - 1`, allowing peer sequence zero without an
        /// unsigned subtraction.
        max_peer_sequence_lag: u64,
    },
    /// IKE SA with a monotonic 64-bit AEAD explicit-IV counter.
    IkeAeadExplicitIv64,
}

/// Caller-supplied evidence for restoring inbound anti-replay state.
///
/// A high watermark alone does not prove continuity of the replay bitmap.
/// These variants make the caller state whether the complete window is exact
/// or whether previously accepted packets may be accepted again within an
/// explicit operational bound. Fields remain public so decoded or otherwise
/// untrusted evidence can be represented and rejected by [`Self::validate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AntiReplayResume {
    /// The caller attests that the complete replay window, including every
    /// bitmap bit and its high watermark, was restored exactly. A periodic or
    /// otherwise stale checkpoint is not exact takeover state and must use
    /// [`Self::BoundedReopening`] instead.
    ExactWindowRestore {
        /// Highest accepted value in the source replay window.
        checkpoint_highest_accepted: u64,
        /// Highest accepted value in the installed replay window.
        restored_highest_accepted: u64,
    },
    /// Replay state was restored without claiming bitmap continuity.
    BoundedReopening {
        /// Highest accepted value in the last trusted checkpoint.
        checkpoint_highest_accepted: u64,
        /// Highest accepted value in the installed replay window.
        restored_highest_accepted: u64,
        /// Caller-attested maximum count of previously accepted sequence values
        /// that the survivor might accept again.
        ///
        /// This total covers every source of reopening, including lost bitmap
        /// bits and packets accepted after the checkpoint. It is deployment
        /// evidence (for example, replay-window width plus a receive-rate/checkpoint
        /// lag bound), not a library policy default. Zero is invalid; callers
        /// with no reopening use [`Self::ExactWindowRestore`].
        max_reopened_packets: u64,
    },
}

impl AntiReplayResume {
    /// Validate that installed state has the shape described by the evidence.
    ///
    /// Exact restore requires the installed high watermark to equal its source
    /// checkpoint. Bounded reopening may install that watermark or a later one,
    /// but never an earlier one, and requires a non-zero caller attestation.
    /// There is deliberately no hidden library maximum: the caller owns and
    /// exposes the deployment-specific bound.
    pub fn validate(self) -> Result<(), IpsecLbError> {
        match self {
            Self::ExactWindowRestore {
                checkpoint_highest_accepted,
                restored_highest_accepted,
            } => {
                if restored_highest_accepted != checkpoint_highest_accepted {
                    let reason = if restored_highest_accepted < checkpoint_highest_accepted {
                        "anti-replay window rollback would accept old packets"
                    } else {
                        "exact anti-replay restore does not match the checkpoint high watermark"
                    };
                    return Err(IpsecLbError::unsafe_resume(reason));
                }
            }
            Self::BoundedReopening {
                checkpoint_highest_accepted,
                restored_highest_accepted,
                max_reopened_packets,
            } => {
                if restored_highest_accepted < checkpoint_highest_accepted {
                    return Err(IpsecLbError::unsafe_resume(
                        "anti-replay window rollback would accept old packets",
                    ));
                }
                if max_reopened_packets == 0 {
                    return Err(IpsecLbError::unsafe_resume(
                        "bounded anti-replay reopening must attest a non-zero maximum",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iv_resume_advances_after_last_sent_or_requires_rekey_on_overflow() {
        assert_eq!(
            SendIvCounter::resume_after(41).unwrap(),
            IvResumeDecision::Resume(SendIvCounter::new(42))
        );
        assert_eq!(
            SendIvCounter::resume_after(u64::MAX).unwrap(),
            IvResumeDecision::RekeyRequired
        );
    }

    #[test]
    fn resume_with_margin_jumps_past_in_flight_window_or_rekeys() {
        // Resuming from a checkpoint must skip past the largest possible
        // in-flight IV window so no IV the departed owner may have sent is reused.
        assert_eq!(
            SendIvCounter::resume_with_margin(100, 50).unwrap(),
            IvResumeDecision::Resume(SendIvCounter::new(150))
        );
        // A margin that would overflow the counter forces a rekey rather than
        // wrapping into reuse.
        assert_eq!(
            SendIvCounter::resume_with_margin(u64::MAX, 1).unwrap(),
            IvResumeDecision::RekeyRequired
        );
    }

    #[test]
    fn forward_jump_proof_rejects_malformed_state_and_counter_exhaustion() {
        let esp_sa = SaId::Esp { spi: 1 };
        let proof = SendIvForwardJump {
            forward_jump: MIN_SEND_IV_FORWARD_JUMP,
            counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
                max_peer_sequence_lag: 0,
            },
        };
        assert_eq!(
            proof
                .validate_restored_next(esp_sa, 7, 7 + MIN_SEND_IV_FORWARD_JUMP)
                .unwrap(),
            SendIvCounter::new(7 + MIN_SEND_IV_FORWARD_JUMP)
        );

        assert!(matches!(
            SendIvForwardJump {
                counter_mode: SendIvCounterMode::IkeAeadExplicitIv64,
                ..proof
            }
            .validate_restored_next(esp_sa, 7, 7 + MIN_SEND_IV_FORWARD_JUMP),
            Err(IpsecLbError::UnsafeResume { .. })
        ));
        assert!(matches!(
            SendIvForwardJump {
                forward_jump: MIN_SEND_IV_FORWARD_JUMP - 1,
                ..proof
            }
            .validate_restored_next(esp_sa, 7, 7 + MIN_SEND_IV_FORWARD_JUMP - 1),
            Err(IpsecLbError::UnsafeResume { .. })
        ));
        for mismatched in [
            7 + MIN_SEND_IV_FORWARD_JUMP - 1,
            7 + MIN_SEND_IV_FORWARD_JUMP + 1,
        ] {
            assert!(matches!(
                proof.validate_restored_next(esp_sa, 7, mismatched),
                Err(IpsecLbError::UnsafeResume { .. })
            ));
        }

        // The final representable IV remains usable. Moving the checkpoint one
        // value higher would wrap the jump, so same-SPI resume must fail closed.
        let final_checkpoint = u64::MAX - MIN_SEND_IV_FORWARD_JUMP;
        assert_eq!(
            proof
                .validate_restored_next(esp_sa, final_checkpoint, u64::MAX)
                .unwrap(),
            SendIvCounter::new(u64::MAX)
        );
        assert!(matches!(
            proof.validate_restored_next(esp_sa, final_checkpoint + 1, u64::MAX),
            Err(IpsecLbError::UnsafeResume { .. })
        ));
        assert!(matches!(
            proof.validate_restored_next(esp_sa, 0, MIN_SEND_IV_FORWARD_JUMP),
            Err(IpsecLbError::UnsafeResume { .. })
        ));
        assert_eq!(
            proof
                .validate_restored_next(esp_sa, 1, 1 + MIN_SEND_IV_FORWARD_JUMP)
                .unwrap(),
            SendIvCounter::new(1 + MIN_SEND_IV_FORWARD_JUMP)
        );

        assert!(matches!(
            proof.validate_restored_next(SaId::Esp { spi: 0 }, 7, 7 + MIN_SEND_IV_FORWARD_JUMP,),
            Err(IpsecLbError::UnsafeResume { .. })
        ));
        assert!(matches!(
            SendIvForwardJump {
                forward_jump: MIN_SEND_IV_FORWARD_JUMP,
                counter_mode: SendIvCounterMode::IkeAeadExplicitIv64,
            }
            .validate_restored_next(
                SaId::Ike { responder_spi: 0 },
                7,
                7 + MIN_SEND_IV_FORWARD_JUMP,
            ),
            Err(IpsecLbError::UnsafeResume { .. })
        ));
    }

    #[test]
    fn forward_jump_counter_mode_must_match_esp_or_ike_sa() {
        let restored = 7 + MIN_SEND_IV_FORWARD_JUMP;
        let esp_proof = SendIvForwardJump {
            forward_jump: MIN_SEND_IV_FORWARD_JUMP,
            counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
                max_peer_sequence_lag: 0,
            },
        };
        let ike_proof = SendIvForwardJump {
            forward_jump: MIN_SEND_IV_FORWARD_JUMP,
            counter_mode: SendIvCounterMode::IkeAeadExplicitIv64,
        };
        let esp_sa = SaId::Esp { spi: 1 };
        let ike_sa = SaId::Ike { responder_spi: 1 };

        esp_proof
            .validate_restored_next(esp_sa, 7, restored)
            .unwrap();
        ike_proof
            .validate_restored_next(ike_sa, 7, restored)
            .unwrap();
        assert_eq!(
            ike_proof
                .validate_restored_next(ike_sa, 0, MIN_SEND_IV_FORWARD_JUMP)
                .unwrap(),
            SendIvCounter::new(MIN_SEND_IV_FORWARD_JUMP)
        );
        assert!(matches!(
            esp_proof.validate_restored_next(ike_sa, 7, restored),
            Err(IpsecLbError::UnsafeResume { .. })
        ));
        assert!(matches!(
            ike_proof.validate_restored_next(esp_sa, 7, restored),
            Err(IpsecLbError::UnsafeResume { .. })
        ));
    }

    #[test]
    fn esp_esn_lag_zero_forward_jump_caps_resume_delta_at_two_to_31() {
        let sa = SaId::Esp { spi: 1 };
        let checkpoint_next = 9_u64;
        let peer_last_at_checkpoint = checkpoint_next - 1;
        let maximum = SendIvForwardJump {
            forward_jump: MAX_ESP_SEND_IV_FORWARD_JUMP,
            counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
                max_peer_sequence_lag: 0,
            },
        };
        let first_resumed = checkpoint_next + MAX_ESP_SEND_IV_FORWARD_JUMP;

        maximum
            .validate_restored_next(sa, checkpoint_next, first_resumed)
            .unwrap();
        assert_eq!(first_resumed - peer_last_at_checkpoint, 1_u64 << 31);

        // One more skipped value makes the first resumed sequence more than
        // 2^31 ahead even under a zero-lag attestation and must fail closed.
        let beyond_lag_zero_ceiling = SendIvForwardJump {
            forward_jump: MAX_ESP_SEND_IV_FORWARD_JUMP + 1,
            counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
                max_peer_sequence_lag: 0,
            },
        };
        assert_eq!(
            checkpoint_next + beyond_lag_zero_ceiling.forward_jump - peer_last_at_checkpoint,
            (1_u64 << 31) + 1
        );
        assert!(matches!(
            beyond_lag_zero_ceiling.validate_restored_next(
                sa,
                checkpoint_next,
                checkpoint_next + beyond_lag_zero_ceiling.forward_jump,
            ),
            Err(IpsecLbError::UnsafeResume { .. })
        ));
    }

    #[test]
    fn esp_esn_peer_lag_reduces_the_permitted_jump_and_overflow_fails_closed() {
        let sa = SaId::Esp { spi: 1 };
        let checkpoint_next = 1_u64 << 32;

        let one_packet_lag_boundary = SendIvForwardJump {
            forward_jump: MAX_ESP_SEND_IV_FORWARD_JUMP - 1,
            counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
                max_peer_sequence_lag: 1,
            },
        };
        one_packet_lag_boundary
            .validate_restored_next(
                sa,
                checkpoint_next,
                checkpoint_next + one_packet_lag_boundary.forward_jump,
            )
            .unwrap();

        let one_packet_lag_over_limit = SendIvForwardJump {
            forward_jump: MAX_ESP_SEND_IV_FORWARD_JUMP,
            counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
                max_peer_sequence_lag: 1,
            },
        };
        assert!(matches!(
            one_packet_lag_over_limit.validate_restored_next(
                sa,
                checkpoint_next,
                checkpoint_next + one_packet_lag_over_limit.forward_jump,
            ),
            Err(IpsecLbError::UnsafeResume { .. })
        ));

        let maximum_lag_at_floor = (1_u64 << 31) - MIN_SEND_IV_FORWARD_JUMP - 1;
        let floor_boundary = SendIvForwardJump {
            forward_jump: MIN_SEND_IV_FORWARD_JUMP,
            counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
                max_peer_sequence_lag: maximum_lag_at_floor,
            },
        };
        floor_boundary
            .validate_restored_next(
                sa,
                checkpoint_next,
                checkpoint_next + MIN_SEND_IV_FORWARD_JUMP,
            )
            .unwrap();
        assert!(matches!(
            SendIvForwardJump {
                counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
                    max_peer_sequence_lag: maximum_lag_at_floor + 1,
                },
                ..floor_boundary
            }
            .validate_restored_next(
                sa,
                checkpoint_next,
                checkpoint_next + MIN_SEND_IV_FORWARD_JUMP,
            ),
            Err(IpsecLbError::UnsafeResume { .. })
        ));
        assert!(matches!(
            SendIvForwardJump {
                counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
                    max_peer_sequence_lag: maximum_lag_at_floor,
                },
                ..floor_boundary
            }
            .validate_restored_next(sa, 1, 1 + MIN_SEND_IV_FORWARD_JUMP,),
            Err(IpsecLbError::UnsafeResume { .. })
        ));
        assert!(matches!(
            SendIvForwardJump {
                counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
                    max_peer_sequence_lag: u64::MAX - 1,
                },
                ..floor_boundary
            }
            .validate_restored_next(sa, u64::MAX, u64::MAX),
            Err(IpsecLbError::UnsafeResume { .. })
        ));
    }

    #[test]
    fn ike_iv64_can_jump_beyond_the_esp_esn_reconstruction_maximum() {
        let checkpoint_next = 9_u64;
        let forward_jump = MAX_ESP_SEND_IV_FORWARD_JUMP + 1;
        let proof = SendIvForwardJump {
            forward_jump,
            counter_mode: SendIvCounterMode::IkeAeadExplicitIv64,
        };

        assert_eq!(
            proof
                .validate_restored_next(
                    SaId::Ike { responder_spi: 1 },
                    checkpoint_next,
                    checkpoint_next + forward_jump,
                )
                .unwrap(),
            SendIvCounter::new(checkpoint_next + forward_jump)
        );
    }

    #[test]
    fn forward_jump_is_strictly_beyond_every_possibly_consumed_iv() {
        // Exhaust the reduced arithmetic domain, including k == margin. The old
        // owner's next value after k packets is checkpoint_next + k, so every IV
        // it consumed is strictly smaller. This is the same checked-add formula
        // used for the full-width counter.
        for checkpoint_next in 0_u64..=63 {
            for margin in 0_u64..=63 {
                let IvResumeDecision::Resume(resumed) =
                    SendIvCounter::resume_with_margin(checkpoint_next, margin).unwrap()
                else {
                    panic!("small exhaustive domain cannot overflow");
                };
                for packets_sent in 0..=margin {
                    let old_owner_next = checkpoint_next.checked_add(packets_sent).unwrap();
                    assert!(old_owner_next <= resumed.next());
                    if packets_sent > 0 {
                        let highest_consumed = old_owner_next - 1;
                        assert!(highest_consumed < resumed.next());
                    }
                }
            }
        }

        // Adversarial full-width boundaries establish the same invariant at the
        // mandatory floor and immediately below counter exhaustion.
        let proof = SendIvForwardJump {
            forward_jump: MIN_SEND_IV_FORWARD_JUMP,
            counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
                max_peer_sequence_lag: 0,
            },
        };
        for checkpoint_next in [1, 2, u32::MAX as u64, u64::MAX - MIN_SEND_IV_FORWARD_JUMP] {
            let resumed = proof
                .validate_restored_next(
                    SaId::Esp { spi: 1 },
                    checkpoint_next,
                    checkpoint_next + MIN_SEND_IV_FORWARD_JUMP,
                )
                .unwrap();
            for packets_sent in [
                0,
                1,
                MIN_SEND_IV_FORWARD_JUMP / 2,
                MIN_SEND_IV_FORWARD_JUMP - 1,
                MIN_SEND_IV_FORWARD_JUMP,
            ] {
                let old_owner_next = checkpoint_next.checked_add(packets_sent).unwrap();
                assert!(old_owner_next <= resumed.next());
                if packets_sent > 0 {
                    assert!(old_owner_next - 1 < resumed.next());
                }
            }
        }
    }

    #[test]
    fn restored_iv_counter_must_not_roll_back() {
        assert!(SendIvCounter::validate_restored_next(11, 10).is_ok());
        assert!(matches!(
            SendIvCounter::validate_restored_next(9, 10).unwrap_err(),
            IpsecLbError::UnsafeResume { .. }
        ));
    }

    #[test]
    fn exact_anti_replay_restore_requires_checkpoint_bound_high_watermark() {
        AntiReplayResume::ExactWindowRestore {
            checkpoint_highest_accepted: 100,
            restored_highest_accepted: 100,
        }
        .validate()
        .unwrap();

        for restored_highest_accepted in [99, 101] {
            assert!(matches!(
                AntiReplayResume::ExactWindowRestore {
                    checkpoint_highest_accepted: 100,
                    restored_highest_accepted,
                }
                .validate(),
                Err(IpsecLbError::UnsafeResume { .. })
            ));
        }
    }

    #[test]
    fn bounded_anti_replay_reopening_rejects_malformed_and_rollback_shapes() {
        for restored_highest_accepted in [100, 101] {
            AntiReplayResume::BoundedReopening {
                checkpoint_highest_accepted: 100,
                restored_highest_accepted,
                max_reopened_packets: 64,
            }
            .validate()
            .unwrap();
        }

        assert!(matches!(
            AntiReplayResume::BoundedReopening {
                checkpoint_highest_accepted: 100,
                restored_highest_accepted: 99,
                max_reopened_packets: 64,
            }
            .validate(),
            Err(IpsecLbError::UnsafeResume { .. })
        ));
        assert!(matches!(
            AntiReplayResume::BoundedReopening {
                checkpoint_highest_accepted: 100,
                restored_highest_accepted: 100,
                max_reopened_packets: 0,
            }
            .validate(),
            Err(IpsecLbError::UnsafeResume { .. })
        ));

        // The attestation is a count, not a post-checkpoint sequence delta, so
        // it remains valid near counter exhaustion and has no hidden SDK cap.
        AntiReplayResume::BoundedReopening {
            checkpoint_highest_accepted: u64::MAX - 1,
            restored_highest_accepted: u64::MAX,
            max_reopened_packets: u64::MAX,
        }
        .validate()
        .unwrap();
    }
}
