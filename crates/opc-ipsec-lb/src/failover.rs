//! Pure failover safety guards.

use crate::error::IpsecLbError;

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
    /// headroom). The survivor then resumes strictly past that window, so no IV
    /// the departed owner may have used can be reused. Returns
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

/// Anti-replay resume guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AntiReplayResume {
    /// Highest sequence number accepted before loss.
    pub previous_highest_accepted: u64,
    /// Highest sequence number restored on survivor.
    pub restored_highest_accepted: u64,
}

impl AntiReplayResume {
    /// Validate that restore does not move the replay window backward.
    pub fn validate(self) -> Result<(), IpsecLbError> {
        if self.restored_highest_accepted < self.previous_highest_accepted {
            return Err(IpsecLbError::unsafe_resume(
                "anti-replay window rollback would accept old packets",
            ));
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
    fn restored_iv_counter_must_not_roll_back() {
        assert!(SendIvCounter::validate_restored_next(11, 10).is_ok());
        assert!(matches!(
            SendIvCounter::validate_restored_next(9, 10).unwrap_err(),
            IpsecLbError::UnsafeResume { .. }
        ));
    }

    #[test]
    fn anti_replay_state_must_not_roll_back() {
        AntiReplayResume {
            previous_highest_accepted: 100,
            restored_highest_accepted: 100,
        }
        .validate()
        .unwrap();
        assert!(AntiReplayResume {
            previous_highest_accepted: 100,
            restored_highest_accepted: 99,
        }
        .validate()
        .is_err());
    }
}
