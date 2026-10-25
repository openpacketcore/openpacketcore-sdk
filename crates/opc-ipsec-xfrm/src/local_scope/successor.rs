//! Scoped Child-SA rekey overlap: install a successor SA, move the one
//! protective policy to it, and retire the predecessor SA only once the
//! successor is live.
//!
//! The flow keeps the exact policy lookup identity (selector, direction, mark,
//! interface ID) throughout. The only kernel effect that moves traffic is the
//! atomic policy update (`XFRM_MSG_UPDPOLICY`, encoded from the successor
//! policy) from the predecessor request ID to the successor request ID; the
//! predecessor SA and its request ID remain untouched until the caller retires
//! it through [`retire_predecessor`]. No step removes the policy while traffic
//! could still select it, and undo restores the predecessor policy before
//! removing the successor SA.
//!
//! Every step is exact or reported as indeterminate, never assumed. Progress
//! flags are recorded before the first possible effect so a lost reply,
//! cancellation or panic resumes through readback (`undo`) instead of
//! repeating an uncertain effect.

use super::effect::{unresolved, Readback};
use crate::XfrmError;

/// Policy readback at the flow's exact lookup identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PolicyReadback {
    /// The policy at this identity equals the requested parameters.
    Exact,
    /// Some policy exists at this identity with different parameters.
    Other,
    /// No policy exists at this identity.
    Absent,
}

/// Actor-owned progress of one successor install and traffic move.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SuccessorProgress {
    pub(crate) sa_started: bool,
    pub(crate) sa_installed: bool,
    pub(crate) move_started: bool,
    pub(crate) moved: bool,
    pub(crate) published: bool,
    pub(crate) undo: bool,
    pub(crate) retired: bool,
}

/// Actor-owned progress of retiring one superseded predecessor SA.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PredecessorRetirementProgress {
    pub(crate) sa_started: bool,
    pub(crate) retired: bool,
}

/// Actor-owned progress of removing a successor after its predecessor retired.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SuccessorRemovalProgress {
    pub(crate) sa_started: bool,
    pub(crate) sa_removed: bool,
    pub(crate) policy_started: bool,
    pub(crate) retired: bool,
}

#[async_trait::async_trait]
pub(crate) trait SuccessorKernel: Send {
    fn local(&self) -> Result<(), XfrmError>;
    fn publication(&self) -> Result<(), XfrmError> {
        self.local()
    }
    async fn current(&self) -> Result<(), XfrmError>;
    async fn predecessor_sa(&mut self) -> Result<Readback, XfrmError>;
    async fn predecessor_policy(&mut self) -> Result<PolicyReadback, XfrmError>;
    async fn successor_sa(&mut self) -> Result<Readback, XfrmError>;
    async fn successor_policy(&mut self) -> Result<PolicyReadback, XfrmError>;
    async fn create_successor_sa(&mut self) -> Result<(), XfrmError>;
    async fn move_policy_to_successor(&mut self) -> Result<(), XfrmError>;
    async fn restore_policy_to_predecessor(&mut self) -> Result<(), XfrmError>;
    async fn remove_successor_sa(&mut self) -> Result<(), XfrmError>;
    async fn remove_successor_policy(&mut self) -> Result<(), XfrmError>;
    async fn remove_predecessor_sa(&mut self) -> Result<(), XfrmError>;
}

fn predecessor_not_live() -> XfrmError {
    XfrmError::StateMismatch {
        operation: "local_scope_successor_predecessor",
    }
}

/// Install the successor SA and atomically move the protective policy to it.
///
/// Preconditions are proved by fresh readback: the predecessor SA and policy
/// are exact and no successor SA is present. A failed or ambiguous step keeps
/// the recorded progress and requires [`undo`] through readback.
pub(crate) async fn install<K: SuccessorKernel>(
    kernel: &mut K,
    progress: &mut SuccessorProgress,
) -> Result<(), XfrmError> {
    if progress.sa_started
        || progress.move_started
        || progress.published
        || progress.undo
        || progress.retired
    {
        return Err(unresolved());
    }
    kernel.local()?;
    kernel.current().await?;
    if kernel.predecessor_sa().await? != Readback::Exact
        || kernel.predecessor_policy().await? != PolicyReadback::Exact
    {
        return Err(predecessor_not_live());
    }
    if kernel.successor_sa().await? != Readback::Absent {
        return Err(XfrmError::AlreadyExists);
    }
    kernel.local()?;
    kernel.current().await?;
    progress.sa_started = true;
    // Record uncertainty before submitting: readback decides, never a retry.
    let _ack = kernel.create_successor_sa().await;
    if kernel.successor_sa().await? != Readback::Exact {
        return Err(unresolved());
    }
    progress.sa_installed = true;
    kernel.local()?;
    kernel.current().await?;
    progress.move_started = true;
    let _ack = kernel.move_policy_to_successor().await;
    // The policy identity always exists exactly once. Exact successor evidence
    // proves the move even after a lost acknowledgement.
    match (
        kernel.successor_policy().await?,
        kernel.predecessor_policy().await?,
    ) {
        (PolicyReadback::Exact, PolicyReadback::Other) => {
            progress.moved = true;
            Ok(())
        }
        (PolicyReadback::Other, PolicyReadback::Exact) => {
            // Definite no-effect for the move: undo removes the candidate SA.
            Err(XfrmError::StateMismatch {
                operation: "local_scope_successor_policy_move",
            })
        }
        _ => Err(unresolved()),
    }
}

/// Publish the successor effect after fresh exact readback.
pub(crate) async fn publish<K: SuccessorKernel>(
    kernel: &mut K,
    progress: &mut SuccessorProgress,
    observer_closed: impl FnOnce() -> bool,
) -> Result<(), XfrmError> {
    if !progress.sa_installed
        || !progress.moved
        || progress.undo
        || progress.retired
        || progress.published
    {
        return Err(unresolved());
    }
    kernel.current().await?;
    if kernel.successor_sa().await? != Readback::Exact
        || kernel.successor_policy().await? != PolicyReadback::Exact
        || kernel.predecessor_policy().await? != PolicyReadback::Other
    {
        return Err(unresolved());
    }
    kernel.publication()?;
    if observer_closed() {
        return Err(unresolved());
    }
    progress.published = true;
    Ok(())
}

/// Reverse the successor install: restore the predecessor policy first, then
/// remove the successor SA. Never touches the predecessor SA or its policy
/// once restored.
pub(crate) async fn undo<K: SuccessorKernel>(
    kernel: &mut K,
    progress: &mut SuccessorProgress,
) -> Result<(), XfrmError> {
    progress.undo = true;
    if progress.retired {
        return Ok(());
    }
    kernel.local()?;
    if progress.move_started {
        match (
            kernel.successor_policy().await?,
            kernel.predecessor_policy().await?,
        ) {
            (PolicyReadback::Exact, PolicyReadback::Other) => {
                kernel.local()?;
                let _ack = kernel.restore_policy_to_predecessor().await;
                if kernel.predecessor_policy().await? != PolicyReadback::Exact
                    || kernel.successor_policy().await? != PolicyReadback::Other
                {
                    return Err(unresolved());
                }
                progress.moved = false;
            }
            (PolicyReadback::Other, PolicyReadback::Exact) => {
                // The move never landed; the predecessor still owns selection.
                progress.moved = false;
            }
            _ => return Err(unresolved()),
        }
    }
    if progress.sa_started {
        // Traffic must select the predecessor before its candidate disappears.
        if kernel.predecessor_policy().await? != PolicyReadback::Exact {
            return Err(unresolved());
        }
        match kernel.successor_sa().await? {
            Readback::Exact => {
                kernel.local()?;
                let _ack = kernel.remove_successor_sa().await;
            }
            Readback::Absent => {}
        }
        if kernel.successor_sa().await? != Readback::Absent {
            return Err(unresolved());
        }
    }
    progress.retired = true;
    Ok(())
}

/// Retire one superseded predecessor SA while its published successor owns the
/// protective policy. The policy is never read, moved or removed.
pub(crate) async fn retire_predecessor<K: SuccessorKernel>(
    kernel: &mut K,
    progress: &mut PredecessorRetirementProgress,
) -> Result<(), XfrmError> {
    if progress.retired {
        return Ok(());
    }
    kernel.local()?;
    // Only a live successor (SA *and* policy) authorizes dropping the
    // predecessor SA. If the successor SA expired or was removed, keeping the
    // predecessor is the last working path; never drop both.
    if kernel.successor_policy().await? != PolicyReadback::Exact
        || kernel.successor_sa().await? != Readback::Exact
    {
        return Err(XfrmError::StateMismatch {
            operation: "local_scope_successor_not_live",
        });
    }
    match kernel.predecessor_sa().await? {
        Readback::Exact => {
            progress.sa_started = true;
            kernel.local()?;
            let _ack = kernel.remove_predecessor_sa().await;
        }
        Readback::Absent => {}
    }
    if kernel.predecessor_sa().await? != Readback::Absent {
        return Err(unresolved());
    }
    progress.retired = true;
    Ok(())
}

/// Remove one published successor after its predecessor SA was retired.
///
/// The protective policy is kept until the successor SA is proved absent, so
/// traffic that still selects the old key fails closed instead of escaping
/// unprotected; the policy is removed last.
pub(crate) async fn remove_successor<K: SuccessorKernel>(
    kernel: &mut K,
    progress: &mut SuccessorRemovalProgress,
    predecessor_retired: bool,
) -> Result<(), XfrmError> {
    if progress.retired {
        return Ok(());
    }
    if !predecessor_retired {
        return Err(XfrmError::StateMismatch {
            operation: "local_scope_successor_predecessor_live",
        });
    }
    kernel.local()?;
    progress.sa_started = true;
    match kernel.successor_sa().await? {
        Readback::Exact => {
            kernel.local()?;
            let _ack = kernel.remove_successor_sa().await;
        }
        Readback::Absent => {}
    }
    if kernel.successor_sa().await? != Readback::Absent {
        return Err(unresolved());
    }
    progress.sa_removed = true;
    progress.policy_started = true;
    kernel.local()?;
    match kernel.successor_policy().await? {
        PolicyReadback::Exact => {
            let _ack = kernel.remove_successor_policy().await;
        }
        PolicyReadback::Absent => {}
        PolicyReadback::Other => return Err(unresolved()),
    }
    // A removed successor policy reads as some other policy at the identity or
    // absent; exactness is the only refusal.
    if kernel.successor_policy().await? == PolicyReadback::Exact {
        return Err(unresolved());
    }
    progress.retired = true;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::sync::Mutex;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Policy {
        Predecessor,
        Successor,
    }

    struct Port {
        predecessor_sa: Readback,
        successor_sa: Readback,
        policy: Policy,
        fail_create_sa: bool,
        lose_move_ack: bool,
        ambiguous_move: bool,
        reject_current: bool,
        policy_removed: bool,
        events: Mutex<Vec<&'static str>>,
    }
    impl Default for Port {
        fn default() -> Self {
            Self {
                predecessor_sa: Readback::Exact,
                successor_sa: Readback::Absent,
                policy: Policy::Predecessor,
                fail_create_sa: false,
                lose_move_ack: false,
                ambiguous_move: false,
                reject_current: false,
                policy_removed: false,
                events: Mutex::default(),
            }
        }
    }
    impl Port {
        fn event(&self, name: &'static str) {
            self.events.lock().unwrap().push(name);
        }
        fn events(&self) -> Vec<&'static str> {
            self.events.lock().unwrap().clone()
        }
        fn assert_flow_invariants(&self) {
            // `policy` is a closed enum: the single protective policy identity
            // always exists exactly once while either SA is live, and the SA it
            // selects is installed exactly. The successor steps can therefore
            // never expose an unprotected or black-holed interval.
            match self.policy {
                Policy::Predecessor => assert_eq!(self.predecessor_sa, Readback::Exact),
                Policy::Successor => assert_eq!(self.successor_sa, Readback::Exact),
            }
        }
    }
    #[async_trait::async_trait]
    impl SuccessorKernel for Port {
        fn local(&self) -> Result<(), XfrmError> {
            self.event("local");
            Ok(())
        }
        async fn current(&self) -> Result<(), XfrmError> {
            self.event("current");
            if self.reject_current {
                Err(XfrmError::Unavailable)
            } else {
                Ok(())
            }
        }
        async fn predecessor_sa(&mut self) -> Result<Readback, XfrmError> {
            self.event("read-predecessor-sa");
            Ok(self.predecessor_sa)
        }
        async fn predecessor_policy(&mut self) -> Result<PolicyReadback, XfrmError> {
            self.event("read-predecessor-policy");
            if self.policy_removed {
                return Ok(PolicyReadback::Absent);
            }
            Ok(match self.policy {
                Policy::Predecessor => PolicyReadback::Exact,
                Policy::Successor => PolicyReadback::Other,
            })
        }
        async fn successor_sa(&mut self) -> Result<Readback, XfrmError> {
            self.event("read-successor-sa");
            Ok(self.successor_sa)
        }
        async fn successor_policy(&mut self) -> Result<PolicyReadback, XfrmError> {
            self.event("read-successor-policy");
            if self.policy_removed {
                return Ok(PolicyReadback::Absent);
            }
            if self.ambiguous_move {
                return Err(XfrmError::StateIndeterminate {
                    operation: "local_scope_successor_policy_read",
                });
            }
            Ok(match self.policy {
                Policy::Successor => PolicyReadback::Exact,
                Policy::Predecessor => PolicyReadback::Other,
            })
        }
        async fn create_successor_sa(&mut self) -> Result<(), XfrmError> {
            self.event("create-successor-sa");
            assert_eq!(self.predecessor_sa, Readback::Exact);
            assert_eq!(self.policy, Policy::Predecessor);
            if !self.fail_create_sa {
                self.successor_sa = Readback::Exact;
            }
            if self.fail_create_sa {
                Err(XfrmError::Unavailable)
            } else {
                Ok(())
            }
        }
        async fn move_policy_to_successor(&mut self) -> Result<(), XfrmError> {
            self.event("move-policy-to-successor");
            assert_eq!(self.successor_sa, Readback::Exact);
            assert_eq!(self.policy, Policy::Predecessor);
            self.policy = Policy::Successor;
            if self.lose_move_ack {
                Err(XfrmError::Unavailable)
            } else {
                Ok(())
            }
        }
        async fn restore_policy_to_predecessor(&mut self) -> Result<(), XfrmError> {
            self.event("restore-policy-to-predecessor");
            assert_eq!(self.policy, Policy::Successor);
            self.policy = Policy::Predecessor;
            Ok(())
        }
        async fn remove_successor_sa(&mut self) -> Result<(), XfrmError> {
            self.event("remove-successor-sa");
            // Cancel-before-publication removes the candidate only after the
            // policy was restored. Terminal removal after predecessor
            // retirement removes the successor SA while its own policy still
            // selects it, then removes that policy.
            if self.predecessor_sa == Readback::Exact {
                assert_eq!(self.policy, Policy::Predecessor);
            }
            self.successor_sa = Readback::Absent;
            Ok(())
        }
        async fn remove_successor_policy(&mut self) -> Result<(), XfrmError> {
            self.event("remove-successor-policy");
            assert_eq!(self.successor_sa, Readback::Absent);
            assert!(!self.policy_removed);
            self.policy_removed = true;
            Ok(())
        }
        async fn remove_predecessor_sa(&mut self) -> Result<(), XfrmError> {
            self.event("remove-predecessor-sa");
            assert_eq!(self.policy, Policy::Successor);
            self.predecessor_sa = Readback::Absent;
            Ok(())
        }
    }

    async fn install_move_publish(port: &mut Port) {
        let mut progress = SuccessorProgress::default();
        install(port, &mut progress).await.unwrap();
        port.assert_flow_invariants();
        publish(port, &mut progress, || false).await.unwrap();
        assert!(progress.published);
        port.assert_flow_invariants();
    }

    #[tokio::test]
    async fn successor_move_precedes_any_predecessor_retirement() {
        let mut port = Port::default();
        install_move_publish(&mut port).await;
        let mut retirement = PredecessorRetirementProgress::default();
        retire_predecessor(&mut port, &mut retirement)
            .await
            .unwrap();
        assert!(retirement.retired);
        assert_eq!(port.predecessor_sa, Readback::Absent);
        assert_eq!(port.successor_sa, Readback::Exact);
        assert_eq!(port.policy, Policy::Successor);
        let events = port.events();
        let position = |name: &str| events.iter().position(|event| *event == name).unwrap();
        assert!(position("move-policy-to-successor") < position("remove-predecessor-sa"));
        assert!(!events.contains(&"remove-successor-policy"));
    }

    #[tokio::test]
    async fn failed_successor_sa_install_undoes_residue_without_moving_traffic() {
        let mut port = Port {
            fail_create_sa: true,
            ..Port::default()
        };
        let mut progress = SuccessorProgress::default();
        assert!(install(&mut port, &mut progress).await.is_err());
        assert!(progress.sa_started && !progress.sa_installed && !progress.moved);
        undo(&mut port, &mut progress).await.unwrap();
        assert!(progress.retired);
        assert_eq!(port.predecessor_sa, Readback::Exact);
        assert_eq!(port.successor_sa, Readback::Absent);
        assert_eq!(port.policy, Policy::Predecessor);
        assert!(!port.events().contains(&"move-policy-to-successor"));
    }

    #[tokio::test]
    async fn cancelled_successor_restores_predecessor_before_removing_candidate() {
        let mut port = Port::default();
        let mut progress = SuccessorProgress::default();
        install(&mut port, &mut progress).await.unwrap();
        assert!(progress.moved && !progress.published);
        undo(&mut port, &mut progress).await.unwrap();
        assert!(progress.retired);
        assert_eq!(port.predecessor_sa, Readback::Exact);
        assert_eq!(port.successor_sa, Readback::Absent);
        assert_eq!(port.policy, Policy::Predecessor);
        port.assert_flow_invariants();
        let events = port.events();
        let position = |name: &str| events.iter().position(|event| *event == name).unwrap();
        assert!(position("restore-policy-to-predecessor") < position("remove-successor-sa"));
    }

    #[tokio::test]
    async fn lost_move_ack_is_recovered_from_exact_policy_readback() {
        let mut port = Port {
            lose_move_ack: true,
            ..Port::default()
        };
        let mut progress = SuccessorProgress::default();
        install(&mut port, &mut progress).await.unwrap();
        assert!(progress.moved);
        publish(&mut port, &mut progress, || false).await.unwrap();
        assert!(progress.published);
    }

    #[tokio::test]
    async fn ambiguous_policy_readback_retains_successor_and_refuses_undo() {
        let mut port = Port {
            ambiguous_move: true,
            ..Port::default()
        };
        let mut progress = SuccessorProgress::default();
        assert!(install(&mut port, &mut progress).await.is_err());
        assert!(progress.sa_started);
        assert!(undo(&mut port, &mut progress).await.is_err());
        assert!(!progress.retired);
        assert_eq!(port.successor_sa, Readback::Exact);
        assert!(!port.events().contains(&"remove-successor-sa"));
    }

    #[tokio::test]
    async fn retirement_requires_a_live_successor_policy_and_never_touches_it() {
        let mut port = Port::default();
        let mut retirement = PredecessorRetirementProgress::default();
        assert!(matches!(
            retire_predecessor(&mut port, &mut retirement).await,
            Err(XfrmError::StateMismatch {
                operation: "local_scope_successor_not_live"
            })
        ));
        assert!(!retirement.sa_started);
        let mut progress = SuccessorProgress::default();
        install(&mut port, &mut progress).await.unwrap();
        publish(&mut port, &mut progress, || false).await.unwrap();
        retire_predecessor(&mut port, &mut retirement)
            .await
            .unwrap();
        assert_eq!(port.policy, Policy::Successor);
        assert_eq!(port.successor_sa, Readback::Exact);
    }

    #[tokio::test]
    async fn retirement_refuses_when_the_successor_sa_is_no_longer_live() {
        let mut port = Port::default();
        install_move_publish(&mut port).await;
        // Model a kernel hard-lifetime expiry of the successor SA: the policy
        // still selects it, but the successor SA is gone.
        port.successor_sa = Readback::Absent;
        let mut retirement = PredecessorRetirementProgress::default();
        assert!(matches!(
            retire_predecessor(&mut port, &mut retirement).await,
            Err(XfrmError::StateMismatch {
                operation: "local_scope_successor_not_live"
            })
        ));
        assert!(!retirement.sa_started && !retirement.retired);
        // The predecessor SA is retained as the last working path.
        assert_eq!(port.predecessor_sa, Readback::Exact);
        assert!(!port.events().contains(&"remove-predecessor-sa"));
    }

    #[tokio::test]
    async fn successor_residue_is_refused_before_any_effect() {
        let mut port = Port {
            successor_sa: Readback::Exact,
            ..Port::default()
        };
        let mut progress = SuccessorProgress::default();
        assert!(matches!(
            install(&mut port, &mut progress).await,
            Err(XfrmError::AlreadyExists)
        ));
        assert!(!progress.sa_started);
        assert!(!port.events().contains(&"create-successor-sa"));
    }

    #[tokio::test]
    async fn predecessor_retirement_and_policy_absence_never_unprotect_the_flow() {
        let mut port = Port::default();
        install_move_publish(&mut port).await;
        let mut retirement = PredecessorRetirementProgress::default();
        retire_predecessor(&mut port, &mut retirement)
            .await
            .unwrap();
        assert_eq!(port.successor_sa, Readback::Exact);
        assert_eq!(port.policy, Policy::Successor);
        port.assert_flow_invariants();
        // Removing the retired successor keeps the policy until the SA is gone.
        let mut removal = SuccessorRemovalProgress::default();
        remove_successor(&mut port, &mut removal, true)
            .await
            .unwrap();
        assert!(removal.retired);
        assert_eq!(port.successor_sa, Readback::Absent);
        let events = port.events();
        let position = |name: &str| events.iter().position(|event| *event == name).unwrap();
        assert!(position("remove-successor-sa") < position("remove-successor-policy"));
    }

    #[tokio::test]
    async fn successor_removal_is_refused_until_the_predecessor_was_retired() {
        let mut port = Port::default();
        install_move_publish(&mut port).await;
        let mut removal = SuccessorRemovalProgress::default();
        assert!(matches!(
            remove_successor(&mut port, &mut removal, false).await,
            Err(XfrmError::StateMismatch {
                operation: "local_scope_successor_predecessor_live"
            })
        ));
        assert_eq!(port.successor_sa, Readback::Exact);
        assert_eq!(port.policy, Policy::Successor);
    }
}
