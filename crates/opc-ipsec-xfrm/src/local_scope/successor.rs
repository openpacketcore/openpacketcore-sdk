//! Scoped Child-SA overlap with resumable installation and exact retirement.
//! Outbound selection changes atomically; inbound generations share the same
//! protective policy. Lost observers never undo a completed traffic move.

use super::effect::{unresolved, Readback};
use crate::XfrmError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PolicyReadback {
    Exact,
    Other,
    Absent,
}

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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PredecessorRetirementProgress {
    pub(crate) sa_started: bool,
    pub(crate) retired: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SuccessorRemovalProgress {
    pub(crate) restored: bool,
    pub(crate) sa_started: bool,
    pub(crate) sa_removed: bool,
    pub(crate) policy_started: bool,
    pub(crate) retired: bool,
}

#[async_trait::async_trait]
pub(crate) trait SuccessorKernel: Send {
    fn outbound(&self) -> bool;
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
fn successor_not_live() -> XfrmError {
    XfrmError::StateMismatch {
        operation: "local_scope_successor_not_live",
    }
}

/// Resume from readback after every uncertain effect. A started SA creation is
/// never repeated, since that could reset sequence and replay state.
pub(crate) async fn install<K: SuccessorKernel>(
    kernel: &mut K,
    progress: &mut SuccessorProgress,
) -> Result<(), XfrmError> {
    if progress.undo || progress.retired || progress.published {
        return Err(unresolved());
    }
    kernel.local()?;
    if !progress.sa_started {
        kernel.current().await?;
        if kernel.predecessor_sa().await? != Readback::Exact
            || kernel.predecessor_policy().await? != PolicyReadback::Exact
        {
            return Err(predecessor_not_live());
        }
        if kernel.successor_sa().await? != Readback::Absent {
            return Err(XfrmError::AlreadyExists);
        }
        kernel.current().await?;
        progress.sa_started = true;
        let _ack = kernel.create_successor_sa().await;
    }
    if kernel.successor_sa().await? != Readback::Exact {
        // Exact absence is a failed/expired creation, not permission to reuse
        // this SPI under the consumed activation.
        progress.undo = true;
        return Err(unresolved());
    }
    progress.sa_installed = true;
    if !kernel.outbound() {
        if kernel.predecessor_policy().await? != PolicyReadback::Exact
            || kernel.successor_policy().await? != PolicyReadback::Exact
        {
            return Err(unresolved());
        }
        progress.move_started = true;
        progress.moved = true;
        return Ok(());
    }
    match (
        kernel.successor_policy().await?,
        kernel.predecessor_policy().await?,
    ) {
        (PolicyReadback::Exact, PolicyReadback::Other) if progress.move_started => {
            progress.moved = true;
            return Ok(());
        }
        (PolicyReadback::Other, PolicyReadback::Exact) => {}
        _ => return Err(unresolved()),
    }
    // This is the only outbound cutover. Recheck committed authority before
    // submitting it, but never let a later store outage undo an observed move.
    kernel.current().await?;
    progress.move_started = true;
    let _ack = kernel.move_policy_to_successor().await;
    match (
        kernel.successor_policy().await?,
        kernel.predecessor_policy().await?,
    ) {
        (PolicyReadback::Exact, PolicyReadback::Other) => {
            progress.moved = true;
            Ok(())
        }
        (PolicyReadback::Other, PolicyReadback::Exact) => {
            progress.undo = true;
            Err(XfrmError::StateMismatch {
                operation: "local_scope_successor_policy_move",
            })
        }
        _ => Err(unresolved()),
    }
}

/// Publication is retained by the actor, independently of reply delivery.
pub(crate) async fn publish<K: SuccessorKernel>(
    kernel: &mut K,
    progress: &mut SuccessorProgress,
    _observer_closed: impl FnOnce() -> bool,
) -> Result<(), XfrmError> {
    if !progress.sa_installed || !progress.moved || progress.undo || progress.retired {
        return Err(unresolved());
    }
    kernel.local()?;
    if kernel.successor_sa().await? != Readback::Exact
        || kernel.successor_policy().await? != PolicyReadback::Exact
        || kernel.predecessor_policy().await?
            != if kernel.outbound() {
                PolicyReadback::Other
            } else {
                PolicyReadback::Exact
            }
    {
        return Err(unresolved());
    }
    kernel.publication()?;
    progress.published = true;
    Ok(())
}

/// Undo only an unpublished candidate whose operation has been fenced or
/// definitively refused. Restore selection before removing its exact SA.
pub(crate) async fn undo<K: SuccessorKernel>(
    kernel: &mut K,
    progress: &mut SuccessorProgress,
) -> Result<(), XfrmError> {
    progress.undo = true;
    if progress.retired {
        return Ok(());
    }
    kernel.local()?;
    if progress.sa_started && kernel.outbound() {
        // An uncertain policy read before cutover is still insufficient proof
        // that deleting the candidate preserves the selected protection.
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
            }
            (PolicyReadback::Other, PolicyReadback::Exact) => {}
            _ => return Err(unresolved()),
        }
        progress.moved = false;
    }
    if progress.sa_started {
        // Fenced unpublished work must release its reset guard even if the
        // predecessor has expired. Keep the predecessor's protective policy
        // while removing only this operation's candidate SA.
        if kernel.predecessor_policy().await? != PolicyReadback::Exact {
            return Err(unresolved());
        }
        if kernel.successor_sa().await? == Readback::Exact {
            kernel.local()?;
            let _ack = kernel.remove_successor_sa().await;
        }
        if kernel.successor_sa().await? != Readback::Absent {
            return Err(unresolved());
        }
    }
    progress.retired = true;
    Ok(())
}

/// Retire an unselected member without touching the shared policy. A live
/// member cannot be dropped while the selected SA has disappeared; a member
/// already absent from the kernel needs only its retained reservation released.
pub(crate) async fn retire_predecessor<K: SuccessorKernel>(
    kernel: &mut K,
    progress: &mut PredecessorRetirementProgress,
) -> Result<(), XfrmError> {
    if progress.retired {
        return Ok(());
    }
    kernel.local()?;
    if kernel.predecessor_sa().await? == Readback::Absent {
        progress.retired = true;
        return Ok(());
    }
    if kernel.successor_policy().await? != PolicyReadback::Exact
        || kernel.successor_sa().await? != Readback::Exact
    {
        return Err(successor_not_live());
    }
    progress.sa_started = true;
    kernel.local()?;
    let _ack = kernel.remove_predecessor_sa().await;
    if kernel.predecessor_sa().await? != Readback::Absent {
        return Err(unresolved());
    }
    progress.retired = true;
    Ok(())
}

/// Abandon a selected successor by restoring another retained member first,
/// or remove the final SA and then its policy. Both-expired groups can restore
/// a still-protective policy and release their receipts in either order.
pub(crate) async fn remove_successor<K: SuccessorKernel>(
    kernel: &mut K,
    progress: &mut SuccessorRemovalProgress,
    predecessor_retired: bool,
) -> Result<(), XfrmError> {
    if progress.retired {
        return Ok(());
    }
    kernel.local()?;
    if !predecessor_retired {
        let old_policy = kernel.predecessor_policy().await?;
        let new_policy = kernel.successor_policy().await?;
        let restored = old_policy == PolicyReadback::Exact
            && new_policy
                == if kernel.outbound() {
                    PolicyReadback::Other
                } else {
                    PolicyReadback::Exact
                };
        if restored {
            progress.restored = true;
        }
        let old_sa = kernel.predecessor_sa().await?;
        let new_sa = kernel.successor_sa().await?;
        if old_sa != Readback::Exact && new_sa != Readback::Absent {
            return Err(successor_not_live());
        }
        if !restored {
            if !kernel.outbound()
                || old_policy != PolicyReadback::Other
                || new_policy != PolicyReadback::Exact
            {
                return Err(unresolved());
            }
            kernel.local()?;
            let _ack = kernel.restore_policy_to_predecessor().await;
            if kernel.predecessor_policy().await? != PolicyReadback::Exact
                || kernel.successor_policy().await? != PolicyReadback::Other
            {
                return Err(unresolved());
            }
            progress.restored = true;
        }
        // Expiry can race policy replacement. Retain the current live SA and
        // expose the new selection so a later receipt operation can restore it.
        if kernel.predecessor_sa().await? != Readback::Exact
            && kernel.successor_sa().await? != Readback::Absent
        {
            return Err(successor_not_live());
        }
    }
    progress.sa_started = true;
    match kernel.successor_sa().await? {
        Readback::Exact => {
            if predecessor_retired && kernel.successor_policy().await? != PolicyReadback::Exact {
                return Err(unresolved());
            }
            kernel.local()?;
            let _ack = kernel.remove_successor_sa().await;
        }
        Readback::Absent => {}
    }
    if kernel.successor_sa().await? != Readback::Absent {
        return Err(unresolved());
    }
    progress.sa_removed = true;
    if predecessor_retired {
        progress.policy_started = true;
        kernel.local()?;
        match kernel.successor_policy().await? {
            PolicyReadback::Exact => {
                let _ack = kernel.remove_successor_policy().await;
            }
            PolicyReadback::Absent => {}
            PolicyReadback::Other => return Err(unresolved()),
        }
        if kernel.successor_policy().await? != PolicyReadback::Absent {
            return Err(unresolved());
        }
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
        inbound: bool,
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
                inbound: false,
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
        fn outbound(&self) -> bool {
            !self.inbound
        }
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
            if self.inbound {
                return Ok(PolicyReadback::Exact);
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
            assert!(
                !self.inbound,
                "inbound SAs share their unchanged protective policy"
            );
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
            assert_eq!(
                self.policy,
                if self.inbound {
                    Policy::Predecessor
                } else {
                    Policy::Successor
                }
            );
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
    async fn successor_removal_restores_a_retained_predecessor_without_deleting_its_policy() {
        let mut port = Port::default();
        install_move_publish(&mut port).await;
        let mut removal = SuccessorRemovalProgress::default();
        // Retirement is no longer a mandatory order: RFC 7296 section 2.8.1
        // permits abandoning a newly created Child SA. Preserve the live
        // predecessor and its protection while deleting only the candidate.
        remove_successor(&mut port, &mut removal, false)
            .await
            .unwrap();
        assert!(removal.retired && removal.restored);
        assert_eq!(port.predecessor_sa, Readback::Exact);
        assert_eq!(port.successor_sa, Readback::Absent);
        assert_eq!(port.policy, Policy::Predecessor);
        assert!(!port.policy_removed);
    }
    #[tokio::test]
    async fn successor_resumes_interrupted_sa_and_policy_steps_without_reinstalling() {
        for after_move in [false, true] {
            let mut port = Port {
                successor_sa: Readback::Exact,
                policy: if after_move {
                    Policy::Successor
                } else {
                    Policy::Predecessor
                },
                ..Port::default()
            };
            let mut progress = SuccessorProgress {
                sa_started: true,
                move_started: after_move,
                ..SuccessorProgress::default()
            };
            install(&mut port, &mut progress).await.unwrap();
            publish(&mut port, &mut progress, || false).await.unwrap();
            assert!(progress.sa_installed && progress.moved && progress.published);
            assert!(!port.events().contains(&"create-successor-sa"));
            assert!(!port.events().contains(&"remove-successor-sa"));
            port.assert_flow_invariants();
        }
    }

    #[tokio::test]
    async fn successor_publication_survives_lost_observer_after_traffic_moved() {
        let mut port = Port::default();
        let mut progress = SuccessorProgress::default();
        install(&mut port, &mut progress).await.unwrap();
        publish(&mut port, &mut progress, || true).await.unwrap();
        assert!(progress.published);
        assert_eq!(port.successor_sa, Readback::Exact);
        assert_eq!(port.policy, Policy::Successor);
        assert!(!port.events().contains(&"restore-policy-to-predecessor"));
        assert!(!port.events().contains(&"remove-successor-sa"));
    }

    #[tokio::test]
    async fn successor_publication_does_not_revoke_moved_traffic_on_store_outage() {
        let mut port = Port::default();
        let mut progress = SuccessorProgress::default();
        install(&mut port, &mut progress).await.unwrap();
        port.reject_current = true;
        publish(&mut port, &mut progress, || false).await.unwrap();
        assert!(progress.published);
        port.assert_flow_invariants();
    }

    #[tokio::test]
    async fn successor_abandonment_restores_live_predecessor_and_keeps_protection() {
        let mut port = Port::default();
        install_move_publish(&mut port).await;
        let mut progress = SuccessorRemovalProgress::default();
        remove_successor(&mut port, &mut progress, false)
            .await
            .unwrap();
        assert!(progress.retired);
        assert_eq!(port.predecessor_sa, Readback::Exact);
        assert_eq!(port.successor_sa, Readback::Absent);
        assert_eq!(port.policy, Policy::Predecessor);
        assert!(!port.policy_removed);
        let events = port.events();
        let position = |name: &str| events.iter().position(|event| *event == name).unwrap();
        assert!(position("restore-policy-to-predecessor") < position("remove-successor-sa"));
        assert!(!events.contains(&"remove-successor-policy"));
        port.assert_flow_invariants();
    }

    #[tokio::test]
    async fn successor_inbound_overlap_never_replaces_its_shared_policy() {
        let mut port = Port {
            inbound: true,
            ..Port::default()
        };
        let mut progress = SuccessorProgress::default();
        install(&mut port, &mut progress).await.unwrap();
        publish(&mut port, &mut progress, || false).await.unwrap();
        assert!(progress.published && progress.sa_installed && progress.moved);
        assert_eq!(port.predecessor_sa, Readback::Exact);
        assert_eq!(port.successor_sa, Readback::Exact);
        assert_eq!(port.policy, Policy::Predecessor);
        let mut retirement = PredecessorRetirementProgress::default();
        retire_predecessor(&mut port, &mut retirement)
            .await
            .unwrap();
        assert_eq!(port.predecessor_sa, Readback::Absent);
        assert_eq!(port.successor_sa, Readback::Exact);
        assert_eq!(port.policy, Policy::Predecessor);
        assert!(!port.events().contains(&"move-policy-to-successor"));
        assert!(!port.events().contains(&"remove-successor-policy"));
    }
}
