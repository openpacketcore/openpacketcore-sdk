//! Actor-owned install and reverse undo. An uncertain SA is never reinstalled.

use crate::XfrmError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Readback {
    Absent,
    Exact,
}
#[derive(Default)]
pub(crate) struct Progress {
    pub(crate) policy_started: bool,
    pub(crate) sa_started: bool,
    pub(crate) installed: bool,
    pub(crate) published: bool,
    pub(crate) undo: bool,
    pub(crate) retired: bool,
}
#[async_trait::async_trait]
pub(crate) trait Kernel: Send {
    fn local(&self) -> Result<(), XfrmError>;
    fn publication(&self) -> Result<(), XfrmError> {
        self.local()
    }
    async fn current(&self) -> Result<(), XfrmError>;
    async fn policy(&mut self) -> Result<Readback, XfrmError>;
    async fn sa(&mut self) -> Result<Readback, XfrmError>;
    async fn create_policy(&mut self) -> Result<(), XfrmError>;
    async fn create_sa(&mut self) -> Result<(), XfrmError>;
    async fn remove_sa(&mut self) -> Result<(), XfrmError>;
    async fn remove_policy(&mut self) -> Result<(), XfrmError>;
}
fn unresolved() -> XfrmError {
    XfrmError::StateIndeterminate {
        operation: "local_scope_effect",
    }
}

pub(crate) async fn install<K: Kernel>(
    kernel: &mut K,
    progress: &mut Progress,
) -> Result<(), XfrmError> {
    if progress.undo || progress.policy_started || progress.sa_started || progress.retired {
        return Err(unresolved());
    }
    let result = install_once(kernel, progress).await;
    if result.is_err() {
        progress.undo = true;
    }
    result
}
async fn install_once<K: Kernel>(kernel: &mut K, progress: &mut Progress) -> Result<(), XfrmError> {
    kernel.local()?;
    kernel.current().await?;
    if kernel.sa().await? != Readback::Absent || kernel.policy().await? != Readback::Absent {
        return Err(XfrmError::AlreadyExists);
    }
    kernel.local()?;
    kernel.current().await?;
    progress.policy_started = true;
    let _ack = kernel.create_policy().await;
    if kernel.policy().await? != Readback::Exact {
        return Err(unresolved());
    }
    kernel.local()?;
    kernel.current().await?;
    progress.sa_started = true;
    let _ack = kernel.create_sa().await;
    if kernel.sa().await? != Readback::Exact || kernel.policy().await? != Readback::Exact {
        return Err(unresolved());
    }
    progress.installed = true;
    Ok(())
}
pub(crate) async fn undo<K: Kernel>(
    kernel: &mut K,
    progress: &mut Progress,
) -> Result<(), XfrmError> {
    progress.undo = true;
    if progress.retired {
        return Ok(());
    }
    kernel.local()?;
    if progress.sa_started {
        if kernel.sa().await? == Readback::Exact {
            // Preserve the exact protective policy until our SA is absent.
            if kernel.policy().await? != Readback::Exact {
                return Err(unresolved());
            }
            kernel.local()?;
            let _ack = kernel.remove_sa().await;
        }
        if kernel.sa().await? != Readback::Absent {
            return Err(unresolved());
        }
    }
    if progress.policy_started {
        kernel.local()?;
        if kernel.policy().await? == Readback::Exact {
            let _ack = kernel.remove_policy().await;
        }
        if kernel.policy().await? != Readback::Absent {
            return Err(unresolved());
        }
    }
    progress.retired = true;
    Ok(())
}

pub(crate) async fn publish<K: Kernel>(
    kernel: &mut K,
    progress: &mut Progress,
    observer_closed: impl FnOnce() -> bool,
) -> Result<(), XfrmError> {
    if !progress.installed || progress.undo || progress.retired || progress.published {
        return Err(unresolved());
    }
    kernel.current().await?;
    if kernel.sa().await? != Readback::Exact || kernel.policy().await? != Readback::Exact {
        return Err(unresolved());
    }
    kernel.publication()?;
    if observer_closed() {
        return Err(unresolved());
    }
    // No suspension between the decision and recording publication. Reply
    // loss after this point never changes a successful install into undo.
    progress.published = true;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    struct Port {
        events: Mutex<Vec<&'static str>>,
        sa: Readback,
        policy: Readback,
        reject_current: bool,
        retire_after_policy_read: Option<Readback>,
        fail_sa: bool,
        lost_acks: bool,
        foreign: bool,
    }
    impl Default for Port {
        fn default() -> Self {
            Self {
                events: Mutex::new(vec![]),
                sa: Readback::Absent,
                policy: Readback::Absent,
                reject_current: false,
                retire_after_policy_read: None,
                fail_sa: false,
                lost_acks: false,
                foreign: false,
            }
        }
    }
    #[async_trait::async_trait]
    impl Kernel for Port {
        fn local(&self) -> Result<(), XfrmError> {
            self.events.lock().unwrap().push("local");
            Ok(())
        }
        async fn current(&self) -> Result<(), XfrmError> {
            self.events.lock().unwrap().push("current");
            if self.reject_current {
                Err(XfrmError::Unavailable)
            } else {
                Ok(())
            }
        }
        async fn policy(&mut self) -> Result<Readback, XfrmError> {
            self.events.lock().unwrap().push("read-policy");
            if self.retire_after_policy_read == Some(self.policy) {
                self.reject_current = true;
            }
            Ok(self.policy)
        }
        async fn sa(&mut self) -> Result<Readback, XfrmError> {
            self.events.lock().unwrap().push("read-sa");
            if self.foreign {
                Err(XfrmError::StateMismatch { operation: "keys" })
            } else {
                Ok(self.sa)
            }
        }
        async fn create_policy(&mut self) -> Result<(), XfrmError> {
            self.events.lock().unwrap().push("create-policy");
            self.policy = Readback::Exact;
            Ok(())
        }
        async fn create_sa(&mut self) -> Result<(), XfrmError> {
            assert_eq!(self.policy, Readback::Exact);
            self.events.lock().unwrap().push("create-sa");
            if !self.fail_sa {
                self.sa = Readback::Exact;
            }
            if self.lost_acks || self.fail_sa {
                Err(XfrmError::Unavailable)
            } else {
                Ok(())
            }
        }
        async fn remove_sa(&mut self) -> Result<(), XfrmError> {
            assert_eq!(self.policy, Readback::Exact);
            self.events.lock().unwrap().push("remove-sa");
            self.sa = Readback::Absent;
            if self.lost_acks {
                Err(XfrmError::Unavailable)
            } else {
                Ok(())
            }
        }
        async fn remove_policy(&mut self) -> Result<(), XfrmError> {
            assert_eq!(self.sa, Readback::Absent);
            self.events.lock().unwrap().push("remove-policy");
            self.policy = Readback::Absent;
            Ok(())
        }
    }
    #[tokio::test]
    async fn undo_refuses_an_sa_without_its_exact_protective_policy() {
        let mut port = Port {
            sa: Readback::Exact,
            policy: Readback::Absent,
            ..Port::default()
        };
        let mut progress = Progress {
            sa_started: true,
            policy_started: true,
            ..Progress::default()
        };
        assert!(undo(&mut port, &mut progress).await.is_err());
        assert_eq!(port.sa, Readback::Exact);
        assert!(!progress.retired);
        assert!(!port
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event.starts_with("remove-")));
        // Only an exact policy readback allows reverse undo to resume.
        port.policy = Readback::Exact;
        undo(&mut port, &mut progress).await.unwrap();
        assert_eq!(port.sa, Readback::Absent);
        assert_eq!(port.policy, Readback::Absent);
        assert!(progress.retired);
    }

    #[tokio::test]
    async fn retirement_after_preflight_or_policy_read_blocks_the_next_mutation() {
        for boundary in [Readback::Absent, Readback::Exact] {
            let mut port = Port {
                retire_after_policy_read: Some(boundary),
                ..Port::default()
            };
            let mut progress = Progress::default();
            assert!(install(&mut port, &mut progress).await.is_err());
            assert_eq!(port.sa, Readback::Absent);
            assert_eq!(port.policy, boundary);
            assert!(!progress.installed && !progress.published);
            undo(&mut port, &mut progress).await.unwrap();
            assert_eq!(port.policy, Readback::Absent);
            assert!(progress.retired);
        }
    }
    #[tokio::test]
    async fn publication_requires_fresh_authority_and_a_live_observer() {
        for cancelled in [false, true] {
            let mut port = Port::default();
            let mut progress = Progress::default();
            install(&mut port, &mut progress).await.unwrap();
            port.reject_current = !cancelled;
            assert!(publish(&mut port, &mut progress, || cancelled)
                .await
                .is_err());
            assert!(!progress.published);
            undo(&mut port, &mut progress).await.unwrap();
            assert_eq!(port.sa, Readback::Absent);
            assert_eq!(port.policy, Readback::Absent);
        }
    }
    #[tokio::test]
    async fn expiration_before_publication_refuses_and_reply_loss_after_keeps_forwarding() {
        let mut port = Port::default();
        let mut progress = Progress::default();
        install(&mut port, &mut progress).await.unwrap();
        port.sa = Readback::Absent;
        assert!(publish(&mut port, &mut progress, || false).await.is_err());
        assert!(!progress.published);
        let mut port = Port::default();
        let mut progress = Progress::default();
        install(&mut port, &mut progress).await.unwrap();
        let (reply, observer) = tokio::sync::oneshot::channel();
        publish(&mut port, &mut progress, || reply.is_closed())
            .await
            .unwrap();
        drop(observer);
        assert!(reply.send(()).is_err());
        assert!(progress.published);
        assert!(!progress.undo);
        assert_eq!(port.sa, Readback::Exact);
        assert_eq!(port.policy, Readback::Exact);
    }
    #[tokio::test]
    async fn protective_policy_precedes_sa_and_survives_until_confirmed_reverse_undo() {
        let mut port = Port {
            lost_acks: true,
            ..Port::default()
        };
        let mut progress = Progress::default();
        install(&mut port, &mut progress).await.unwrap();
        assert!(progress.installed);
        port.reject_current = true;
        undo(&mut port, &mut progress).await.unwrap();
        assert!(progress.retired);
        let events = port.events.lock().unwrap();
        let effects = events
            .iter()
            .filter(|e| e.starts_with("create-") || e.starts_with("remove-"))
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(
            effects,
            ["create-policy", "create-sa", "remove-sa", "remove-policy"]
        );
    }
    #[tokio::test]
    async fn failed_sa_install_is_undone_and_never_reinstalls_an_uncertain_key() {
        let mut port = Port {
            fail_sa: true,
            ..Port::default()
        };
        let mut progress = Progress::default();
        assert!(install(&mut port, &mut progress).await.is_err());
        assert_eq!(port.policy, Readback::Exact);
        port.fail_sa = false;
        assert!(
            install(&mut port, &mut progress).await.is_err(),
            "a prior attempt might have used and expired this key"
        );
        undo(&mut port, &mut progress).await.unwrap();
        assert!(progress.retired);
        assert_eq!(port.policy, Readback::Absent);
        assert_eq!(
            port.events
                .lock()
                .unwrap()
                .iter()
                .filter(|e| **e == "create-sa")
                .count(),
            1
        );
    }
    #[tokio::test]
    async fn changed_keys_preserve_both_the_occupant_and_protective_policy() {
        let mut port = Port::default();
        let mut progress = Progress::default();
        install(&mut port, &mut progress).await.unwrap();
        port.foreign = true;
        assert!(undo(&mut port, &mut progress).await.is_err());
        assert_eq!(port.sa, Readback::Exact);
        assert_eq!(port.policy, Readback::Exact);
        assert!(!port.events.lock().unwrap().contains(&"remove-sa"));
        assert!(!port.events.lock().unwrap().contains(&"remove-policy"));
    }
    #[tokio::test]
    async fn expiration_is_absence_but_does_not_admit_key_reuse_before_undo() {
        let mut port = Port::default();
        let mut progress = Progress::default();
        install(&mut port, &mut progress).await.unwrap();
        port.sa = Readback::Absent;
        undo(&mut port, &mut progress).await.unwrap();
        assert!(progress.retired);
        assert!(!port.events.lock().unwrap().contains(&"remove-sa"));
    }
    #[tokio::test]
    async fn stale_activation_has_no_policy_or_sa_effect() {
        let mut port = Port {
            reject_current: true,
            ..Port::default()
        };
        let mut progress = Progress::default();
        assert!(install(&mut port, &mut progress).await.is_err());
        assert!(!progress.policy_started && !progress.sa_started);
        assert!(!port.events.lock().unwrap().contains(&"create-policy"));
    }
}
