//! Transient grouped-session effects. Active group publication follows every
//! selector; teardown removes group authority and drains readers first.
use crate::GtpuError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Readback {
    Absent,
    Exact,
}
#[derive(Default)]
pub(crate) struct Progress {
    pub(crate) indexes_started: u8,
    pub(crate) group_started: bool,
    pub(crate) installed: bool,
    pub(crate) published: bool,
    pub(crate) undo: bool,
    pub(crate) retired: bool,
}
#[async_trait::async_trait]
pub(crate) trait Kernel: Send {
    fn index_count(&self) -> usize;
    fn local(&self) -> Result<(), GtpuError>;
    fn publication(&self) -> Result<(), GtpuError>;
    async fn current(&self) -> Result<(), GtpuError>;
    fn group(&self) -> Result<Readback, GtpuError>;
    fn index(&self, index: usize) -> Result<Readback, GtpuError>;
    fn create_index(&mut self, index: usize) -> Result<(), GtpuError>;
    async fn create_group(&mut self) -> Result<(), GtpuError>;
    fn remove_group(&mut self) -> Result<(), GtpuError>;
    fn remove_index(&mut self, index: usize) -> Result<(), GtpuError>;
    fn synchronize_readers(&self) -> Result<(), GtpuError>;
}
fn uncertain() -> GtpuError {
    GtpuError::StateIndeterminate {
        operation: "ebpf_local_session",
    }
}
pub(crate) async fn install(
    kernel: &mut impl Kernel,
    progress: &mut Progress,
) -> Result<(), GtpuError> {
    if progress.undo || progress.retired || progress.group_started || progress.indexes_started != 0
    {
        return Err(uncertain());
    }
    let result = install_once(kernel, progress).await;
    if result.is_err() {
        progress.undo = true;
    }
    result
}
async fn install_once(kernel: &mut impl Kernel, progress: &mut Progress) -> Result<(), GtpuError> {
    if !(1..=4).contains(&kernel.index_count()) {
        return Err(uncertain());
    }
    kernel.local()?;
    kernel.current().await?;
    if kernel.group()? != Readback::Absent {
        return Err(GtpuError::AlreadyExists);
    }
    for index in 0..kernel.index_count() {
        if kernel.index(index)? != Readback::Absent {
            return Err(GtpuError::AlreadyExists);
        }
    }
    for index in 0..kernel.index_count() {
        kernel.current().await?;
        kernel.local()?;
        progress.indexes_started |= 1 << index;
        let _ack = kernel.create_index(index);
        if kernel.index(index)? != Readback::Exact {
            return Err(uncertain());
        }
    }
    kernel.current().await?;
    kernel.local()?;
    progress.group_started = true;
    let _ack = kernel.create_group().await;
    if !read_installed(kernel)? {
        return Err(uncertain());
    }
    progress.installed = true;
    Ok(())
}
pub(crate) fn read_installed(kernel: &impl Kernel) -> Result<bool, GtpuError> {
    kernel.local()?;
    if kernel.group()? != Readback::Exact {
        return Ok(false);
    }
    for index in 0..kernel.index_count() {
        if kernel.index(index)? != Readback::Exact {
            return Ok(false);
        }
    }
    Ok(true)
}
pub(crate) async fn publish(
    kernel: &mut impl Kernel,
    progress: &mut Progress,
    observer_closed: impl FnOnce() -> bool,
) -> Result<(), GtpuError> {
    if !progress.installed || progress.undo || progress.retired || progress.published {
        return Err(uncertain());
    }
    kernel.current().await?;
    if !read_installed(kernel)? {
        return Err(uncertain());
    }
    kernel.publication()?;
    if observer_closed() {
        return Err(uncertain());
    }
    // The actor records this decision and replies without a suspension point.
    progress.published = true;
    Ok(())
}
pub(crate) fn undo(kernel: &mut impl Kernel, progress: &mut Progress) -> Result<(), GtpuError> {
    progress.undo = true;
    if progress.retired {
        return Ok(());
    }
    kernel.local()?;
    if progress.group_started && kernel.group()? == Readback::Exact {
        kernel.local()?;
        let _ack = kernel.remove_group();
    }
    if progress.group_started || progress.indexes_started != 0 {
        if kernel.group()? != Readback::Absent {
            return Err(uncertain());
        }
        // A delete ACK cannot prove that a reader which retained the old
        // active group has finished. Only the qualified kernel grace can.
        kernel.synchronize_readers()?;
        for index in 0..kernel.index_count() {
            if progress.indexes_started & (1 << index) == 0 {
                continue;
            }
            kernel.local()?;
            if kernel.index(index)? == Readback::Exact {
                let _ack = kernel.remove_index(index);
            }
            if kernel.index(index)? != Readback::Absent {
                return Err(uncertain());
            }
        }
        kernel.synchronize_readers()?;
    }
    progress.retired = true;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    #[derive(Default)]
    struct Port {
        group: bool,
        indexes: [bool; 2],
        stale: bool,
        lost_ack: bool,
        failed_group: bool,
        changed_group: bool,
        grace_fails: bool,
        events: Mutex<Vec<&'static str>>,
    }
    impl Port {
        fn event(&self, event: &'static str) {
            self.events.lock().unwrap().push(event);
        }
    }
    #[async_trait::async_trait]
    impl Kernel for Port {
        fn index_count(&self) -> usize {
            2
        }
        fn local(&self) -> Result<(), GtpuError> {
            Ok(())
        }
        fn publication(&self) -> Result<(), GtpuError> {
            self.local()
        }
        async fn current(&self) -> Result<(), GtpuError> {
            self.event("current");
            if self.stale {
                Err(uncertain())
            } else {
                Ok(())
            }
        }
        fn group(&self) -> Result<Readback, GtpuError> {
            if self.changed_group {
                return Err(uncertain());
            }
            Ok(if self.group {
                Readback::Exact
            } else {
                Readback::Absent
            })
        }
        fn index(&self, index: usize) -> Result<Readback, GtpuError> {
            Ok(if self.indexes[index] {
                Readback::Exact
            } else {
                Readback::Absent
            })
        }
        fn create_index(&mut self, index: usize) -> Result<(), GtpuError> {
            self.event("index+");
            self.indexes[index] = true;
            if self.lost_ack {
                Err(uncertain())
            } else {
                Ok(())
            }
        }
        async fn create_group(&mut self) -> Result<(), GtpuError> {
            assert_eq!(
                self.indexes, [true; 2],
                "both selectors must precede executable group authority"
            );
            self.event("group+");
            if self.failed_group {
                return Err(uncertain());
            }
            self.group = true;
            if self.lost_ack {
                Err(uncertain())
            } else {
                Ok(())
            }
        }
        fn remove_group(&mut self) -> Result<(), GtpuError> {
            self.event("group-");
            self.group = false;
            if self.lost_ack {
                Err(uncertain())
            } else {
                Ok(())
            }
        }
        fn remove_index(&mut self, index: usize) -> Result<(), GtpuError> {
            assert!(!self.group, "group authority must retire before selectors");
            assert!(self.events.lock().unwrap().contains(&"grace"));
            self.event("index-");
            self.indexes[index] = false;
            if self.lost_ack {
                Err(uncertain())
            } else {
                Ok(())
            }
        }
        fn synchronize_readers(&self) -> Result<(), GtpuError> {
            assert!(!self.group);
            if self.grace_fails {
                Err(uncertain())
            } else {
                self.event("grace");
                Ok(())
            }
        }
    }
    #[tokio::test]
    async fn selectors_precede_authority_and_lost_acks_resolve_by_readback() {
        let mut port = Port {
            lost_ack: true,
            ..Default::default()
        };
        let mut progress = Progress::default();
        install(&mut port, &mut progress).await.unwrap();
        assert!(progress.installed);
        publish(&mut port, &mut progress, || false).await.unwrap();
        assert!(progress.published);
        for pair in port.events.lock().unwrap().windows(2) {
            if matches!(pair[1], "index+" | "group+") {
                assert_eq!(pair[0], "current");
            }
        }
        port.stale = true;
        undo(&mut port, &mut progress).unwrap();
        assert!(progress.retired);
        assert!(!port.group && port.indexes == [false; 2]);
        let events = port.events.lock().unwrap();
        let removed = events.iter().position(|event| *event == "group-").unwrap();
        assert_eq!(
            &events[removed..],
            ["group-", "grace", "index-", "index-", "grace"]
        );
    }
    #[tokio::test]
    async fn stale_activation_has_no_effect_and_partial_install_never_republishes() {
        let mut stale = Port {
            stale: true,
            ..Default::default()
        };
        let mut progress = Progress::default();
        assert!(install(&mut stale, &mut progress).await.is_err());
        assert_eq!(stale.indexes, [false; 2]);
        let mut port = Port {
            failed_group: true,
            ..Default::default()
        };
        let mut progress = Progress::default();
        assert!(install(&mut port, &mut progress).await.is_err());
        assert_eq!(port.indexes, [true; 2]);
        assert!(progress.undo);
        assert!(install(&mut port, &mut progress).await.is_err());
        undo(&mut port, &mut progress).unwrap();
        assert_eq!(
            port.events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == "group+")
                .count(),
            1
        );
        assert!(progress.retired && port.indexes == [false; 2]);
    }
    #[tokio::test]
    async fn cancellation_changed_values_and_failed_grace_retain_exact_cleanup() {
        let mut port = Port::default();
        let mut progress = Progress::default();
        install(&mut port, &mut progress).await.unwrap();
        assert!(publish(&mut port, &mut progress, || true).await.is_err());
        assert!(!progress.published);
        port.changed_group = true;
        assert!(undo(&mut port, &mut progress).is_err());
        assert!(port.group && port.indexes == [true; 2]);
        port.changed_group = false;
        port.grace_fails = true;
        assert!(undo(&mut port, &mut progress).is_err());
        assert!(!port.group && port.indexes == [true; 2] && !progress.retired);
        port.grace_fails = false;
        undo(&mut port, &mut progress).unwrap();
        assert!(progress.retired);
    }
}
