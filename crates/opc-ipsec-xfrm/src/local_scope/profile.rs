//! Admission probe convergence. No candidate key or policy enters this driver.

use crate::XfrmError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProbeRead {
    Absent,
    ExactKeys,
    KeysUnavailable,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Phase {
    #[default]
    Empty,
    Create,
    Inspect,
    Remove,
    Verify,
    Complete,
}
#[derive(Default)]
pub(crate) struct ProbeProgress {
    phase: Phase,
    readable: Option<bool>,
}
impl ProbeProgress {
    pub(crate) fn has_uncertain_effects(&self) -> bool {
        matches!(self.phase, Phase::Inspect | Phase::Remove | Phase::Verify)
    }
}
#[async_trait::async_trait]
pub(crate) trait ProbeKernel: Send {
    fn contained(&self) -> Result<(), XfrmError>;
    fn empty(&self) -> Result<(), XfrmError>;
    async fn create(&mut self) -> Result<(), XfrmError>;
    async fn read(&mut self) -> Result<ProbeRead, XfrmError>;
    async fn remove(&mut self) -> Result<(), XfrmError>;
}

pub(crate) async fn run<K: ProbeKernel>(
    kernel: &mut K,
    progress: &mut ProbeProgress,
) -> Result<(), XfrmError> {
    kernel.contained()?;
    if progress.phase == Phase::Empty {
        kernel.empty()?;
        progress.phase = Phase::Create;
    }
    if progress.phase == Phase::Create {
        kernel.contained()?;
        // Record uncertainty before submitting. A retry reads this exact probe
        // instead of installing a second key after a lost response or panic.
        progress.phase = Phase::Inspect;
        let _ack = kernel.create().await;
    }
    if progress.phase == Phase::Inspect {
        progress.readable = Some(match kernel.read().await? {
            ProbeRead::Absent => {
                progress.phase = Phase::Empty;
                return Err(XfrmError::StateIndeterminate {
                    operation: "local_scope_profile_probe",
                });
            }
            ProbeRead::ExactKeys => true,
            ProbeRead::KeysUnavailable => false,
        });
        progress.phase = Phase::Remove;
    }
    if progress.phase == Phase::Remove {
        kernel.contained()?;
        if kernel.read().await? != ProbeRead::Absent {
            // Only the private noncandidate probe admits metadata-only cleanup
            // after redaction. Session undo always requires complete key proof.
            let _ack = kernel.remove().await;
        }
        progress.phase = Phase::Verify;
    }
    if progress.phase == Phase::Verify {
        kernel.contained()?;
        if kernel.read().await? != ProbeRead::Absent {
            progress.phase = Phase::Remove;
            return Err(XfrmError::StateIndeterminate {
                operation: "local_scope_profile_probe",
            });
        }
        kernel.empty()?;
        progress.phase = Phase::Complete;
    }
    match progress.readable {
        Some(true) => Ok(()),
        Some(false) => Err(XfrmError::UnsupportedFeature {
            feature: "local_scope_full_key_readback",
        }),
        None => Err(XfrmError::StateIndeterminate {
            operation: "local_scope_profile_probe",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Kernel {
        events: Mutex<Vec<&'static str>>,
        read: ProbeRead,
        keys: ProbeRead,
        lost_create_ack: bool,
        lost_remove_ack: bool,
        read_failures: usize,
        failed: bool,
    }
    impl Kernel {
        fn new(keys: ProbeRead) -> Self {
            Self {
                events: Mutex::new(Vec::new()),
                read: ProbeRead::Absent,
                keys,
                lost_create_ack: false,
                lost_remove_ack: false,
                read_failures: 0,
                failed: false,
            }
        }
    }
    #[async_trait::async_trait]
    impl ProbeKernel for Kernel {
        fn contained(&self) -> Result<(), XfrmError> {
            self.events.lock().unwrap().push("contain");
            Ok(())
        }
        fn empty(&self) -> Result<(), XfrmError> {
            self.events.lock().unwrap().push("empty");
            if self.read == ProbeRead::Absent {
                Ok(())
            } else {
                Err(XfrmError::AlreadyExists)
            }
        }
        async fn create(&mut self) -> Result<(), XfrmError> {
            self.events.lock().unwrap().push("create");
            self.read = self.keys;
            if self.lost_create_ack {
                Err(XfrmError::Unavailable)
            } else {
                Ok(())
            }
        }
        async fn read(&mut self) -> Result<ProbeRead, XfrmError> {
            self.events.lock().unwrap().push("read");
            if self.read_failures != 0 {
                self.read_failures -= 1;
                self.failed = true;
                Err(XfrmError::Unavailable)
            } else {
                Ok(self.read)
            }
        }
        async fn remove(&mut self) -> Result<(), XfrmError> {
            self.events.lock().unwrap().push("remove");
            self.read = ProbeRead::Absent;
            if self.lost_remove_ack {
                Err(XfrmError::Unavailable)
            } else {
                Ok(())
            }
        }
    }
    #[tokio::test]
    async fn probe_cleans_redacted_keys_before_typed_refusal() {
        let mut kernel = Kernel::new(ProbeRead::KeysUnavailable);
        let result = run(&mut kernel, &mut ProbeProgress::default()).await;
        assert!(matches!(
            result,
            Err(XfrmError::UnsupportedFeature {
                feature: "local_scope_full_key_readback"
            })
        ));
        assert_eq!(kernel.read, ProbeRead::Absent);
        let events = kernel.events.into_inner().unwrap();
        assert!(
            events.iter().position(|event| *event == "remove").unwrap()
                < events.iter().rposition(|event| *event == "empty").unwrap()
        );
    }
    #[tokio::test]
    async fn lost_probe_acks_resolve_from_readback_and_empty_namespace() {
        let mut kernel = Kernel::new(ProbeRead::ExactKeys);
        kernel.lost_create_ack = true;
        kernel.lost_remove_ack = true;
        run(&mut kernel, &mut ProbeProgress::default())
            .await
            .unwrap();
        assert_eq!(kernel.read, ProbeRead::Absent);
        assert_eq!(kernel.events.lock().unwrap().last(), Some(&"empty"));
    }
    #[tokio::test]
    async fn failed_read_keeps_exact_probe_and_resumes_without_reinstall() {
        let mut kernel = Kernel::new(ProbeRead::ExactKeys);
        kernel.read_failures = 1;
        let mut progress = ProbeProgress::default();
        assert!(run(&mut kernel, &mut progress).await.is_err());
        assert!(kernel.failed);
        assert_eq!(kernel.read, ProbeRead::ExactKeys);
        run(&mut kernel, &mut progress).await.unwrap();
        assert_eq!(
            kernel
                .events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == "create")
                .count(),
            1
        );
    }
    #[tokio::test]
    async fn nonempty_namespace_refuses_before_probe_creation() {
        let mut kernel = Kernel::new(ProbeRead::ExactKeys);
        kernel.read = ProbeRead::ExactKeys;
        assert!(run(&mut kernel, &mut ProbeProgress::default())
            .await
            .is_err());
        assert!(!kernel.events.lock().unwrap().contains(&"create"));
        assert!(!kernel.events.lock().unwrap().contains(&"remove"));
    }
}
