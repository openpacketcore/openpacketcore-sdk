use super::*;
use opc_local_kernel_lifecycle::{LocalLifecycleError, LocalXfrmReset};
use std::sync::atomic::{AtomicBool, Ordering};

pub(super) fn setup() {
    for args in [
        vec![
            "link", "add", "core0", "type", "veth", "peer", "name", "edge0",
        ],
        vec!["link", "set", "core0", "address", "02:00:00:00:79:01"],
        vec!["link", "set", "edge0", "address", "02:00:00:00:79:02"],
        vec!["addr", "add", "192.0.2.1/24", "dev", "core0"],
        vec!["link", "set", "core0", "up"],
        vec!["link", "set", "edge0", "up"],
        vec![
            "neigh",
            "replace",
            "192.0.2.2",
            "lladdr",
            "02:00:00:00:79:02",
            "nud",
            "permanent",
            "dev",
            "core0",
        ],
    ] {
        assert!(std::process::Command::new("ip")
            .args(args)
            .status()
            .unwrap()
            .success());
    }
}
pub(super) fn check(mode: &str) {
    let output = std::process::Command::new("python3")
        .args(["-c", include_str!("packets.py"), mode])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "packet {mode}: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
pub(super) struct CheckedReset {
    pub(super) inner: Arc<dyn LocalXfrmReset>,
    pub(super) verify_packets: AtomicBool,
}
#[async_trait::async_trait]
impl LocalXfrmReset for CheckedReset {
    fn local_scope(&self) -> &sys::tc::LocalKernelScope {
        self.inner.local_scope()
    }
    async fn is_empty(&self) -> Result<bool, LocalLifecycleError> {
        self.inner.is_empty().await
    }
    async fn reset_contained(
        &self,
        contained: &sys::tc::ContainedScope,
    ) -> Result<(), LocalLifecycleError> {
        if self.verify_packets.load(Ordering::Acquire) {
            assert!(
                !self.inner.is_empty().await?,
                "a live SA still exists at the normal-exit boundary"
            );
            assert_eq!(self.local_scope().spec().data_slots().len(), 3);
            for slot in self.local_scope().spec().data_slots() {
                assert!(self
                    .local_scope()
                    .inventory()?
                    .iter()
                    .any(|dump| dump.find(*slot).is_some()));
            }
            check("closed");
        }
        self.inner.reset_contained(contained).await?;
        if self.verify_packets.load(Ordering::Acquire) {
            check("closed");
        }
        Ok(())
    }
}
