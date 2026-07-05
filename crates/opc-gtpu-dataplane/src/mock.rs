//! Deterministic mock GTP-U dataplane backend for tests and offline development.

use std::fmt;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::backend::GtpuDataplaneBackend;
use crate::error::GtpuError;
use crate::model::{
    CreateGtpDeviceRequest, GtpDevice, GtpPdpContext, GtpuProbe, RemovePdpContextRequest,
};

/// One recorded call against the mock backend.
#[derive(Clone, PartialEq, Eq)]
pub enum MockOperation {
    /// Device creation.
    CreateDevice {
        /// Request snapshot.
        request: CreateGtpDeviceRequest,
    },
    /// Device removal.
    RemoveDevice {
        /// Device snapshot.
        device: GtpDevice,
    },
    /// PDP-context installation.
    InstallPdpContext {
        /// PDP context snapshot.
        request: GtpPdpContext,
    },
    /// PDP-context removal.
    RemovePdpContext {
        /// Remove request snapshot.
        request: RemovePdpContextRequest,
    },
    /// Capability probe.
    Probe,
}

impl fmt::Debug for MockOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CreateDevice { request } => f
                .debug_struct("CreateDevice")
                .field("request", request)
                .finish(),
            Self::RemoveDevice { device } => f
                .debug_struct("RemoveDevice")
                .field("device", device)
                .finish(),
            Self::InstallPdpContext { request } => f
                .debug_struct("InstallPdpContext")
                .field("request", request)
                .finish(),
            Self::RemovePdpContext { request } => f
                .debug_struct("RemovePdpContext")
                .field("request", request)
                .finish(),
            Self::Probe => f.write_str("Probe"),
        }
    }
}

/// Deterministic in-memory GTP-U dataplane backend.
#[derive(Debug, Clone)]
pub struct MockGtpuDataplaneBackend {
    state: Arc<Mutex<MockState>>,
}

#[derive(Debug)]
struct MockState {
    operations: Vec<MockOperation>,
    probe_result: GtpuProbe,
    failure: Option<GtpuError>,
    next_ifindex: u32,
}

impl MockGtpuDataplaneBackend {
    /// Create a mock backend that reports itself as a dry-run/mock probe.
    #[must_use]
    pub fn new() -> Self {
        Self::with_probe(GtpuProbe::mock())
    }

    /// Create a mock backend with a specific probe result.
    #[must_use]
    pub fn with_probe(probe_result: GtpuProbe) -> Self {
        Self {
            state: Arc::new(Mutex::new(MockState {
                operations: Vec::new(),
                probe_result,
                failure: None,
                next_ifindex: 1,
            })),
        }
    }

    /// Inject an error that every subsequent operation will return.
    pub fn set_failure(&self, error: GtpuError) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.failure = Some(error);
    }

    /// Clear any injected failure.
    pub fn clear_failure(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.failure = None;
    }

    /// Set the result returned by `probe`.
    pub fn set_probe_result(&self, probe_result: GtpuProbe) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.probe_result = probe_result;
    }

    /// Return all recorded operations, in order.
    #[must_use]
    pub fn operations(&self) -> Vec<MockOperation> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.operations.clone()
    }

    /// Clear the recorded operation log.
    pub fn clear_operations(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.operations.clear();
    }

    fn check_failure(state: &MockState) -> Result<(), GtpuError> {
        if let Some(ref error) = state.failure {
            return Err(error.clone());
        }
        Ok(())
    }
}

impl Default for MockGtpuDataplaneBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl GtpuDataplaneBackend for MockGtpuDataplaneBackend {
    async fn create_device(&self, request: CreateGtpDeviceRequest) -> Result<GtpDevice, GtpuError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        if request.name.is_empty() {
            return Err(GtpuError::invalid_config(
                "device.name",
                "name must be nonempty",
            ));
        }
        let ifindex = state.next_ifindex;
        state.next_ifindex = state.next_ifindex.saturating_add(1).max(1);
        state.operations.push(MockOperation::CreateDevice {
            request: request.clone(),
        });
        Ok(GtpDevice {
            name: request.name,
            ifindex,
        })
    }

    async fn remove_device(&self, device: &GtpDevice) -> Result<(), GtpuError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        state.operations.push(MockOperation::RemoveDevice {
            device: device.clone(),
        });
        Ok(())
    }

    async fn install_pdp_context(&self, request: GtpPdpContext) -> Result<(), GtpuError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        if request.link_ifindex == 0 {
            return Err(GtpuError::invalid_config(
                "pdp.link_ifindex",
                "ifindex must be nonzero",
            ));
        }
        state
            .operations
            .push(MockOperation::InstallPdpContext { request });
        Ok(())
    }

    async fn remove_pdp_context(&self, request: RemovePdpContextRequest) -> Result<(), GtpuError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        if request.link_ifindex == 0 {
            return Err(GtpuError::invalid_config(
                "pdp.link_ifindex",
                "ifindex must be nonzero",
            ));
        }
        state
            .operations
            .push(MockOperation::RemovePdpContext { request });
        Ok(())
    }

    async fn probe(&self) -> Result<GtpuProbe, GtpuError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        state.operations.push(MockOperation::Probe);
        Ok(state.probe_result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{GtpVersion, Teid};
    use std::net::{IpAddr, Ipv4Addr};

    fn teid(value: u32) -> Teid {
        Teid::new(value).unwrap()
    }

    fn context() -> GtpPdpContext {
        GtpPdpContext {
            local_teid: teid(1),
            peer_teid: teid(2),
            ms_address: IpAddr::V4(Ipv4Addr::new(10, 23, 0, 2)),
            peer_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            link_ifindex: 7,
            gtp_version: GtpVersion::V1,
        }
    }

    #[tokio::test]
    async fn mock_records_device_lifecycle() {
        let backend = MockGtpuDataplaneBackend::new();
        let request = CreateGtpDeviceRequest::new("gtp0");
        let device = backend.create_device(request.clone()).await.unwrap();
        backend.remove_device(&device).await.unwrap();

        assert_eq!(
            backend.operations(),
            vec![
                MockOperation::CreateDevice { request },
                MockOperation::RemoveDevice { device }
            ]
        );
    }

    #[tokio::test]
    async fn mock_records_pdp_lifecycle() {
        let backend = MockGtpuDataplaneBackend::new();
        let ctx = context();
        let remove = RemovePdpContextRequest::from_context(&ctx);

        backend.install_pdp_context(ctx.clone()).await.unwrap();
        backend.remove_pdp_context(remove.clone()).await.unwrap();

        assert_eq!(
            backend.operations(),
            vec![
                MockOperation::InstallPdpContext { request: ctx },
                MockOperation::RemovePdpContext { request: remove }
            ]
        );
    }

    #[tokio::test]
    async fn mock_failure_is_injected_without_recording() {
        let backend = MockGtpuDataplaneBackend::new();
        backend.set_failure(GtpuError::AlreadyExists);
        let err = backend
            .create_device(CreateGtpDeviceRequest::new("gtp0"))
            .await
            .unwrap_err();
        assert!(matches!(err, GtpuError::AlreadyExists));
        assert!(backend.operations().is_empty());
    }

    #[tokio::test]
    async fn mock_operation_debug_redacts_pdp_values() {
        let op = MockOperation::InstallPdpContext { request: context() };
        let debug = format!("{op:?}");
        assert!(!debug.contains("10.23.0.2"));
        assert!(!debug.contains("192.0.2.10"));
    }
}
