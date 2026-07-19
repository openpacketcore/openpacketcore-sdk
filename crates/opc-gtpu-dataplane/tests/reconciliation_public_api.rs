use std::net::{IpAddr, Ipv4Addr};

use async_trait::async_trait;
use opc_gtpu_dataplane::{
    CreateGtpDeviceRequest, GtpDevice, GtpPdpContext, GtpVersion, GtpuDataplaneBackend, GtpuError,
    GtpuProbe, GtpuSourcePortPolicy, MockOperation, PdpContextConflict, PdpContextInstallOutcome,
    PdpContextSelectorOccupancy, RemovePdpContextRequest, Teid,
};

fn established_mock_operation_kind(operation: &MockOperation) -> &'static str {
    match operation {
        MockOperation::CreateDevice { .. } => "create_device",
        MockOperation::ResolveDevice { .. } => "resolve_device",
        MockOperation::RemoveDevice { .. } => "remove_device",
        MockOperation::InstallPdpContext { .. } => "install_pdp_context",
        MockOperation::RemovePdpContext { .. } => "remove_pdp_context",
        MockOperation::Probe => "probe",
    }
}

#[derive(Debug)]
struct ExternalBackend;

#[async_trait]
impl GtpuDataplaneBackend for ExternalBackend {
    async fn create_device(
        &self,
        _request: CreateGtpDeviceRequest,
    ) -> Result<GtpDevice, GtpuError> {
        Err(GtpuError::UnsupportedPlatform)
    }

    async fn resolve_device(&self, _name: &str) -> Result<GtpDevice, GtpuError> {
        Err(GtpuError::UnsupportedPlatform)
    }

    async fn remove_device(&self, _device: &GtpDevice) -> Result<(), GtpuError> {
        Err(GtpuError::UnsupportedPlatform)
    }

    async fn install_pdp_context(&self, _request: GtpPdpContext) -> Result<(), GtpuError> {
        Err(GtpuError::UnsupportedPlatform)
    }

    async fn remove_pdp_context(&self, _request: RemovePdpContextRequest) -> Result<(), GtpuError> {
        Err(GtpuError::UnsupportedPlatform)
    }

    async fn install_pdp_context_classified(
        &self,
        desired: GtpPdpContext,
    ) -> Result<PdpContextInstallOutcome, GtpuError> {
        let mut existing = desired.clone();
        existing.peer_teid = Teid::new(3)
            .ok_or_else(|| GtpuError::invalid_config("test.peer_teid", "TEID must be nonzero"))?;
        let conflict =
            PdpContextConflict::between(PdpContextSelectorOccupancy::Both, &existing, &desired)
                .ok_or_else(|| {
                    GtpuError::invalid_config("test.conflict", "mismatch evidence must be nonempty")
                })?;
        Ok(PdpContextInstallOutcome::Conflict(conflict))
    }

    async fn probe(&self) -> Result<GtpuProbe, GtpuError> {
        Ok(GtpuProbe::unsupported())
    }
}

fn context() -> GtpPdpContext {
    GtpPdpContext {
        local_teid: Teid::new(1).unwrap(),
        peer_teid: Teid::new(2).unwrap(),
        ms_address: IpAddr::V4(Ipv4Addr::new(10, 23, 0, 2)),
        peer_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        link_ifindex: 7,
        downlink_source_port_policy: GtpuSourcePortPolicy::Any,
        gtp_version: GtpVersion::V1,
        bearer_mark: None,
        egress_dscp: None,
    }
}

#[tokio::test]
async fn external_backend_can_construct_redacted_conflict_outcome() {
    let backend: Box<dyn GtpuDataplaneBackend> = Box::new(ExternalBackend);
    assert!(matches!(
        backend
            .install_pdp_context_classified(context())
            .await
            .unwrap(),
        PdpContextInstallOutcome::Conflict(conflict)
            if conflict.occupied() == PdpContextSelectorOccupancy::Both
                && conflict.mismatches().len() == 1
    ));
}

#[test]
fn established_mock_operation_remains_externally_exhaustive() {
    assert_eq!(
        established_mock_operation_kind(&MockOperation::Probe),
        "probe"
    );
}
