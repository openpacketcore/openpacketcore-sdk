//! Safe Linux GTP-U dataplane backend model for OpenPacketCore.
//!
//! This crate provides a backend trait for Linux `gtp` device and PDP-context
//! lifecycle operations, a deterministic mock backend for tests, an
//! unsupported-platform backend, a Linux kernel adapter, and redaction-safe
//! error types. It deliberately does not implement GTP-U packet encoding,
//! GTP-C/PFCP control plane, route steering, XFRM policy, namespace management,
//! or deployment policy.
//!
//! Raw Linux netlink and socket syscalls stay in [`opc_linux_gtpu_sys`]; this
//! crate is safe Rust and never performs `unsafe` operations.

#![forbid(unsafe_code)]

pub mod backend;
pub mod error;
pub mod linux;
pub mod mock;
pub mod model;
pub mod unsupported;

pub use backend::GtpuDataplaneBackend;
pub use error::GtpuError;
pub use linux::{LinuxGtpuDataplaneBackend, LinuxGtpuDataplaneBackendConfig};
pub use mock::{MockGtpuDataplaneBackend, MockOperation};
pub use model::{
    CreateGtpDeviceRequest, GtpAddressFamily, GtpDevice, GtpPdpContext, GtpRole, GtpVersion,
    GtpuBackendKind, GtpuProbe, RemovePdpContextRequest, Teid, GTPU_PORT,
};
pub use unsupported::UnsupportedGtpuDataplaneBackend;

#[cfg(test)]
mod integration_tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn teid(value: u32) -> Teid {
        Teid::new(value).unwrap()
    }

    fn context() -> GtpPdpContext {
        GtpPdpContext {
            local_teid: teid(0x1000_0001),
            peer_teid: teid(0x2000_0001),
            ms_address: IpAddr::V4(Ipv4Addr::new(10, 23, 0, 2)),
            peer_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            link_ifindex: 7,
            gtp_version: GtpVersion::V1,
        }
    }

    #[tokio::test]
    async fn mock_backend_lifecycle_round_trip() {
        let backend = MockGtpuDataplaneBackend::new();
        let dev = backend
            .create_device(CreateGtpDeviceRequest::new("gtp-test"))
            .await
            .unwrap();
        assert_eq!(dev.name, "gtp-test");
        assert_ne!(dev.ifindex, 0);

        let pdp = context();
        backend.install_pdp_context(pdp.clone()).await.unwrap();
        backend
            .remove_pdp_context(RemovePdpContextRequest::from_context(&pdp))
            .await
            .unwrap();
        backend.remove_device(&dev).await.unwrap();

        let probe = backend.probe().await.unwrap();
        assert_eq!(probe.kind, GtpuBackendKind::Mock);
        assert!(probe.platform_supported);
        assert!(!probe.kernel_reachable);
        assert!(!probe.net_admin_capable);
        assert_eq!(backend.operations().len(), 5);
    }

    #[tokio::test]
    async fn unsupported_backend_is_trait_object_safe() {
        let backend: Box<dyn GtpuDataplaneBackend> =
            Box::new(UnsupportedGtpuDataplaneBackend::new());
        let probe = backend.probe().await.unwrap();
        assert_eq!(probe, GtpuProbe::unsupported());
    }
}
