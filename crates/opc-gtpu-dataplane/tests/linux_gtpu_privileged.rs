use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;

use opc_gtpu_dataplane::{
    CreateGtpDeviceRequest, GtpPdpContext, GtpVersion, GtpuCapability, GtpuDataplaneBackend,
    LinuxGtpuDataplaneBackend, PdpContextInstallOutcome, PdpContextLocalTeidSelector,
    PdpContextReadback, PdpContextSelector, PdpContextSelectorOccupancy, PdpContextUplinkSelector,
    RemovePdpContextRequest, Teid,
};

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN, a fresh netns, and the linux gtp module"]
async fn create_install_remove_destroy_gtpu_device_in_current_netns(
) -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh CAP_NET_ADMIN netns");
        return Ok(());
    }

    let backend = LinuxGtpuDataplaneBackend::new();
    let name = format!("gtp{}", std::process::id() % 10_000);
    let device = backend
        .create_device(CreateGtpDeviceRequest::new(name.clone()))
        .await?;

    let local_teid = Teid::new(0x1000_0001).ok_or("local TEID must be nonzero")?;
    let peer_teid = Teid::new(0x2000_0001).ok_or("peer TEID must be nonzero")?;
    let context = GtpPdpContext {
        local_teid,
        peer_teid,
        ms_address: IpAddr::V4(Ipv4Addr::new(10, 23, 0, 2)),
        peer_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        link_ifindex: device.ifindex,
        downlink_source_port_policy: opc_gtpu_dataplane::GtpuSourcePortPolicy::Any,
        gtp_version: GtpVersion::V1,
        bearer_mark: None,
        egress_dscp: None,
    };

    let result = async {
        backend.install_pdp_context(context.clone()).await?;
        assert_eq!(
            backend.pdp_context_reconciliation_capabilities().readback,
            GtpuCapability::Available
        );
        assert_eq!(
            backend
                .read_pdp_context(PdpContextSelector::LocalTeid(
                    PdpContextLocalTeidSelector::from_context(&context)
                        .ok_or("local selector requires nonzero ifindex")?,
                ))
                .await?,
            PdpContextReadback::Present(context.clone())
        );
        assert_eq!(
            backend
                .read_pdp_context(PdpContextSelector::Uplink(
                    PdpContextUplinkSelector::from_context(&context)
                        .ok_or("uplink selector requires canonical context")?,
                ))
                .await?,
            PdpContextReadback::Present(context.clone())
        );
        assert_eq!(
            backend
                .install_pdp_context_classified(context.clone())
                .await?,
            PdpContextInstallOutcome::ExactAlreadyPresent
        );

        let mut stale_selector = context.clone();
        stale_selector.local_teid =
            Teid::new(0x1000_0002).ok_or("stale local TEID must be nonzero")?;
        stale_selector.peer_teid =
            Teid::new(0x2000_0002).ok_or("stale peer TEID must be nonzero")?;
        assert!(matches!(
            backend
                .install_pdp_context_classified(stale_selector)
                .await?,
            PdpContextInstallOutcome::Conflict(conflict)
                if conflict.occupied() == PdpContextSelectorOccupancy::Uplink
        ));

        let output = Command::new("ip")
            .args(["-d", "link", "show", "dev", &name])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "ip -d link show failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        backend
            .remove_pdp_context(RemovePdpContextRequest::from_context(&context))
            .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;

    let cleanup = backend.remove_device(&device).await;
    result?;
    cleanup?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN, a fresh netns, IPv6, and the linux gtp module"]
async fn mixed_inner_outer_families_read_back_and_reconcile_in_current_netns(
) -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh CAP_NET_ADMIN netns");
        return Ok(());
    }

    let backend = LinuxGtpuDataplaneBackend::new();
    let suffix = std::process::id() % 10_000;
    let cases = [
        (
            format!("gm4{suffix}"),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "2001:db8:23:1::".parse::<IpAddr>()?,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0x1100_0001,
            0x2100_0001,
        ),
        (
            format!("gm6{suffix}"),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(10, 23, 0, 3)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            0x1100_0002,
            0x2100_0002,
        ),
    ];

    for (name, bind_address, ms_address, peer_address, local_teid, peer_teid) in cases {
        let mut create = CreateGtpDeviceRequest::new(name);
        create.bind_address = bind_address;
        // Keep this independently runnable alongside the established fixture,
        // which owns the default GTP-U port in the same test namespace.
        create.bind_port = 32_152;
        let device = backend.create_device(create).await?;
        let context = GtpPdpContext {
            local_teid: Teid::new(local_teid).ok_or("local TEID must be nonzero")?,
            peer_teid: Teid::new(peer_teid).ok_or("peer TEID must be nonzero")?,
            ms_address,
            peer_address,
            link_ifindex: device.ifindex,
            downlink_source_port_policy: opc_gtpu_dataplane::GtpuSourcePortPolicy::Any,
            gtp_version: GtpVersion::V1,
            bearer_mark: None,
            egress_dscp: None,
        };

        let result = async {
            backend.install_pdp_context(context.clone()).await?;
            assert_eq!(
                backend
                    .read_pdp_context(PdpContextSelector::LocalTeid(
                        PdpContextLocalTeidSelector::from_context(&context)
                            .ok_or("local selector requires nonzero ifindex")?,
                    ))
                    .await?,
                PdpContextReadback::Present(context.clone())
            );
            assert_eq!(
                backend
                    .read_pdp_context(PdpContextSelector::Uplink(
                        PdpContextUplinkSelector::from_context(&context)
                            .ok_or("uplink selector requires canonical context")?,
                    ))
                    .await?,
                PdpContextReadback::Present(context.clone())
            );
            assert_eq!(
                backend
                    .install_pdp_context_classified(context.clone())
                    .await?,
                PdpContextInstallOutcome::ExactAlreadyPresent
            );
            backend
                .remove_pdp_context(RemovePdpContextRequest::from_context(&context))
                .await?;
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;

        let cleanup = backend.remove_device(&device).await;
        result?;
        cleanup?;
    }

    Ok(())
}
