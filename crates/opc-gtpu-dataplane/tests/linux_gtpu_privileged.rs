use std::env;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;

use opc_gtpu_dataplane::{
    CreateGtpDeviceRequest, GtpPdpContext, GtpVersion, GtpuDataplaneBackend,
    LinuxGtpuDataplaneBackend, RemovePdpContextRequest, Teid,
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
        gtp_version: GtpVersion::V1,
        egress_dscp: None,
    };

    let result = async {
        backend.install_pdp_context(context.clone()).await?;
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
