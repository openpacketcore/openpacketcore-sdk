use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use std::path::PathBuf;
use std::process::Command;

use opc_gtpu_dataplane::{
    CreateGtpDeviceRequest, GtpDevice, GtpPdpContext, GtpVersion, GtpuCapability,
    GtpuDataplaneBackend, LinuxGtpuDataplaneBackend, PdpContextInstallOutcome,
    PdpContextLocalTeidSelector, PdpContextReadback, PdpContextRemovalOutcome, PdpContextSelector,
    PdpContextSelectorOccupancy, PdpContextUplinkSelector, PdpDeviceIncarnation,
    PdpLiveWriterRemovalRequest, PdpRestartRecoveryProof, PdpRestartRecoveryRequest,
    RemovePdpContextRequest, RetainedDeviceConflictReason, RetainedDeviceIdentityOutcome,
    RetainedDeviceIdentityRequest, Teid, GTPU_PORT,
};

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN, a fresh netns, and the linux gtp module"]
async fn probe_recognizes_owned_userspace_socket_in_current_netns(
) -> Result<(), Box<dyn std::error::Error>> {
    probe_owned_socket_lifecycle(false, Ipv4Addr::UNSPECIFIED).await
}

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN, a fresh netns, and the linux gtp module"]
async fn probe_recognizes_owned_specific_ipv4_socket_in_current_netns(
) -> Result<(), Box<dyn std::error::Error>> {
    probe_owned_socket_lifecycle(false, Ipv4Addr::LOCALHOST).await
}

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN, a fresh netns, and the linux gtp module"]
async fn probe_recognizes_owned_kernel_sockets_in_current_netns(
) -> Result<(), Box<dyn std::error::Error>> {
    probe_owned_socket_lifecycle(true, Ipv4Addr::UNSPECIFIED).await
}

async fn probe_owned_socket_lifecycle(
    recoverable: bool,
    bind_address: Ipv4Addr,
) -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh CAP_NET_ADMIN netns");
        return Ok(());
    }

    let root = std::env::temp_dir().join(format!("opc-gtpu-probe-{}", std::process::id()));
    let backend = LinuxGtpuDataplaneBackend::new().with_pdp_recovery_root(root.clone())?;
    require_equal(
        backend.probe().await?.mutation_ready,
        true,
        "fresh probe failed",
    )?;
    let foreign = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, GTPU_PORT))?;
    require_equal(
        backend.probe().await?.mutation_ready,
        false,
        "foreign socket accepted",
    )?;
    require_equal(
        backend
            .pdp_context_reconciliation_capabilities()
            .classified_install,
        GtpuCapability::Missing,
        "foreign socket enabled classified install",
    )?;
    drop(foreign);

    // A foreign socket on another address is insufficient by itself, but it
    // does not invalidate this backend's own specific IPv4 service socket.
    let foreign_specific = if bind_address.is_unspecified() {
        None
    } else {
        let foreign = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), GTPU_PORT))?;
        require_equal(
            backend.probe().await?.mutation_ready,
            false,
            "foreign specific IPv4 socket accepted",
        )?;
        Some(foreign)
    };
    let mut request = CreateGtpDeviceRequest::new(format!("gprobe{}", std::process::id() % 10_000));
    request.bind_address = IpAddr::V4(bind_address);
    let device = if recoverable {
        backend
            .create_recoverable_device(
                request,
                PdpDeviceIncarnation::from_bytes([0x93; 16]).ok_or("invalid incarnation")?,
            )
            .await?
    } else {
        backend.create_device(request).await?
    };
    let result = async {
        require_equal(
            UdpSocket::bind((Ipv4Addr::UNSPECIFIED, GTPU_PORT)).is_err(),
            true,
            "device socket did not occupy the service port",
        )?;
        let probe = backend.clone().probe().await?;
        if !probe.mutation_ready {
            return Err(format!("owned socket made the backend unavailable: {probe:?}").into());
        }
        require_equal(
            backend
                .pdp_context_reconciliation_capabilities()
                .classified_install,
            GtpuCapability::Available,
            "owned socket did not enable classified install",
        )?;
        let independent = LinuxGtpuDataplaneBackend::new();
        require_equal(
            independent.resolve_device(&device.name).await?,
            device.clone(),
            "independent backend resolved the wrong device",
        )?;
        require_equal(
            independent.probe().await?.mutation_ready,
            false,
            "name-only resolution granted socket ownership",
        )?;
        require_equal(
            independent
                .pdp_context_reconciliation_capabilities()
                .classified_install,
            GtpuCapability::Missing,
            "name-only resolution enabled classified install",
        )?;
        let context = privileged_recovery_context(&device)?;
        require_equal(
            backend
                .install_pdp_context_classified(context.clone())
                .await?,
            PdpContextInstallOutcome::Installed,
            "classified PDP install failed",
        )?;
        require_equal(
            backend
                .read_pdp_context(PdpContextSelector::LocalTeid(
                    PdpContextLocalTeidSelector::from_context(&context)
                        .ok_or("invalid local selector")?,
                ))
                .await?,
            PdpContextReadback::Present(context.clone()),
            "installed PDP readback differed",
        )?;
        backend
            .remove_pdp_context(RemovePdpContextRequest::from_context(&context))
            .await?;

        if recoverable {
            // An externally changed incarnation must withdraw readiness even
            // while the very same kernel socket still owns the service port.
            let output = Command::new("ip")
                .args(["link", "set", "dev", &device.name, "alias", "foreign"])
                .output()?;
            if !output.status.success() {
                return Err("failed to change fixture device alias".into());
            }
            require_equal(
                backend.probe().await?.mutation_ready,
                false,
                "changed recoverable incarnation retained readiness",
            )?;
            require_equal(
                backend
                    .pdp_context_reconciliation_capabilities()
                    .classified_install,
                GtpuCapability::Missing,
                "changed recoverable incarnation enabled classified install",
            )?;
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let cleanup = backend.remove_device(&device).await;
    let _ = std::fs::remove_dir_all(root);
    result?;
    cleanup?;

    require_equal(
        backend.probe().await?.mutation_ready,
        foreign_specific.is_none(),
        "probe retained ownership after device removal",
    )?;
    drop(foreign_specific);
    require_equal(
        backend.probe().await?.mutation_ready,
        true,
        "removed socket still occupied",
    )?;
    let _foreign = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, GTPU_PORT))?;
    require_equal(
        backend.probe().await?.mutation_ready,
        false,
        "foreign socket accepted after removal",
    )?;
    Ok(())
}

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
    let mut create = CreateGtpDeviceRequest::new(name.clone());
    // Recoverable fixtures in this binary use the kernel-owned standard GTP
    // ports. Keep this ordinary userspace-socket fixture independent.
    create.bind_port = 32_151;
    let device = backend.create_device(create).await?;

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
        uplink_source_port_policy:
            opc_gtpu_dataplane::GtpuUplinkSourcePortPolicy::LegacyServicePort,
        downlink_inner_mtu: None,
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
            uplink_source_port_policy:
                opc_gtpu_dataplane::GtpuUplinkSourcePortPolicy::LegacyServicePort,
            downlink_inner_mtu: None,
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

fn privileged_recovery_root() -> PathBuf {
    std::env::temp_dir().join(format!("opc-gtpu-627-priv-recovery-{}", std::process::id()))
}

fn privileged_recovery_context(device: &GtpDevice) -> Result<GtpPdpContext, &'static str> {
    Ok(GtpPdpContext {
        local_teid: Teid::new(0x1400_0001).ok_or("local TEID must be nonzero")?,
        peer_teid: Teid::new(0x2400_0001).ok_or("peer TEID must be nonzero")?,
        ms_address: IpAddr::V4(Ipv4Addr::new(10, 23, 0, 9)),
        peer_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        link_ifindex: device.ifindex,
        downlink_source_port_policy: opc_gtpu_dataplane::GtpuSourcePortPolicy::Any,
        gtp_version: GtpVersion::V1,
        bearer_mark: None,
        egress_dscp: None,
        uplink_source_port_policy:
            opc_gtpu_dataplane::GtpuUplinkSourcePortPolicy::LegacyServicePort,
        downlink_inner_mtu: None,
    })
}

fn privileged_recovery_request(
    device: &GtpDevice,
    incarnation: PdpDeviceIncarnation,
    context: GtpPdpContext,
) -> PdpRestartRecoveryRequest {
    PdpRestartRecoveryRequest::new(
        GtpDevice {
            name: device.name.clone(),
            ifindex: device.ifindex,
        },
        incarnation,
        context,
        PdpRestartRecoveryProof::previous_writer_stopped(),
    )
}

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN, a fresh netns, and the linux gtp module"]
async fn restart_recovery_removes_exact_pdp_and_is_idempotent_in_current_netns(
) -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh CAP_NET_ADMIN netns");
        return Ok(());
    }

    let recovery_root = privileged_recovery_root();
    let backend = LinuxGtpuDataplaneBackend::new().with_pdp_recovery_root(recovery_root.clone())?;
    let incarnation = PdpDeviceIncarnation::from_bytes([0xa5; 16])
        .ok_or("privileged fixture incarnation must be nonzero")?;
    let name = format!("gr{}", std::process::id() % 10_000);
    let create = CreateGtpDeviceRequest::new(name.clone());
    let prepared_request = RetainedDeviceIdentityRequest::new(
        name,
        None,
        incarnation,
        PdpRestartRecoveryProof::previous_writer_stopped(),
    );
    let device = match backend.create_recoverable_device(create, incarnation).await {
        Ok(device) => device,
        Err(error) => {
            if let Ok(acquisition) = backend
                .acquire_retained_device_identity(prepared_request)
                .await
            {
                if let Some(orphan) = acquisition.into_retained_device() {
                    let _ = backend.remove_device(&orphan).await;
                }
            }
            let _ = std::fs::remove_dir_all(&recovery_root);
            return Err(error.into());
        }
    };
    let context = privileged_recovery_context(&device)?;

    let result = async {
        // Generationless trait removal stays unsupported even with a root;
        // the Linux restart API carries the required device incarnation.
        assert_eq!(
            backend
                .pdp_context_reconciliation_capabilities()
                .exact_removal,
            GtpuCapability::Missing
        );

        // Removing a context that is not present is proven without mutation.
        assert_eq!(
            backend
                .recover_pdp_context_exact(privileged_recovery_request(
                    &device,
                    incarnation,
                    context.clone(),
                ))
                .await?,
            PdpContextRemovalOutcome::AlreadyAbsent
        );

        backend.install_pdp_context(context.clone()).await?;

        // The exact resident context is removed under recovery authority.
        assert_eq!(
            backend
                .recover_pdp_context_exact(privileged_recovery_request(
                    &device,
                    incarnation,
                    context.clone(),
                ))
                .await?,
            PdpContextRemovalOutcome::Removed
        );

        // A confirmed removal is idempotent: re-running proves exact absence.
        assert_eq!(
            backend
                .recover_pdp_context_exact(privileged_recovery_request(
                    &device,
                    incarnation,
                    context.clone(),
                ))
                .await?,
            PdpContextRemovalOutcome::AlreadyAbsent
        );

        // The generationless trait request cannot authorize Linux deletion.
        backend.install_pdp_context(context.clone()).await?;
        assert!(matches!(
            backend
                .remove_pdp_context_exact(context.clone())
                .await
                .unwrap_err(),
            opc_gtpu_dataplane::GtpuError::UnsupportedFeature {
                feature: "pdp_context_exact_removal"
            }
        ));
        assert_eq!(
            backend
                .recover_pdp_context_exact(privileged_recovery_request(
                    &device,
                    incarnation,
                    context.clone(),
                ))
                .await?,
            PdpContextRemovalOutcome::Removed
        );

        // A same-selector but different-identity resident is never touched.
        backend.install_pdp_context(context.clone()).await?;
        let mut foreign = context.clone();
        foreign.peer_teid = Teid::new(0x2400_0999).ok_or("foreign TEID must be nonzero")?;
        let conflict = backend
            .recover_pdp_context_exact(privileged_recovery_request(&device, incarnation, foreign))
            .await?;
        assert!(
            matches!(conflict, PdpContextRemovalOutcome::Conflict(_)),
            "expected Conflict, got {conflict:?}"
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

        backend
            .remove_pdp_context(RemovePdpContextRequest::from_context(&context))
            .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;

    let cleanup = backend.remove_device(&device).await;
    let _ = std::fs::remove_dir_all(&recovery_root);
    result?;
    cleanup?;
    Ok(())
}

fn privileged_retained_device_root() -> PathBuf {
    std::env::temp_dir().join(format!("opc-gtpu-634-priv-retained-{}", std::process::id()))
}

fn require_equal<T: PartialEq>(
    actual: T,
    expected: T,
    failure: &'static str,
) -> Result<(), Box<dyn std::error::Error>> {
    if actual == expected {
        Ok(())
    } else {
        Err(failure.into())
    }
}

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN, a fresh netns, and the linux gtp module"]
async fn retained_device_identity_acquisition_classifies_without_mutation_in_current_netns(
) -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh CAP_NET_ADMIN netns");
        return Ok(());
    }

    // A separate authority root keeps this fixture's writer group independent
    // of the restart-recovery fixture running in the same test binary.
    let recovery_root = privileged_retained_device_root();
    let creator = LinuxGtpuDataplaneBackend::new().with_pdp_recovery_root(recovery_root.clone())?;
    // Complete fallible setup before creating the retained link so every
    // later failure reaches the device cleanup below.
    let backend = LinuxGtpuDataplaneBackend::new().with_pdp_recovery_root(recovery_root.clone())?;
    let incarnation = PdpDeviceIncarnation::from_bytes([0xc3; 16])
        .ok_or("privileged fixture incarnation must be nonzero")?;
    let name = format!("ga{}", std::process::id() % 10_000);
    let create = CreateGtpDeviceRequest::new(name.clone());
    let prepared_request = RetainedDeviceIdentityRequest::new(
        name.clone(),
        None,
        incarnation,
        PdpRestartRecoveryProof::previous_writer_stopped(),
    );
    let device = match creator.create_recoverable_device(create, incarnation).await {
        Ok(device) => device,
        Err(error) => {
            // An ambiguous create may have published a fully stamped link.
            // Recover and remove only when the durable identity proves it is
            // this fixture's device; never delete a merely matching name.
            if let Ok(acquisition) = creator
                .acquire_retained_device_identity(prepared_request.clone())
                .await
            {
                if let Some(orphan) = acquisition.into_retained_device() {
                    let _ = creator.remove_device(&orphan).await;
                }
            }
            let _ = std::fs::remove_dir_all(&recovery_root);
            return Err(error.into());
        }
    };
    // The durable consumer still has only the prepared request. Dropping the
    // creator models process loss after the link was created and stamped but
    // before its returned ifindex was durably published.
    drop(creator);

    let retained_request = RetainedDeviceIdentityRequest::new(
        device.name.clone(),
        Some(device.ifindex),
        incarnation,
        PdpRestartRecoveryProof::previous_writer_stopped(),
    );

    let result = async {
        // Exact retained name, ifindex, and kernel-bound incarnation return
        // the retained identity, and the classification is idempotent.
        require_equal(
            backend.probe().await?.mutation_ready,
            false,
            "fresh backend assumed retained socket ownership",
        )?;
        require_equal(
            backend
                .pdp_context_reconciliation_capabilities()
                .classified_install,
            GtpuCapability::Missing,
            "fresh backend enabled classified install before acquisition",
        )?;
        let prepared = backend
            .acquire_retained_device_identity(prepared_request.clone())
            .await?;
        require_equal(
            prepared.outcome(),
            RetainedDeviceIdentityOutcome::Retained,
            "prepared acquisition was not retained",
        )?;
        require_equal(
            prepared.into_retained_device(),
            Some(device.clone()),
            "prepared acquisition returned the wrong device",
        )?;
        require_equal(
            backend.clone().probe().await?.mutation_ready,
            true,
            "retained acquisition did not establish readiness",
        )?;
        require_equal(
            backend
                .pdp_context_reconciliation_capabilities()
                .classified_install,
            GtpuCapability::Available,
            "retained acquisition did not enable classified install",
        )?;
        require_equal(
            backend
                .acquire_retained_device_identity(retained_request.clone())
                .await?
                .outcome(),
            RetainedDeviceIdentityOutcome::Retained,
            "exact acquisition was not retained",
        )?;

        // The acquisition is mutation-free against live PDP state: it neither
        // installs nor removes the resident context.
        let context = privileged_recovery_context(&device)?;
        backend.install_pdp_context(context.clone()).await?;
        require_equal(
            backend
                .acquire_retained_device_identity(retained_request.clone())
                .await?
                .outcome(),
            RetainedDeviceIdentityOutcome::Retained,
            "resident PDP changed retained classification",
        )?;
        require_equal(
            backend
                .read_pdp_context(PdpContextSelector::LocalTeid(
                    PdpContextLocalTeidSelector::from_context(&context)
                        .ok_or("local selector requires nonzero ifindex")?,
                ))
                .await?,
            PdpContextReadback::Present(context.clone()),
            "retained acquisition mutated resident PDP context",
        )?;

        // A different incarnation at the same name and ifindex fails closed
        // and leaves the resident context untouched.
        let replacement = PdpDeviceIncarnation::from_bytes([0x3c; 16])
            .ok_or("replacement incarnation must be nonzero")?;
        let foreign_request = RetainedDeviceIdentityRequest::new(
            device.name.clone(),
            Some(device.ifindex),
            replacement,
            PdpRestartRecoveryProof::previous_writer_stopped(),
        );
        require_equal(
            backend
                .acquire_retained_device_identity(foreign_request)
                .await?
                .outcome(),
            RetainedDeviceIdentityOutcome::Conflict(
                RetainedDeviceConflictReason::ReplacementIdentity,
            ),
            "foreign incarnation was not rejected",
        )?;
        require_equal(
            backend
                .read_pdp_context(PdpContextSelector::LocalTeid(
                    PdpContextLocalTeidSelector::from_context(&context)
                        .ok_or("local selector requires nonzero ifindex")?,
                ))
                .await?,
            PdpContextReadback::Present(context.clone()),
            "foreign acquisition mutated resident PDP context",
        )?;

        // The same name recorded against a different ifindex fails closed.
        let replaced_ifindex_request = RetainedDeviceIdentityRequest::new(
            device.name.clone(),
            Some(device.ifindex.checked_add(1).ok_or("ifindex overflow")?),
            incarnation,
            PdpRestartRecoveryProof::previous_writer_stopped(),
        );
        require_equal(
            backend
                .acquire_retained_device_identity(replaced_ifindex_request)
                .await?
                .outcome(),
            RetainedDeviceIdentityOutcome::Conflict(
                RetainedDeviceConflictReason::ReplacementIdentity,
            ),
            "replacement ifindex was not rejected",
        )?;

        backend
            .remove_pdp_context(RemovePdpContextRequest::from_context(&context))
            .await?;

        // After the device is removed, the recorded name is authoritatively
        // absent; the classification is idempotent and authorizes one fresh
        // create_recoverable_device call.
        backend.remove_device(&device).await?;
        require_equal(
            backend
                .acquire_retained_device_identity(retained_request.clone())
                .await?
                .outcome(),
            RetainedDeviceIdentityOutcome::Absent,
            "removed exact device was not absent",
        )?;
        require_equal(
            backend
                .acquire_retained_device_identity(prepared_request)
                .await?
                .outcome(),
            RetainedDeviceIdentityOutcome::Absent,
            "removed prepared device was not absent",
        )?;
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;

    if result.is_err() {
        let _ = backend.remove_device(&device).await;
    }
    let _ = std::fs::remove_dir_all(&recovery_root);
    result?;
    Ok(())
}

fn privileged_live_writer_root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "opc-gtpu-638-priv-livewriter-{}",
        std::process::id()
    ))
}

async fn privileged_live_writer_request(
    backend: &LinuxGtpuDataplaneBackend,
    device: &GtpDevice,
    incarnation: PdpDeviceIncarnation,
    context: GtpPdpContext,
) -> PdpLiveWriterRemovalRequest {
    let writer_proof = backend
        .acquire_pdp_live_writer_proof()
        .await
        .expect("bound backend must attest live writer");
    PdpLiveWriterRemovalRequest::new(
        GtpDevice {
            name: device.name.clone(),
            ifindex: device.ifindex,
        },
        incarnation,
        context,
        writer_proof,
    )
}

#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN, a fresh netns, and the linux gtp module"]
async fn live_writer_removal_removes_exact_pdp_under_live_authority_in_current_netns(
) -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh CAP_NET_ADMIN netns");
        return Ok(());
    }

    // A separate authority root keeps this fixture's writer group independent
    // of the other recovery fixtures running in the same test binary.
    let recovery_root = privileged_live_writer_root();
    let backend = LinuxGtpuDataplaneBackend::new().with_pdp_recovery_root(recovery_root.clone())?;
    let incarnation = PdpDeviceIncarnation::from_bytes([0x63; 16])
        .ok_or("privileged fixture incarnation must be nonzero")?;
    let name = format!("gw{}", std::process::id() % 10_000);
    let create = CreateGtpDeviceRequest::new(name.clone());
    let prepared_request = RetainedDeviceIdentityRequest::new(
        name,
        None,
        incarnation,
        PdpRestartRecoveryProof::previous_writer_stopped(),
    );
    let device = match backend.create_recoverable_device(create, incarnation).await {
        Ok(device) => device,
        Err(error) => {
            if let Ok(acquisition) = backend
                .acquire_retained_device_identity(prepared_request)
                .await
            {
                if let Some(orphan) = acquisition.into_retained_device() {
                    let _ = backend.remove_device(&orphan).await;
                }
            }
            let _ = std::fs::remove_dir_all(&recovery_root);
            return Err(error.into());
        }
    };
    let context = privileged_recovery_context(&device)?;

    let result = async {
        // The live-writer authority is reported once the root is bound; the
        // generationless trait removal stays unavailable.
        require_equal(
            backend.pdp_live_writer_removal_capability(),
            GtpuCapability::Available,
            "live-writer capability was not available with a bound root",
        )?;
        require_equal(
            backend
                .pdp_context_reconciliation_capabilities()
                .exact_removal,
            GtpuCapability::Missing,
            "generationless exact removal must remain missing",
        )?;

        // Removing a context that is not present is proven without mutation.
        require_equal(
            backend
                .remove_pdp_context_exact_live_writer(
                    privileged_live_writer_request(&backend, &device, incarnation, context.clone())
                        .await,
                )
                .await?,
            PdpContextRemovalOutcome::AlreadyAbsent,
            "absent live-writer removal was not AlreadyAbsent",
        )?;

        backend.install_pdp_context(context.clone()).await?;

        // The exact resident context is removed under live-writer authority
        // while the creating writer remains live.
        require_equal(
            backend
                .remove_pdp_context_exact_live_writer(
                    privileged_live_writer_request(&backend, &device, incarnation, context.clone())
                        .await,
                )
                .await?,
            PdpContextRemovalOutcome::Removed,
            "exact resident context was not removed under live-writer authority",
        )?;

        // A confirmed removal is idempotent: re-running proves exact absence.
        require_equal(
            backend
                .remove_pdp_context_exact_live_writer(
                    privileged_live_writer_request(&backend, &device, incarnation, context.clone())
                        .await,
                )
                .await?,
            PdpContextRemovalOutcome::AlreadyAbsent,
            "confirmed live-writer removal was not idempotent",
        )?;

        // The generationless trait request cannot authorize Linux deletion
        // even with a bound root and a live writer.
        backend.install_pdp_context(context.clone()).await?;
        match backend.remove_pdp_context_exact(context.clone()).await {
            Err(opc_gtpu_dataplane::GtpuError::UnsupportedFeature { feature }) => {
                require_equal(
                    feature,
                    "pdp_context_exact_removal",
                    "unexpected unsupported feature label",
                )?;
            }
            other => return Err(format!("expected UnsupportedFeature, got {other:?}").into()),
        }
        require_equal(
            backend
                .remove_pdp_context_exact_live_writer(
                    privileged_live_writer_request(&backend, &device, incarnation, context.clone())
                        .await,
                )
                .await?,
            PdpContextRemovalOutcome::Removed,
            "live-writer removal after generationless refusal failed",
        )?;

        // A same-selector but different-identity resident is never touched.
        backend.install_pdp_context(context.clone()).await?;
        let mut foreign = context.clone();
        foreign.peer_teid = Teid::new(0x2400_0999).ok_or("foreign TEID must be nonzero")?;
        match backend
            .remove_pdp_context_exact_live_writer(
                privileged_live_writer_request(&backend, &device, incarnation, foreign).await,
            )
            .await?
        {
            PdpContextRemovalOutcome::Conflict(_) => {}
            other => return Err(format!("expected Conflict, got {other:?}").into()),
        }
        require_equal(
            backend
                .read_pdp_context(PdpContextSelector::LocalTeid(
                    PdpContextLocalTeidSelector::from_context(&context)
                        .ok_or("local selector requires nonzero ifindex")?,
                ))
                .await?,
            PdpContextReadback::Present(context.clone()),
            "conflicting live-writer removal touched the resident context",
        )?;

        // A mismatched device incarnation fails closed and leaves the
        // resident context untouched.
        let replacement = PdpDeviceIncarnation::from_bytes([0x36; 16])
            .ok_or("replacement incarnation must be nonzero")?;
        require_equal(
            backend
                .remove_pdp_context_exact_live_writer(
                    privileged_live_writer_request(&backend, &device, replacement, context.clone())
                        .await,
                )
                .await?,
            PdpContextRemovalOutcome::RepairRequired(
                opc_gtpu_dataplane::PdpContextRepairReason::DeviceIdentityChanged,
            ),
            "foreign incarnation was not repair-required",
        )?;
        require_equal(
            backend
                .read_pdp_context(PdpContextSelector::LocalTeid(
                    PdpContextLocalTeidSelector::from_context(&context)
                        .ok_or("local selector requires nonzero ifindex")?,
                ))
                .await?,
            PdpContextReadback::Present(context.clone()),
            "foreign-incarnation removal touched the resident context",
        )?;

        backend
            .remove_pdp_context(RemovePdpContextRequest::from_context(&context))
            .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;

    let cleanup = backend.remove_device(&device).await;
    let _ = std::fs::remove_dir_all(&recovery_root);
    result?;
    cleanup?;
    Ok(())
}
