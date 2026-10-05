//! An attachment needs the interface on which IP input receives, on a real
//! kernel (#1019).
//!
//! tc decides a hand-off on the device it is attached to. It looks for the
//! consumer there, and where it cannot settle the consumer it relies on the
//! frame's type reaching UDP input. Both assume that IP input receives the
//! datagram on that same device.
//!
//! A port of a bridge is not such a device, and neither is a port of a bond,
//! a team or a virtual switch. The master's receive handler runs after tc
//! and moves the frame to the master device. The master's VRF and the socket
//! bindings to the master then decide the delivery, which tc's lookup on the
//! port does not see; a bridge also sets the frame's type back to "host".
//! With the bridge in a VRF and an unrelated socket in the default VRF, a
//! hand-off is then assigned across the VRF boundary or answered with ICMP
//! Port Unreachable, on every kernel.
//!
//! The contract: the backend refuses such an interface. It does not attach
//! to it and does not adopt a retained attachment on it, and it changes
//! nothing when it refuses. If the interface of an attachment is enslaved
//! later, the backend refuses to open the control port and to adopt the
//! attachment after a restart. The process that made the attachment still
//! removes it. A restarted process cannot remove what it does not adopt; it
//! adopts and removes the attachment once the interface is released. It can
//! still fence the retained attachment for cleanup, but cannot activate it
//! while the interface is enslaved.

use super::*;

const BRIDGE: &str = "opcbr0";
/// The feature that the refusal names.
const REFUSED: &str = "attachment_on_enslaved_interface";

/// The attachment's interface as a port of a bridge that holds the endpoint
/// addresses, for the life of this value.
struct BridgePort;

impl BridgePort {
    fn enslave() -> Self {
        // The bridge takes the port's link address, so frames for the
        // endpoint keep their destination.
        let link_address = main_link_address("s2bu")
            .iter()
            .map(|octet| format!("{octet:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        run(
            "ip",
            &[
                "link",
                "add",
                BRIDGE,
                "type",
                "bridge",
                "forward_delay",
                "0",
            ],
        );
        let port = Self;
        run("ip", &["link", "set", BRIDGE, "address", &link_address]);
        run("ip", &["addr", "flush", "dev", "s2bu"]);
        run("ip", &["link", "set", "s2bu", "master", BRIDGE]);
        run("ip", &["link", "set", BRIDGE, "up"]);
        run("ip", &["addr", "add", "192.0.2.1/24", "dev", BRIDGE]);
        run(
            "ip",
            &[
                "-6",
                "addr",
                "replace",
                "2001:db8:2::1/64",
                "dev",
                BRIDGE,
                "nodad",
            ],
        );
        port
    }
}

impl Drop for BridgePort {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["link", "del", BRIDGE]).output();
    }
}

fn refused<T>(result: &Result<T, GtpuError>) -> bool {
    matches!(result, Err(GtpuError::UnsupportedFeature { feature }) if *feature == REFUSED)
}

pub(super) fn outcome<T>(result: &Result<T, GtpuError>) -> String {
    match result {
        Ok(_) => "accepted".to_owned(),
        Err(error) => format!("{error:?}"),
    }
}

/// What an attachment consists of on the host: the program on each of the
/// interface's two hooks, and the pinned objects.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Attachment {
    ingress: Option<u32>,
    egress: Option<u32>,
    pins: std::collections::BTreeSet<std::ffi::OsString>,
}

impl Attachment {
    pub(super) fn observe(pin_dir: &Path) -> Self {
        let program = |direction: &str| {
            tc_filters(direction)
                .contains("opc_gtpu")
                .then(|| tc_program_id(direction))
        };
        let pins = match std::fs::read_dir(pin_dir) {
            Ok(entries) => entries
                .map(|entry| entry.expect("read a pin directory entry").file_name())
                .collect(),
            Err(_) => std::collections::BTreeSet::new(),
        };
        Self {
            ingress: program("ingress"),
            egress: program("egress"),
            pins,
        }
    }

    /// Both hooks carry a program and the pins exist.
    pub(super) fn is_complete(&self) -> bool {
        self.ingress.is_some() && self.egress.is_some() && !self.pins.is_empty()
    }

    /// No hook carries a program and no pin exists.
    pub(super) fn is_absent(&self) -> bool {
        self.ingress.is_none() && self.egress.is_none() && self.pins.is_empty()
    }
}

pub(super) fn ordinary_request() -> CreateGtpDeviceRequest {
    let mut request = CreateGtpDeviceRequest::new("s2bu");
    request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
    request
}

// The serial guard is deliberately held for the entire body; see
// PRIVILEGED_TEST_LOCK.
#[allow(clippy::await_holding_lock)]
pub(super) async fn qualify() -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!("skipping: set OPC_GTPU_RUN_PRIVILEGED=1 inside a fresh privileged netns");
        return Ok(());
    }
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut violations = Vec::new();
    refused_on_a_bridge_port(&mut violations).await?;
    refused_once_enslaved(&mut violations).await?;
    not_adopted_while_enslaved(&mut violations).await?;
    not_activated_while(
        "the interface is enslaved",
        refused::<GtpDevice>,
        BridgePort::enslave,
        &mut violations,
    )
    .await?;
    assert!(
        violations.is_empty(),
        "an enslaved interface was not refused:\n{}",
        violations.join("\n")
    );
    eprintln!(
        "OPC_GTPU_ATTACHMENT_RECEIVE_INTERFACE_PROVEN: a bridge port is refused by create_device, create_device_with_endpoints and resolve_device before any hook or pin exists; once the interface of an attachment is enslaved, the control port and the adoption are refused and neither hook nor pin changes; the process that made the attachment still removes it, and a restarted one adopts and removes it after the interface is released; a cleanup-only attachment is fenced but not activated while the interface is enslaved, and activated after it is released"
    );
    Ok(())
}

/// The interface is a bridge port before anything is attached.
async fn refused_on_a_bridge_port(
    violations: &mut Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let net = TestNet::provision();
    let _bridge = BridgePort::enslave();
    let backend = Arc::new(EbpfGtpuDataplaneBackend::with_config(
        EbpfGtpuDataplaneBackendConfig {
            bpffs_pin_root: net.pin_root.clone(),
            ..EbpfGtpuDataplaneBackendConfig::default()
        },
    ));
    let pins = [
        net.pin_root.join("s2bu"),
        grouped_pin_directory(&net.pin_root, grouped_device_id()),
    ];
    let untouched = |entry: &str, violations: &mut Vec<String>| {
        for pin in &pins {
            let found = Attachment::observe(pin);
            if !found.is_absent() || pin.exists() {
                violations.push(format!(
                    "{entry} on a bridge port: a hook or a pin exists: {found:?}"
                ));
            }
        }
    };

    let ordinary = backend.create_device(ordinary_request()).await;
    if !refused(&ordinary) {
        violations.push(format!(
            "create_device on a bridge port: {}",
            outcome(&ordinary)
        ));
    }
    untouched("create_device", violations);
    if let Ok(device) = ordinary {
        backend.remove_device(&device).await?;
    }

    let grouped = backend
        .create_device_with_endpoints(grouped_device_request(grouped_mtu_policy()))
        .await;
    if !refused(&grouped) {
        violations.push(format!(
            "create_device_with_endpoints on a bridge port: {}",
            outcome(&grouped)
        ));
    }
    untouched("create_device_with_endpoints", violations);
    if let Ok(device) = grouped {
        backend.remove_device(&device).await?;
    }

    // Nothing is retained here, so there is nothing to adopt; the interface
    // is refused all the same, before the backend looks for a retained graph.
    let resolved = backend.resolve_device("s2bu").await;
    if !refused(&resolved) {
        violations.push(format!(
            "resolve_device on a bridge port: {}",
            outcome(&resolved)
        ));
    }
    Ok(())
}

/// The interface of an existing attachment becomes a bridge port while the
/// pinned programs keep running and the process that made it is still there.
async fn refused_once_enslaved(
    violations: &mut Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let net = TestNet::provision();
    let backend = EbpfGtpuDataplaneBackend::with_config(EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    });
    // On its own interface the attachment is made and its port opens.
    let device = backend.create_device(ordinary_request()).await?;
    let pin_dir = net.pin_root.join("s2bu");
    drop(backend.open_gtpu_control_port(&device).await?);
    let attached = Attachment::observe(&pin_dir);
    assert!(attached.is_complete(), "{attached:?}");

    let _bridge = BridgePort::enslave();
    let unchanged = |entry: &str, violations: &mut Vec<String>| {
        let found = Attachment::observe(&pin_dir);
        if found != attached {
            violations.push(format!(
                "{entry} after the interface was enslaved: the attachment was changed from {attached:?} to {found:?}"
            ));
        }
    };
    let port = backend.open_gtpu_control_port(&device).await;
    if !refused(&port) {
        violations.push(format!(
            "open_gtpu_control_port after the interface was enslaved: {}",
            outcome(&port)
        ));
    }
    drop(port);
    unchanged("open_gtpu_control_port", violations);
    let resolved = backend.resolve_device("s2bu").await;
    if !refused(&resolved) {
        violations.push(format!(
            "resolve_device after the interface was enslaved: {}",
            outcome(&resolved)
        ));
    }
    unchanged("resolve_device", violations);

    // The backend that made the attachment still removes it.
    backend.remove_device(&device).await?;
    let left = Attachment::observe(&pin_dir);
    if !left.is_absent() || pin_dir.exists() {
        violations.push(format!(
            "remove_device after the interface was enslaved: the attachment is still there: {left:?}"
        ));
    }
    Ok(())
}

/// The interface is enslaved while the process is down. After the restart
/// the retained attachment is not adopted and is left as it is; this backend
/// then cannot remove it either. Once the interface is released again, the
/// attachment is adopted and can be removed.
async fn not_adopted_while_enslaved(
    violations: &mut Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let net = TestNet::provision();
    let config = EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    };
    let backend = EbpfGtpuDataplaneBackend::with_config(config.clone());
    let device = backend.create_device(ordinary_request()).await?;
    let pin_dir = net.pin_root.join("s2bu");
    drop(backend);
    let retained = Attachment::observe(&pin_dir);
    assert!(retained.is_complete(), "{retained:?}");

    let restarted = EbpfGtpuDataplaneBackend::with_config(config);
    {
        let _bridge = BridgePort::enslave();
        let adopted = restarted.resolve_device("s2bu").await;
        if !refused(&adopted) {
            violations.push(format!(
                "resolve_device after a restart, interface enslaved: {}",
                outcome(&adopted)
            ));
        }
        let found = Attachment::observe(&pin_dir);
        if found != retained {
            violations.push(format!(
                "resolve_device after a restart, interface enslaved: the retained attachment was changed from {retained:?} to {found:?}"
            ));
        }
        // What is not adopted is not managed, so this backend cannot remove
        // it either while the interface is enslaved.
        let removal = restarted.remove_device(&device).await;
        if !matches!(removal, Err(GtpuError::NotFound)) {
            violations.push(format!(
                "remove_device after a restart, interface enslaved: {}",
                outcome(&removal)
            ));
        }
    }
    // The bridge is gone and the interface holds its endpoint again.
    run("ip", &["addr", "replace", "192.0.2.1/24", "dev", "s2bu"]);
    let adopted = restarted.resolve_device("s2bu").await?;
    assert_eq!(adopted.ifindex, device.ifindex);
    restarted.remove_device(&adopted).await?;
    let left = Attachment::observe(&pin_dir);
    if !left.is_absent() || pin_dir.exists() {
        violations.push(format!(
            "remove_device after the interface was released: the attachment is still there: {left:?}"
        ));
    }
    Ok(())
}

/// A restarted process fences the retained attachment for cleanup, which does
/// not ask where IP input receives. While `case` holds it cannot activate the
/// attachment: the activation would attach the programs again, and with them
/// the hand-offs. The attachment stays fenced as it is, and is activated once
/// `changed` is gone and the interface holds its endpoint again.
pub(super) async fn not_activated_while<Changed>(
    case: &str,
    refused: fn(&Result<GtpDevice, GtpuError>) -> bool,
    change: impl FnOnce() -> Changed,
    violations: &mut Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let net = TestNet::provision();
    let config = EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    };
    let owner = EbpfGtpuDataplaneBackend::with_config(config.clone());
    let device = owner.create_device(ordinary_request()).await?;
    let pin_dir = net.pin_root.join("s2bu");
    drop(owner);

    let recovered = EbpfGtpuDataplaneBackend::with_config(config);
    let activated = {
        let _changed = change();
        let request = RetainedGraphCleanupRequest::new(
            device.clone(),
            EPDG_S2BU_IP,
            CurrentEbpfGraphWriterProof::previous_writer_stopped(),
        );
        let acquired = recovered.acquire_cleanup_only_recovery(request).await?;
        if acquired != RetainedGraphCleanupClassification::Acquired {
            violations.push(format!(
                "acquire_cleanup_only_recovery while {case}: {acquired:?}"
            ));
        }
        let fenced = Attachment::observe(&pin_dir);
        if fenced.ingress.is_some() || fenced.egress.is_some() || fenced.pins.is_empty() {
            violations.push(format!(
                "acquire_cleanup_only_recovery while {case}: the attachment is not fenced: {fenced:?}"
            ));
        }
        let activation = recovered.activate_cleanup_recovery(&device).await;
        if !refused(&activation) {
            violations.push(format!(
                "activate_cleanup_recovery while {case}: {}",
                outcome(&activation)
            ));
        }
        let found = Attachment::observe(&pin_dir);
        if activation.is_err() && found != fenced {
            violations.push(format!(
                "activate_cleanup_recovery while {case}: the fenced attachment was changed from {fenced:?} to {found:?}"
            ));
        }
        activation.is_ok()
    };
    run("ip", &["addr", "replace", "192.0.2.1/24", "dev", "s2bu"]);
    if !activated {
        recovered.activate_cleanup_recovery(&device).await?;
    }
    let active = Attachment::observe(&pin_dir);
    if !active.is_complete() {
        violations.push(format!(
            "activate_cleanup_recovery after {case} no longer: the attachment is not complete: {active:?}"
        ));
    }
    recovered.remove_device(&device).await?;
    Ok(())
}
