//! Linux XFRM fixed-outer-DSCP companion configuration and runtime.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use opc_ipsec_xfrm_ebpf_common::MarkProfile;

use crate::{XfrmCapability, XfrmError};

/// Default bpffs root for per-interface XFRM DSCP companion state.
pub const DEFAULT_XFRM_DSCP_BPFFS_PIN_ROOT: &str = "/sys/fs/bpf/opc-ipsec-xfrm-dscp";
/// Default tc egress filter priority for the XFRM DSCP companion.
pub const DEFAULT_XFRM_DSCP_TC_PRIORITY: u16 = 60;

/// Explicit production configuration for fixed outer DSCP on XFRM SAs.
///
/// Linux XFRM writes the token into the reserved seven-bit skb-mark window
/// after selecting the SA. A tc egress program on every configured SWu-facing
/// interface consumes the token, updates the outer IP DSCP, preserves ECN and
/// unrelated mark bits, then clears the token. Deployments must reserve this
/// bit window against every other mark producer/consumer in the namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxXfrmDscpMarkingConfig {
    /// SWu egress interfaces on which transformed ESP/ESP-in-UDP packets leave.
    pub egress_interfaces: Vec<String>,
    /// bpffs root under which one configuration map is pinned per interface.
    pub bpffs_pin_root: PathBuf,
    /// tc filter priority reserved for this companion.
    pub tc_priority: u16,
    /// Starting bit of the contiguous seven-bit mark token.
    pub mark_shift: u8,
    /// Exact seven-bit mark mask; must equal `0x7f << mark_shift`.
    pub mark_mask: u32,
}

impl LinuxXfrmDscpMarkingConfig {
    /// Construct a marking profile with SDK bpffs/tc defaults.
    pub fn new(
        egress_interfaces: impl IntoIterator<Item = String>,
        mark_shift: u8,
    ) -> Result<Self, XfrmError> {
        let mark_mask = MarkProfile::mask_for_shift(mark_shift).ok_or_else(|| {
            XfrmError::invalid_config(
                "dscp_marking.mark_shift",
                "seven-bit token must fit within a 32-bit mark",
            )
        })?;
        let config = Self {
            egress_interfaces: egress_interfaces.into_iter().collect(),
            bpffs_pin_root: PathBuf::from(DEFAULT_XFRM_DSCP_BPFFS_PIN_ROOT),
            tc_priority: DEFAULT_XFRM_DSCP_TC_PRIORITY,
            mark_shift,
            mark_mask,
        };
        config.validate()?;
        Ok(config)
    }

    pub(crate) fn profile(&self) -> Result<MarkProfile, XfrmError> {
        MarkProfile::new(self.mark_shift, self.mark_mask).ok_or_else(|| {
            XfrmError::invalid_config(
                "dscp_marking.mark_mask",
                "mask must be exactly seven contiguous bits at mark_shift",
            )
        })
    }

    pub(crate) fn validate(&self) -> Result<(), XfrmError> {
        self.profile()?;
        if self.egress_interfaces.is_empty() {
            return Err(XfrmError::invalid_config(
                "dscp_marking.egress_interfaces",
                "at least one egress interface is required",
            ));
        }
        let mut unique = BTreeSet::new();
        for interface in &self.egress_interfaces {
            validate_interface_name(interface)?;
            if !unique.insert(interface.as_str()) {
                return Err(XfrmError::invalid_config(
                    "dscp_marking.egress_interfaces",
                    "duplicate interface names are not allowed",
                ));
            }
        }
        let normalized_text = self.bpffs_pin_root.to_str().is_some_and(|root| {
            root.strip_prefix('/').is_some_and(|relative| {
                relative
                    .split('/')
                    .all(|component| !component.is_empty() && component != "." && component != "..")
            })
        });
        if !normalized_text
            || !self.bpffs_pin_root.starts_with("/sys/fs/bpf")
            || self.bpffs_pin_root == Path::new("/sys/fs/bpf")
            || self
                .bpffs_pin_root
                .components()
                .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        {
            return Err(XfrmError::invalid_config(
                "dscp_marking.bpffs_pin_root",
                "pin root must be a normalized child of /sys/fs/bpf",
            ));
        }
        if self.tc_priority == 0 {
            return Err(XfrmError::invalid_config(
                "dscp_marking.tc_priority",
                "tc priority must be nonzero",
            ));
        }
        Ok(())
    }
}

fn validate_interface_name(name: &str) -> Result<(), XfrmError> {
    if name.is_empty() || name.len() >= 16 {
        return Err(XfrmError::invalid_config(
            "dscp_marking.egress_interfaces",
            "interface name must contain 1 through 15 bytes",
        ));
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(XfrmError::invalid_config(
            "dscp_marking.egress_interfaces",
            "interface name contains unsupported characters",
        ));
    }
    Ok(())
}

pub(crate) trait XfrmDscpRuntime: Send + Sync + std::fmt::Debug {
    fn ensure_ready(&self, config: &LinuxXfrmDscpMarkingConfig) -> Result<(), XfrmError>;
    fn capability(&self, config: &LinuxXfrmDscpMarkingConfig) -> XfrmCapability;
}

pub(crate) fn production_runtime() -> Arc<dyn XfrmDscpRuntime> {
    #[cfg(target_os = "linux")]
    {
        Arc::new(aya_runtime::AyaXfrmDscpRuntime::new())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Arc::new(UnsupportedDscpRuntime)
    }
}

#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
struct UnsupportedDscpRuntime;

#[cfg(not(target_os = "linux"))]
impl XfrmDscpRuntime for UnsupportedDscpRuntime {
    fn ensure_ready(&self, _config: &LinuxXfrmDscpMarkingConfig) -> Result<(), XfrmError> {
        Err(XfrmError::UnsupportedFeature {
            feature: "fixed_outer_dscp",
        })
    }

    fn capability(&self, _config: &LinuxXfrmDscpMarkingConfig) -> XfrmCapability {
        XfrmCapability::Missing
    }
}

#[cfg(target_os = "linux")]
mod aya_runtime {
    use std::collections::HashMap;
    use std::fs;
    use std::io;
    use std::mem::ManuallyDrop;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use aya::maps::{Array, IterableMap, MapInfo};
    use aya::pin::PinError;
    use aya::programs::tc::{NlOptions, SchedClassifierLink, TcAttachOptions, TcError, TcHandle};
    use aya::programs::{tc, ProgramError, ProgramInfo, SchedClassifier, TcAttachType};
    use aya::{Ebpf, EbpfLoader};
    use opc_ipsec_xfrm_ebpf_common::{
        MarkProfile, MAP_MARK_CONFIG, MARK_CONFIG_VALUE_LEN, PROG_EGRESS_DSCP,
    };
    use opc_linux_gtpu_sys as sys;
    use opc_linux_xfrm_sys as xfrm_sys;

    use super::{LinuxXfrmDscpMarkingConfig, XfrmDscpRuntime};
    use crate::{XfrmCapability, XfrmError};

    const DATAPATH_OBJECT: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/bpf/opc-ipsec-xfrm-dscp.bpf.o"
    ));
    const TC_HANDLE: TcHandle = TcHandle::new(0, 1);
    const CAP_NET_ADMIN: u32 = 12;
    const CAP_SYS_ADMIN: u32 = 21;
    const CAP_BPF: u32 = 39;

    #[derive(Debug, Default)]
    pub(super) struct AyaXfrmDscpRuntime {
        interfaces: Mutex<HashMap<String, LoadedInterface>>,
    }

    #[derive(Debug)]
    struct LoadedInterface {
        ifindex: u32,
        ebpf: Ebpf,
        pin_dir: xfrm_sys::BpffsDirectory,
        identity: CompanionIdentity,
        // Netlink tc filters are intentionally kernel-owned across process
        // restart. Taking the Aya link out of the program prevents an old
        // backend instance from deleting the exact slot after a new instance
        // has adopted it. Network-namespace teardown still removes the link.
        _persistent_link: Option<ManuallyDrop<SchedClassifierLink>>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct CompanionIdentity {
        program_id: u32,
        program_tag: u64,
        map_id: u32,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct FilterOwner {
        name: String,
        program_id: Option<u32>,
    }

    impl AyaXfrmDscpRuntime {
        pub(super) fn new() -> Self {
            Self::default()
        }

        fn open_pin_dir(
            config: &LinuxXfrmDscpMarkingConfig,
            interface: &str,
        ) -> Result<xfrm_sys::BpffsDirectory, XfrmError> {
            let relative = config
                .bpffs_pin_root
                .strip_prefix("/sys/fs/bpf")
                .map_err(|_| {
                    XfrmError::invalid_config(
                        "dscp_marking.bpffs_pin_root",
                        "pin root must be beneath /sys/fs/bpf",
                    )
                })?
                .join(interface);
            xfrm_sys::open_or_create_bpffs_directory(&relative)
                .map_err(|error| XfrmError::io("dscp_pin_dir_open", error))
        }

        fn load_pinned(pin_dir: &Path) -> Result<Ebpf, XfrmError> {
            let load = || {
                EbpfLoader::new()
                    .default_map_pin_directory(pin_dir)
                    .load(DATAPATH_OBJECT)
            };
            match load() {
                Ok(ebpf) => Ok(ebpf),
                // A concurrent constructor can win the exclusive map pin
                // after this loader observed no pin. Retry by opening it.
                Err(_) => load().map_err(|_| {
                    XfrmError::io("dscp_object_load", invalid_data("object load failed"))
                }),
            }
        }

        fn program_pin_path(pin_dir: &Path) -> PathBuf {
            pin_dir.join(PROG_EGRESS_DSCP)
        }

        fn open_or_create_pinned_program(
            ebpf: &mut Ebpf,
            pin_dir: &Path,
        ) -> Result<(SchedClassifier, ProgramInfo), XfrmError> {
            let pin_path = Self::program_pin_path(pin_dir);
            let pinned = match SchedClassifier::from_pin(&pin_path) {
                Ok(program) => Some(program),
                Err(error) if program_error_kind(&error) == Some(io::ErrorKind::NotFound) => None,
                Err(error) => return Err(program_error("dscp_program_pin_open", &error)),
            };

            // Always load the classifier embedded in this SDK build, even on
            // restart. Its kernel tag/type are the artifact identity against
            // which an existing pin must be checked before adoption.
            let program: &mut SchedClassifier = ebpf
                .program_mut(PROG_EGRESS_DSCP)
                .ok_or_else(|| {
                    XfrmError::io("dscp_program_lookup", invalid_data("program missing"))
                })?
                .try_into()
                .map_err(|_: ProgramError| {
                    XfrmError::io("dscp_program_type", invalid_data("not a classifier"))
                })?;
            program
                .load()
                .map_err(|error| program_error("dscp_program_load", &error))?;
            let artifact_info = program
                .info()
                .map_err(|error| program_error("dscp_artifact_program_info", &error))?;
            if artifact_info.name() != PROG_EGRESS_DSCP.as_bytes() {
                return Err(XfrmError::io(
                    "dscp_artifact_program_info",
                    invalid_data("embedded program name mismatch"),
                ));
            }
            if let Some(pinned) = pinned {
                return Ok((pinned, artifact_info));
            }
            match program.pin(&pin_path) {
                Ok(()) => {}
                Err(error) if pin_error_kind(&error) == Some(io::ErrorKind::AlreadyExists) => {}
                Err(error) => {
                    return Err(XfrmError::io(
                        "dscp_program_pin",
                        io::Error::new(
                            pin_error_kind(&error).unwrap_or(io::ErrorKind::InvalidData),
                            "program pin failed",
                        ),
                    ));
                }
            }
            let pinned = SchedClassifier::from_pin(&pin_path)
                .map_err(|error| program_error("dscp_program_pin_open", &error))?;
            Ok((pinned, artifact_info))
        }

        fn companion_identity(
            ebpf: &Ebpf,
            program: &SchedClassifier,
            pin_dir: &Path,
            expected_artifact: Option<&ProgramInfo>,
        ) -> Result<CompanionIdentity, XfrmError> {
            let map = ebpf.map(MAP_MARK_CONFIG).ok_or_else(|| {
                XfrmError::io("dscp_config_map", invalid_data("config map missing"))
            })?;
            let array = Array::<_, [u8; MARK_CONFIG_VALUE_LEN]>::try_from(map)
                .map_err(|_| XfrmError::io("dscp_config_map", invalid_data("wrong map schema")))?;
            let map_id = array
                .map()
                .info()
                .map_err(|_| XfrmError::io("dscp_config_map", invalid_data("map info failed")))?
                .id();
            let pinned_map_id = MapInfo::from_pin(pin_dir.join(MAP_MARK_CONFIG))
                .map_err(|_| {
                    XfrmError::io("dscp_config_map_pin", invalid_data("map pin open failed"))
                })?
                .id();
            if pinned_map_id != map_id {
                return Err(XfrmError::io(
                    "dscp_config_map_pin",
                    invalid_data("loaded and pinned map identities differ"),
                ));
            }
            let info = program
                .info()
                .map_err(|error| program_error("dscp_program_info", &error))?;
            if info.name() != PROG_EGRESS_DSCP.as_bytes() {
                return Err(XfrmError::AlreadyExists);
            }
            if let Some(expected) = expected_artifact {
                if expected.name() != PROG_EGRESS_DSCP.as_bytes()
                    || !artifact_metadata_matches(
                        info.name(),
                        info.tag(),
                        info.program_type() == expected.program_type(),
                        expected.tag(),
                    )
                {
                    return Err(XfrmError::AlreadyExists);
                }
            }
            let map_ids = info
                .map_ids()
                .map_err(|error| program_error("dscp_program_map_ids", &error))?
                .ok_or_else(|| {
                    XfrmError::io(
                        "dscp_program_map_ids",
                        invalid_data("kernel did not report program map ids"),
                    )
                })?;
            if !map_ids.contains(&map_id) {
                return Err(XfrmError::AlreadyExists);
            }
            Ok(CompanionIdentity {
                program_id: info.id(),
                program_tag: info.tag(),
                map_id,
            })
        }

        fn pinned_identity_matches(
            loaded: &LoadedInterface,
            expected_profile: MarkProfile,
        ) -> bool {
            let pin_dir = loaded.pin_dir.proc_path();
            let Ok(program) = SchedClassifier::from_pin(Self::program_pin_path(&pin_dir)) else {
                return false;
            };
            let Ok(identity) = Self::companion_identity(&loaded.ebpf, &program, &pin_dir, None)
            else {
                return false;
            };
            identity == loaded.identity
                && Self::read_profile(&loaded.ebpf)
                    .ok()
                    .and_then(|raw| MarkProfile::decode(&raw))
                    == Some(expected_profile)
        }

        fn read_profile(ebpf: &Ebpf) -> Result<[u8; MARK_CONFIG_VALUE_LEN], XfrmError> {
            let map = ebpf.map(MAP_MARK_CONFIG).ok_or_else(|| {
                XfrmError::io("dscp_config_map", invalid_data("config map missing"))
            })?;
            let array = Array::<_, [u8; MARK_CONFIG_VALUE_LEN]>::try_from(map)
                .map_err(|_| XfrmError::io("dscp_config_map", invalid_data("wrong map schema")))?;
            array
                .get(&0, 0)
                .map_err(|_| XfrmError::io("dscp_config_read", invalid_data("map read failed")))
        }

        fn write_profile(ebpf: &mut Ebpf, profile: MarkProfile) -> Result<(), XfrmError> {
            let map = ebpf.map_mut(MAP_MARK_CONFIG).ok_or_else(|| {
                XfrmError::io("dscp_config_map", invalid_data("config map missing"))
            })?;
            let mut array = Array::<_, [u8; MARK_CONFIG_VALUE_LEN]>::try_from(map)
                .map_err(|_| XfrmError::io("dscp_config_map", invalid_data("wrong map schema")))?;
            array
                .set(0, profile.encode(), 0)
                .map_err(|_| XfrmError::io("dscp_config_write", invalid_data("map write failed")))
        }

        fn configure_profile(ebpf: &mut Ebpf, expected: MarkProfile) -> Result<(), XfrmError> {
            let raw = Self::read_profile(ebpf)?;
            if raw == [0; MARK_CONFIG_VALUE_LEN] {
                return Self::write_profile(ebpf, expected);
            }
            match MarkProfile::decode(&raw) {
                Some(actual) if actual == expected => Ok(()),
                _ => Err(XfrmError::invalid_config(
                    "dscp_marking.mark_mask",
                    "pinned companion uses a different or invalid mark profile",
                )),
            }
        }

        fn attach_program(
            program: &mut SchedClassifier,
            interface: &str,
            ifindex: u32,
            priority: u16,
            identity: CompanionIdentity,
        ) -> Result<Option<ManuallyDrop<SchedClassifierLink>>, XfrmError> {
            if let Err(error) = tc::qdisc_add_clsact(interface) {
                if !is_qdisc_already_present(&error) {
                    return Err(tc_error("dscp_qdisc_add", &error));
                }
            }
            let options = || {
                TcAttachOptions::Netlink(NlOptions {
                    priority,
                    handle: TC_HANDLE,
                    classid: None,
                })
            };
            match program.attach_with_options(interface, TcAttachType::Egress, options()) {
                Ok(link_id) => {
                    let link = program
                        .take_link(link_id)
                        .map_err(|error| program_error("dscp_tc_link_ownership", &error))?;
                    verify_taken_link_owner(link, identity, || slot_owner(ifindex, priority))
                        .map(Some)
                }
                Err(first_error) => {
                    match slot_owner(ifindex, priority)? {
                        // A concurrent/restarting SDK instance already owns
                        // the exact slot. Adopt it without a detach gap.
                        Some(owner) if owner_matches(&owner, identity) => Ok(None),
                        Some(_) => Err(XfrmError::AlreadyExists),
                        None => Err(program_error("dscp_tc_attach", &first_error)),
                    }
                }
            }
        }

        fn ensure_interface(
            &self,
            config: &LinuxXfrmDscpMarkingConfig,
            interface: &str,
            profile: MarkProfile,
        ) -> Result<(), XfrmError> {
            let ifindex = sys::ifindex_by_name(interface)
                .map_err(|error| XfrmError::io("dscp_ifindex_lookup", error))?;
            {
                let interfaces = self.interfaces.lock().map_err(|_| XfrmError::Unavailable)?;
                if let Some(loaded) = interfaces.get(interface) {
                    if loaded.ifindex == ifindex {
                        match slot_owner(loaded.ifindex, config.tc_priority)? {
                            Some(owner)
                                if owner_matches(&owner, loaded.identity)
                                    && Self::pinned_identity_matches(loaded, profile) =>
                            {
                                return Ok(());
                            }
                            Some(_) => return Err(XfrmError::AlreadyExists),
                            None => {}
                        }
                    }
                }
            }

            // Drop stale in-process state before reloading/re-attaching.
            self.interfaces
                .lock()
                .map_err(|_| XfrmError::Unavailable)?
                .remove(interface);
            let pin_dir = Self::open_pin_dir(config, interface)?;
            let anchored_pin_dir = pin_dir.proc_path();
            let mut ebpf = Self::load_pinned(&anchored_pin_dir)?;
            let (mut program, artifact_info) =
                Self::open_or_create_pinned_program(&mut ebpf, &anchored_pin_dir)?;
            let identity = configure_after_identity(
                Self::companion_identity(&ebpf, &program, &anchored_pin_dir, Some(&artifact_info)),
                || {
                    // The pinned map may be all-zero after an interrupted
                    // first provision. Do not initialize or otherwise mutate
                    // it until the pinned program has been proven to be this
                    // SDK artifact and to reference this exact map.
                    Self::configure_profile(&mut ebpf, profile)
                },
            )?;
            let persistent_link = match slot_owner(ifindex, config.tc_priority)? {
                // Restart/adoption path: the live tc program ID, pinned
                // program ID, and pinned map/profile are all exact.
                Some(owner) if owner_matches(&owner, identity) => None,
                Some(_) => return Err(XfrmError::AlreadyExists),
                None => Self::attach_program(
                    &mut program,
                    interface,
                    ifindex,
                    config.tc_priority,
                    identity,
                )?,
            };
            self.interfaces
                .lock()
                .map_err(|_| XfrmError::Unavailable)?
                .insert(
                    interface.to_owned(),
                    LoadedInterface {
                        ifindex,
                        ebpf,
                        pin_dir,
                        identity,
                        _persistent_link: persistent_link,
                    },
                );
            Ok(())
        }

        fn environment_capability() -> XfrmCapability {
            if !Path::new("/sys/fs/bpf").is_dir() || !Path::new("/sys/kernel/btf/vmlinux").exists()
            {
                return XfrmCapability::Missing;
            }
            let net_admin = effective_capability(CAP_NET_ADMIN).unwrap_or(false);
            let bpf = effective_capability(CAP_BPF).unwrap_or(false)
                || effective_capability(CAP_SYS_ADMIN).unwrap_or(false);
            if !net_admin || !bpf {
                return XfrmCapability::PermissionDenied;
            }
            XfrmCapability::Available
        }
    }

    impl XfrmDscpRuntime for AyaXfrmDscpRuntime {
        fn ensure_ready(&self, config: &LinuxXfrmDscpMarkingConfig) -> Result<(), XfrmError> {
            config.validate()?;
            match Self::environment_capability() {
                XfrmCapability::Available => {}
                XfrmCapability::PermissionDenied => {
                    return Err(XfrmError::io(
                        "dscp_companion_attach",
                        io::Error::new(io::ErrorKind::PermissionDenied, "capability unavailable"),
                    ));
                }
                _ => {
                    return Err(XfrmError::UnsupportedFeature {
                        feature: "fixed_outer_dscp",
                    });
                }
            }
            let profile = config.profile()?;
            for interface in &config.egress_interfaces {
                self.ensure_interface(config, interface, profile)?;
            }
            Ok(())
        }

        fn capability(&self, config: &LinuxXfrmDscpMarkingConfig) -> XfrmCapability {
            let environment = Self::environment_capability();
            if environment != XfrmCapability::Available {
                return environment;
            }
            let Ok(profile) = config.profile() else {
                return XfrmCapability::Missing;
            };
            let Ok(interfaces) = self.interfaces.lock() else {
                return XfrmCapability::Missing;
            };
            if config.egress_interfaces.iter().all(|interface| {
                interfaces.get(interface).is_some_and(|loaded| {
                    Self::pinned_identity_matches(loaded, profile)
                        && matches!(
                            slot_owner(loaded.ifindex, config.tc_priority),
                            Ok(Some(owner)) if owner_matches(&owner, loaded.identity)
                        )
                })
            }) {
                XfrmCapability::Available
            } else {
                XfrmCapability::Missing
            }
        }
    }

    fn slot_owner(ifindex: u32, priority: u16) -> Result<Option<FilterOwner>, XfrmError> {
        let socket = sys::open_route_netlink_socket()
            .map_err(|error| XfrmError::io("dscp_tc_filter_dump", error))?;
        let ifindex = i32::try_from(ifindex).map_err(|_| {
            XfrmError::invalid_config("dscp_marking.egress_interfaces", "ifindex exceeds i32")
        })?;
        let mut request = Vec::with_capacity(36);
        request.extend_from_slice(&36_u32.to_ne_bytes());
        request.extend_from_slice(&sys::RTM_GETTFILTER.to_ne_bytes());
        request.extend_from_slice(&(sys::NLM_F_REQUEST | sys::NLM_F_DUMP).to_ne_bytes());
        request.extend_from_slice(&1_u32.to_ne_bytes());
        request.extend_from_slice(&0_u32.to_ne_bytes());
        request.push(0);
        request.extend_from_slice(&[0; 3]);
        request.extend_from_slice(&ifindex.to_ne_bytes());
        request.extend_from_slice(&0_u32.to_ne_bytes());
        request.extend_from_slice(&sys::TC_H_CLSACT_EGRESS.to_ne_bytes());
        request.extend_from_slice(&0_u32.to_ne_bytes());
        sys::send_message(&socket, &request)
            .map_err(|error| XfrmError::io("dscp_tc_filter_dump", error))?;

        let mut buffer = vec![0_u8; 65_536];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let length = match sys::receive_message(&socket, &mut buffer) {
                Ok(0) => continue,
                Ok(length) => length,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    if std::time::Instant::now() >= deadline {
                        return Err(XfrmError::io(
                            "dscp_tc_filter_dump",
                            io::Error::new(io::ErrorKind::TimedOut, "tc dump timeout"),
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
                Err(error) => return Err(XfrmError::io("dscp_tc_filter_dump", error)),
            };
            match parse_tfilter_dump(&buffer[..length], priority)? {
                DumpOutcome::Found(name) => return Ok(Some(name)),
                DumpOutcome::Done => return Ok(None),
                DumpOutcome::More => {}
            }
        }
    }

    enum DumpOutcome {
        Found(FilterOwner),
        Done,
        More,
    }

    fn parse_tfilter_dump(datagram: &[u8], priority: u16) -> Result<DumpOutcome, XfrmError> {
        const NL_HDR: usize = 16;
        const TCMSG: usize = 20;
        let malformed = || {
            XfrmError::io(
                "dscp_tc_filter_dump",
                invalid_data("malformed tc dump response"),
            )
        };
        let mut offset = 0;
        while offset + NL_HDR <= datagram.len() {
            let read_u32 = |at: usize| -> Result<u32, XfrmError> {
                datagram
                    .get(at..at + 4)
                    .map(|b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
                    .ok_or_else(malformed)
            };
            let read_u16 = |at: usize| -> Result<u16, XfrmError> {
                datagram
                    .get(at..at + 2)
                    .map(|b| u16::from_ne_bytes([b[0], b[1]]))
                    .ok_or_else(malformed)
            };
            let length = read_u32(offset)? as usize;
            if length < NL_HDR || offset + length > datagram.len() {
                return Err(malformed());
            }
            let message_type = read_u16(offset + 4)?;
            match message_type {
                t if t == sys::NLMSG_DONE => return Ok(DumpOutcome::Done),
                t if t == sys::NLMSG_ERROR => return Err(malformed()),
                t if t == sys::NLMSG_NOOP => {}
                t if t == sys::RTM_NEWTFILTER && length >= NL_HDR + TCMSG => {
                    let body = offset + NL_HDR;
                    let handle = read_u32(body + 8)?;
                    let info = read_u32(body + 16)?;
                    if handle == u32::from(TC_HANDLE) && (info >> 16) as u16 == priority {
                        return Ok(DumpOutcome::Found(
                            bpf_filter_owner(&datagram[body + TCMSG..offset + length])
                                .unwrap_or_else(|| FilterOwner {
                                    name: String::from("<non-bpf-filter>"),
                                    program_id: None,
                                }),
                        ));
                    }
                }
                _ => {}
            }
            offset += sys::align_to_netlink(length).ok_or_else(malformed)?;
        }
        Ok(DumpOutcome::More)
    }

    fn bpf_filter_owner(attributes: &[u8]) -> Option<FilterOwner> {
        let kind = find_attribute(attributes, sys::TCA_KIND)?;
        if kind != b"bpf\0" {
            return None;
        }
        let options = find_attribute(attributes, sys::TCA_OPTIONS)?;
        let name = find_attribute(options, sys::TCA_BPF_NAME)?;
        let name = name.strip_suffix(b"\0").unwrap_or(name);
        let program_id = find_attribute(options, sys::TCA_BPF_ID).and_then(|value| {
            value
                .get(..4)
                .map(|value| u32::from_ne_bytes([value[0], value[1], value[2], value[3]]))
        });
        Some(FilterOwner {
            name: String::from_utf8_lossy(name).into_owned(),
            program_id,
        })
    }

    fn owner_matches(owner: &FilterOwner, identity: CompanionIdentity) -> bool {
        owner.name == PROG_EGRESS_DSCP && owner.program_id == Some(identity.program_id)
    }

    fn verify_taken_link_owner<T>(
        link: T,
        identity: CompanionIdentity,
        read_owner: impl FnOnce() -> Result<Option<FilterOwner>, XfrmError>,
    ) -> Result<ManuallyDrop<T>, XfrmError> {
        // Once a link leaves Aya's program registry, dropping it issues an
        // unconditional netlink delete for the tc slot. Preserve kernel
        // ownership before re-reading the slot so a concurrent same-slot
        // replacement cannot be deleted by a stale link during error unwind.
        let link = ManuallyDrop::new(link);
        match read_owner()? {
            Some(owner) if owner_matches(&owner, identity) => Ok(link),
            // The slot no longer proves that it contains this link. Leave the
            // stale link kernel-owned; uncoordinated external replacement is
            // outside the reconciler's exclusive-writer boundary.
            _ => Err(XfrmError::AlreadyExists),
        }
    }

    fn artifact_metadata_matches(
        pinned_name: &[u8],
        pinned_tag: u64,
        program_type_matches: bool,
        expected_tag: u64,
    ) -> bool {
        pinned_name == PROG_EGRESS_DSCP.as_bytes()
            && program_type_matches
            && pinned_tag == expected_tag
    }

    fn configure_after_identity(
        identity: Result<CompanionIdentity, XfrmError>,
        configure: impl FnOnce() -> Result<(), XfrmError>,
    ) -> Result<CompanionIdentity, XfrmError> {
        let identity = identity?;
        configure()?;
        Ok(identity)
    }

    fn find_attribute(mut attributes: &[u8], attribute_type: u16) -> Option<&[u8]> {
        const ATTR_HDR: usize = 4;
        while attributes.len() >= ATTR_HDR {
            let length = usize::from(u16::from_ne_bytes([attributes[0], attributes[1]]));
            let found = u16::from_ne_bytes([attributes[2], attributes[3]]);
            if length < ATTR_HDR || length > attributes.len() {
                return None;
            }
            if found & 0x3fff == attribute_type {
                return Some(&attributes[ATTR_HDR..length]);
            }
            attributes = &attributes[sys::align_to_netlink(length)?.min(attributes.len())..];
        }
        None
    }

    fn is_qdisc_already_present(error: &TcError) -> bool {
        match error {
            TcError::AlreadyAttached => true,
            TcError::NetlinkError(error) => error.raw_os_error() == Some(17),
            _ => false,
        }
    }

    fn tc_error(operation: &'static str, error: &TcError) -> XfrmError {
        let raw = match error {
            TcError::NetlinkError(error) => error.raw_os_error(),
            TcError::IoError(error) => error.raw_os_error(),
            _ => None,
        };
        raw.map_or_else(
            || XfrmError::io(operation, invalid_data("tc operation failed")),
            |code| XfrmError::io(operation, io::Error::from_raw_os_error(code)),
        )
    }

    fn program_error(operation: &'static str, error: &ProgramError) -> XfrmError {
        match error {
            ProgramError::AlreadyAttached => XfrmError::AlreadyExists,
            ProgramError::SyscallError(error) => XfrmError::io(
                operation,
                io::Error::new(error.io_error.kind(), "eBPF syscall failed"),
            ),
            ProgramError::TcError(error) => tc_error(operation, error),
            _ => XfrmError::io(operation, invalid_data("eBPF program operation failed")),
        }
    }

    fn program_error_kind(error: &ProgramError) -> Option<io::ErrorKind> {
        match error {
            ProgramError::SyscallError(error) => Some(error.io_error.kind()),
            ProgramError::IOError(error) => Some(error.kind()),
            _ => None,
        }
    }

    fn pin_error_kind(error: &PinError) -> Option<io::ErrorKind> {
        match error {
            PinError::SyscallError(error) => Some(error.io_error.kind()),
            _ => None,
        }
    }

    fn effective_capability(capability: u32) -> Result<bool, XfrmError> {
        let status = fs::read_to_string("/proc/self/status")
            .map_err(|error| XfrmError::io("dscp_capability_probe", error))?;
        for line in status.lines() {
            if let Some(hex) = line.strip_prefix("CapEff:") {
                let caps = u64::from_str_radix(hex.trim(), 16).map_err(|_| {
                    XfrmError::io("dscp_capability_probe", invalid_data("invalid CapEff"))
                })?;
                return Ok((caps & (1_u64 << capability)) != 0);
            }
        }
        Ok(false)
    }

    fn invalid_data(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::cell::Cell;

        fn attr(attribute_type: u16, payload: &[u8]) -> Vec<u8> {
            let length = 4 + payload.len();
            let mut value = Vec::from((length as u16).to_ne_bytes());
            value.extend_from_slice(&attribute_type.to_ne_bytes());
            value.extend_from_slice(payload);
            value.resize((length + 3) & !3, 0);
            value
        }

        #[test]
        fn filter_identity_requires_exact_kernel_program_id() {
            let identity = CompanionIdentity {
                program_id: 73,
                program_tag: 0x1234,
                map_id: 91,
            };
            assert!(owner_matches(
                &FilterOwner {
                    name: PROG_EGRESS_DSCP.into(),
                    program_id: Some(73),
                },
                identity
            ));
            for owner in [
                FilterOwner {
                    name: PROG_EGRESS_DSCP.into(),
                    program_id: Some(74),
                },
                FilterOwner {
                    name: PROG_EGRESS_DSCP.into(),
                    program_id: None,
                },
                FilterOwner {
                    name: "foreign".into(),
                    program_id: Some(73),
                },
            ] {
                assert!(!owner_matches(&owner, identity));
            }
            assert_ne!(
                identity,
                CompanionIdentity {
                    program_id: 73,
                    program_tag: 0x1234,
                    map_id: 92,
                },
                "same program label/ID cannot validate a different pinned map"
            );
        }

        #[test]
        fn taken_link_owner_recheck_never_drops_a_stale_slot_handle() {
            #[derive(Debug)]
            struct DropProbe<'a>(&'a Cell<bool>);

            impl Drop for DropProbe<'_> {
                fn drop(&mut self) {
                    self.0.set(true);
                }
            }

            let identity = CompanionIdentity {
                program_id: 73,
                program_tag: 0x1234,
                map_id: 91,
            };
            let replacement_dropped = Cell::new(false);
            let result = verify_taken_link_owner(DropProbe(&replacement_dropped), identity, || {
                Ok(Some(FilterOwner {
                    name: PROG_EGRESS_DSCP.into(),
                    program_id: Some(74),
                }))
            });
            assert!(matches!(result, Err(XfrmError::AlreadyExists)));
            assert!(
                !replacement_dropped.get(),
                "a stale link drop could delete the external replacement"
            );

            let readback_error_dropped = Cell::new(false);
            let result =
                verify_taken_link_owner(DropProbe(&readback_error_dropped), identity, || {
                    Err(XfrmError::Unavailable)
                });
            assert!(matches!(result, Err(XfrmError::Unavailable)));
            assert!(
                !readback_error_dropped.get(),
                "an owner-read error must leave the ambiguous slot kernel-owned"
            );
        }

        #[test]
        fn foreign_same_name_and_map_with_stale_artifact_tag_is_rejected() {
            let pinned = CompanionIdentity {
                program_id: 73,
                program_tag: 0x1111,
                map_id: 91,
            };
            let current_artifact_tag = 0x2222;

            assert!(!artifact_metadata_matches(
                PROG_EGRESS_DSCP.as_bytes(),
                pinned.program_tag,
                true,
                current_artifact_tag,
            ));
            assert!(artifact_metadata_matches(
                PROG_EGRESS_DSCP.as_bytes(),
                current_artifact_tag,
                true,
                current_artifact_tag,
            ));
            assert!(!artifact_metadata_matches(
                PROG_EGRESS_DSCP.as_bytes(),
                current_artifact_tag,
                false,
                current_artifact_tag,
            ));
        }

        #[test]
        fn stale_artifact_gate_cannot_initialize_an_all_zero_profile_map() {
            let mut raw_profile = [0_u8; MARK_CONFIG_VALUE_LEN];
            let result = configure_after_identity(Err(XfrmError::AlreadyExists), || {
                raw_profile = MarkProfile::new(25, 0xfe00_0000).unwrap().encode();
                Ok(())
            });

            assert!(matches!(result, Err(XfrmError::AlreadyExists)));
            assert_eq!(raw_profile, [0_u8; MARK_CONFIG_VALUE_LEN]);
        }

        #[test]
        fn bpf_filter_owner_parses_name_and_program_id() {
            let mut options = attr(sys::TCA_BPF_NAME, b"opc_xfrm_dscp\0");
            options.extend_from_slice(&attr(sys::TCA_BPF_ID, &73_u32.to_ne_bytes()));
            let mut attributes = attr(sys::TCA_KIND, b"bpf\0");
            attributes.extend_from_slice(&attr(sys::TCA_OPTIONS, &options));

            assert_eq!(
                bpf_filter_owner(&attributes),
                Some(FilterOwner {
                    name: PROG_EGRESS_DSCP.into(),
                    program_id: Some(73),
                })
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_derives_and_validates_exact_mark_window() {
        let config = LinuxXfrmDscpMarkingConfig::new([String::from("eth0")], 25).unwrap();
        assert_eq!(config.mark_mask, 0xfe00_0000);
        assert_eq!(config.profile().unwrap().presence_bit(), 0x8000_0000);

        let mut invalid = config.clone();
        invalid.mark_mask = 0xfc00_0000;
        assert!(matches!(
            invalid.validate().unwrap_err(),
            XfrmError::InvalidConfig {
                field: "dscp_marking.mark_mask",
                ..
            }
        ));
    }

    #[test]
    fn config_rejects_empty_duplicate_or_unsafe_interfaces() {
        assert!(LinuxXfrmDscpMarkingConfig::new(Vec::<String>::new(), 0).is_err());
        assert!(
            LinuxXfrmDscpMarkingConfig::new([String::from("eth0"), String::from("eth0")], 0)
                .is_err()
        );
        assert!(LinuxXfrmDscpMarkingConfig::new([String::from("../eth0")], 0).is_err());
    }

    #[test]
    fn config_rejects_unsafe_pin_roots_and_zero_tc_priority() {
        let config = LinuxXfrmDscpMarkingConfig::new([String::from("eth0")], 0).unwrap();
        for root in [
            "/sys/fs/bpf",
            "/sys/fs/bpf/opc/../escape",
            "/sys/fs/bpf/opc/./nested",
            "/var/run/opc-ipsec-xfrm",
            "relative/pin-root",
        ] {
            let mut invalid = config.clone();
            invalid.bpffs_pin_root = root.into();
            assert!(matches!(
                invalid.validate().unwrap_err(),
                XfrmError::InvalidConfig {
                    field: "dscp_marking.bpffs_pin_root",
                    ..
                }
            ));
        }

        let mut invalid = config;
        invalid.tc_priority = 0;
        assert!(matches!(
            invalid.validate().unwrap_err(),
            XfrmError::InvalidConfig {
                field: "dscp_marking.tc_priority",
                ..
            }
        ));
    }
}
