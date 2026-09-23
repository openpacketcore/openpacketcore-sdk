//! Synthetic real-kernel lifecycle regression. Run only in a private mount and
//! network namespace with a private bpffs and the `proof-a` veth interface.
//! The required argument is an empty private on-disk scratch directory.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod linux {

    use opc_gtpu_dataplane::{
        CreateGtpDeviceEndpointSetRequest, CreateGtpDeviceRequest, EbpfGtpuDataplaneBackend,
        EbpfGtpuDataplaneBackendConfig, GtpDevice, GtpPdpContext, GtpVersion, GtpuDataplaneBackend,
        GtpuLocalEndpointSet, GtpuSessionDeviceId, GtpuSessionEntry, GtpuSessionGroup,
        GtpuSessionGroupId, GtpuSessionSelectorNamespaceAuthority, GtpuSourcePortPolicy,
        GtpuUplinkSourcePortPolicy, Teid,
    };
    use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing};
    use opc_session_store::{
        EncryptingSessionBackend, OwnerId, SelectorLedgerStorageScope, SessionStore,
        SqliteSessionBackend,
    };
    use opc_types::{NetworkFunctionKind, TenantId};
    use std::{
        collections::BTreeMap,
        error::Error,
        net::IpAddr,
        os::unix::fs::MetadataExt,
        path::{Path, PathBuf},
        process::Command,
        sync::Arc,
        time::Duration,
    };

    fn pins(root: &Path) -> Result<BTreeMap<PathBuf, u32>, Box<dyn Error>> {
        let leaf = root.join("bpf/retained/v6-41414141414141414141414141414141");
        let mut result = BTreeMap::new();
        for entry in std::fs::read_dir(leaf)? {
            let entry = entry?;
            result.insert(
                PathBuf::from(entry.file_name()),
                aya::maps::MapInfo::from_pin(entry.path())?.id(),
            );
        }
        if result.len() != 34 {
            return Err("complete current map inventory required".into());
        }
        Ok(result)
    }

    fn control_objects(root: &Path) -> Result<BTreeMap<PathBuf, (u64, u64)>, Box<dyn Error>> {
        let control = root.join("bpf/retained/GTPU_RECONCILER_LOCKS");
        let mut pending = vec![control.clone()];
        let mut result = BTreeMap::new();
        while let Some(path) = pending.pop() {
            let metadata = path.symlink_metadata()?;
            result.insert(
                path.strip_prefix(&control)?.to_owned(),
                (metadata.dev(), metadata.ino()),
            );
            if metadata.is_dir() {
                for child in std::fs::read_dir(path)? {
                    pending.push(child?.path());
                }
            }
        }
        if result.len() < 3 {
            return Err("protected control objects required".into());
        }
        Ok(result)
    }

    fn hooks_absent() -> Result<(), Box<dyn Error>> {
        for hook in ["ingress", "egress"] {
            let output = Command::new("tc")
                .args(["filter", "show", "dev", "proof-a", hook])
                .output()?;
            if !output.status.success() || !output.stdout.is_empty() {
                return Err("successful empty hook inventory required".into());
            }
        }
        Ok(())
    }

    type Store = EncryptingSessionBackend<SqliteSessionBackend, MemoryKeyProvider>;
    type Authority = GtpuSessionSelectorNamespaceAuthority<Store>;

    async fn attach(
        root: &Path,
        device: GtpuSessionDeviceId,
    ) -> Result<(Arc<EbpfGtpuDataplaneBackend>, GtpDevice), Box<dyn Error>> {
        let backend = Arc::new(EbpfGtpuDataplaneBackend::with_config(
            EbpfGtpuDataplaneBackendConfig {
                bpffs_pin_root: root.join("bpf/retained"),
                ..Default::default()
            },
        ));
        let attachment = backend
            .create_device_with_endpoints(CreateGtpDeviceEndpointSetRequest::new(
                CreateGtpDeviceRequest::new("proof-a"),
                device,
                GtpuLocalEndpointSet::new("192.0.2.1".parse::<IpAddr>()?, None)?,
            )?)
            .await?;
        Ok((backend, attachment))
    }

    fn group(
        device: GtpuSessionDeviceId,
        attachment: &GtpDevice,
        ordinal: u8,
    ) -> Result<GtpuSessionGroup, Box<dyn Error>> {
        Ok(GtpuSessionGroup::new(
            GtpuSessionGroupId::new([ordinal; 16]).ok_or("synthetic group")?,
            device,
            vec![GtpuSessionEntry::new(
                GtpPdpContext {
                    local_teid: Teid::new(0x4100 + u32::from(ordinal))
                        .ok_or("synthetic local tunnel")?,
                    peer_teid: Teid::new(0x5100 + u32::from(ordinal))
                        .ok_or("synthetic peer tunnel")?,
                    ms_address: IpAddr::from([192, 0, 2, ordinal]),
                    peer_address: "198.51.100.10".parse()?,
                    link_ifindex: attachment.ifindex,
                    downlink_source_port_policy: GtpuSourcePortPolicy::Exact(2152),
                    gtp_version: GtpVersion::V1,
                    bearer_mark: None,
                    egress_dscp: None,
                    uplink_source_port_policy: GtpuUplinkSourcePortPolicy::LegacyServicePort,
                },
                "192.0.2.1".parse()?,
            )?],
        )?)
    }

    #[tokio::main]
    pub async fn run() -> Result<(), Box<dyn Error>> {
        let root =
            std::path::PathBuf::from(std::env::args().nth(1).ok_or("scratch path required")?);
        if !root.is_absolute() || !root.join("isolated-run-authorized").is_file() {
            return Err("private isolated runner required".into());
        }
        let device = GtpuSessionDeviceId::new([0x41; 16]).ok_or("synthetic device")?;
        let tenant = TenantId::from_static("synthetic-retained-restart");
        let scope = SelectorLedgerStorageScope::new(
            tenant.clone(),
            NetworkFunctionKind::from_static("test"),
        );
        let keys = Arc::new(MemoryKeyProvider::new());
        keys.insert_active_key(
            KeyId::new("synthetic-restart-key")?,
            KeyPurpose::Session,
            tenant,
            Zeroizing::new([0x67; 32]),
        )?;
        let store = SessionStore::new(EncryptingSessionBackend::new(
            Arc::new(SqliteSessionBackend::open(root.join("ledger.sqlite"))?),
            keys,
            "synthetic-retained-restart",
        ));
        let (old, attachment) = attach(&root, device).await?;
        eprintln!("stage=predecessor_attached");
        let authority = Authority::provision_protected(
            store.clone(),
            scope.clone(),
            old.selector_namespace_bootstrap(device).await?,
            old.clone(),
            OwnerId::new("synthetic-predecessor")?,
            Duration::from_secs(30),
            32,
        )
        .await?;
        let retired_group = group(device, &attachment, 20)?;
        let active = authority
            .reconcile_fresh(old.clone(), retired_group.clone())
            .await?;
        eprintln!("stage=protected_group_installed");
        drop(
            authority
                .retire(old.clone(), active, retired_group.clone())
                .await?,
        );
        eprintln!("stage=protected_group_retired");
        let retained_active = group(device, &attachment, 22)?;
        drop(
            authority
                .reconcile_fresh(old.clone(), retained_active.clone())
                .await?,
        );
        drop(authority);
        let original_pins = pins(&root)?;
        let original_control = control_objects(&root)?;

        old.suspend_grouped_device(&attachment).await?;
        hooks_absent()?;
        if pins(&root)? != original_pins || control_objects(&root)? != original_control {
            return Err("shutdown changed retained map or control identity".into());
        }
        if !old.managed_device_inventory().await?.is_empty()
            || old.suspend_grouped_device(&attachment).await.is_ok()
        {
            return Err("old attachment retained mutation authority".into());
        }
        eprintln!(
            "stage=shutdown_completed exact_pins=34 hooks_absent=true old_handle_revoked=true"
        );
        drop(old);

        let (next, next_attachment) = attach(&root, device).await?;
        if pins(&root)? != original_pins {
            return Err("reopen replaced retained map objects".into());
        }
        eprintln!("stage=successor_attached exact_pins=34");
        let reopened = Authority::open_protected(
            store,
            scope,
            next.selector_namespace_bootstrap(device).await?,
            next.clone(),
            OwnerId::new("synthetic-successor")?,
            Duration::from_secs(30),
            32,
        )
        .await?;
        eprintln!("stage=retained_authority_reopened");
        if reopened
            .reconcile_fresh(next.clone(), retired_group)
            .await
            .is_ok()
        {
            return Err("retired history must not become fresh admission".into());
        }
        let recovered = reopened
            .recover_active(next.clone(), retained_active.clone())
            .await?;
        drop(
            reopened
                .retire(next.clone(), recovered, retained_active)
                .await?,
        );
        let fresh = group(device, &next_attachment, 21)?;
        let active = reopened
            .reconcile_fresh(next.clone(), fresh.clone())
            .await?;
        drop(reopened.retire(next.clone(), active, fresh).await?);
        drop(reopened);
        next.suspend_grouped_device(&next_attachment).await?;
        hooks_absent()?;
        if pins(&root)? != original_pins {
            return Err("second shutdown changed retained map objects".into());
        }
        eprintln!("result=passed retained_history=true active_history=true fresh_group_lifecycle=true hooks_absent=true exact_pins=34");
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    linux::run()
}

#[cfg(not(target_os = "linux"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    Err("the retained selector restart example requires Linux".into())
}
