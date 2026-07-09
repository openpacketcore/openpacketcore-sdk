//! Host-XDP steering backend.
//!
//! This module keeps the public backend safe and deterministic while the
//! kernel mechanics sit behind a narrow runtime port. The backend programs only
//! packet-header steering keys and redirect metadata; no IPsec key material is
//! accepted by the API or written to kernel maps.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use opc_ipsec_lb_ebpf_common::{
    XdpRuleKey, XdpRuleValue, RULE_FLAG_REDIRECT_IFINDEX, RULE_KEY_LEN, RULE_VALUE_LEN,
};

use crate::error::IpsecLbError;
use crate::model::{ShardId, SteerKey, SteeringBackendKind, SteeringProbe, SteeringRule};
use crate::ports::SteeringBackend;

/// Default bpffs directory under which per-interface map pins are created.
pub const DEFAULT_BPFFS_PIN_ROOT: &str = "/sys/fs/bpf/opc-ipsec-lb";

/// Runtime behavior for the Host-XDP steering backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct HostXdpEnvironment {
    /// The platform can run the Host-XDP datapath.
    pub platform_supported: bool,
    /// bpffs is available for map pinning.
    pub bpffs_present: bool,
    /// Kernel BTF is exposed at `/sys/kernel/btf/vmlinux`.
    pub btf_present: bool,
    /// `CAP_NET_ADMIN` is effective.
    pub net_admin_capable: bool,
    /// `CAP_BPF` or `CAP_SYS_ADMIN` is effective.
    pub bpf_capable: bool,
}

/// Narrow synchronous port to the kernel XDP machinery.
pub(crate) trait HostXdpRuntime: Send + Sync + fmt::Debug {
    /// Resolve an interface index by name in the current netns.
    fn ifindex_by_name(&self, name: &str) -> Result<u32, IpsecLbError>;

    /// Load or adopt the XDP program and pinned maps for `interface`.
    fn attach(&self, interface: &str, ifindex: u32, pin_dir: &Path) -> Result<(), IpsecLbError>;

    /// Detach the XDP program and remove pins owned by this backend.
    fn detach(&self, interface: &str, ifindex: u32, pin_dir: &Path) -> Result<(), IpsecLbError>;

    /// Read a rule map entry.
    fn rule_get(
        &self,
        ifindex: u32,
        key: [u8; RULE_KEY_LEN],
    ) -> Result<Option<[u8; RULE_VALUE_LEN]>, IpsecLbError>;

    /// Insert or replace a rule map entry.
    fn rule_insert(
        &self,
        ifindex: u32,
        key: [u8; RULE_KEY_LEN],
        value: [u8; RULE_VALUE_LEN],
    ) -> Result<(), IpsecLbError>;

    /// Remove a rule map entry; returns whether it existed.
    fn rule_remove(&self, ifindex: u32, key: [u8; RULE_KEY_LEN]) -> Result<bool, IpsecLbError>;

    /// Probe the environment for XDP readiness.
    fn probe_environment(&self) -> HostXdpEnvironment;
}

/// Host-XDP backend configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostXdpSteeringBackendConfig {
    /// bpffs directory under which per-interface pin directories are created.
    pub bpffs_pin_root: PathBuf,
    /// Owner shard to redirect target ifindex.
    ///
    /// A missing owner is a configuration error. The backend refuses to install
    /// the rule rather than risking a correct-not-drop violation.
    pub owner_redirect_ifindexes: BTreeMap<ShardId, NonZeroU32>,
}

impl Default for HostXdpSteeringBackendConfig {
    fn default() -> Self {
        Self {
            bpffs_pin_root: PathBuf::from(DEFAULT_BPFFS_PIN_ROOT),
            owner_redirect_ifindexes: BTreeMap::new(),
        }
    }
}

struct HostXdpSteeringBackendInner {
    interface: String,
    runtime: Arc<dyn HostXdpRuntime>,
    config: HostXdpSteeringBackendConfig,
    attached_ifindex: Mutex<Option<u32>>,
}

/// Steering backend that programs SWu rules into a Host-XDP datapath.
#[derive(Clone)]
pub struct HostXdpSteeringBackend {
    inner: Arc<HostXdpSteeringBackendInner>,
}

impl fmt::Debug for HostXdpSteeringBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostXdpSteeringBackend")
            .field("interface", &self.inner.interface)
            .field("config", &self.inner.config)
            .finish_non_exhaustive()
    }
}

impl HostXdpSteeringBackend {
    /// Create a fail-closed Host-XDP backend placeholder.
    ///
    /// This is useful for composition roots that want a concrete backend value
    /// before kernel support is enabled; probes report unsupported and all
    /// mutating operations fail closed.
    #[must_use]
    pub fn unsupported(interface: impl Into<String>, config: HostXdpSteeringBackendConfig) -> Self {
        Self::from_runtime_and_config(interface, Arc::new(UnsupportedHostXdpRuntime), config)
    }

    fn from_runtime_and_config(
        interface: impl Into<String>,
        runtime: Arc<dyn HostXdpRuntime>,
        config: HostXdpSteeringBackendConfig,
    ) -> Self {
        Self {
            inner: Arc::new(HostXdpSteeringBackendInner {
                interface: interface.into(),
                runtime,
                config,
                attached_ifindex: Mutex::new(None),
            }),
        }
    }

    /// Create a backend from an explicit runtime. This is primarily used by
    /// tests and by downstream integration adapters.
    #[cfg(test)]
    pub(crate) fn with_runtime_and_config(
        interface: impl Into<String>,
        runtime: Arc<dyn HostXdpRuntime>,
        config: HostXdpSteeringBackendConfig,
    ) -> Self {
        Self::from_runtime_and_config(interface, runtime, config)
    }

    /// Detach this backend's XDP state from the configured interface.
    pub async fn detach(&self) -> Result<(), IpsecLbError> {
        self.run_blocking("host_xdp_detach", |backend| backend.detach_sync())
            .await
    }

    async fn run_blocking<T, F>(&self, operation: &'static str, f: F) -> Result<T, IpsecLbError>
    where
        T: Send + 'static,
        F: FnOnce(Self) -> Result<T, IpsecLbError> + Send + 'static,
    {
        let backend = self.clone();
        tokio::task::spawn_blocking(move || f(backend))
            .await
            .map_err(|_| {
                IpsecLbError::io(
                    operation,
                    io::Error::new(io::ErrorKind::Interrupted, "host XDP blocking task failed"),
                )
            })?
    }

    fn pin_dir(&self) -> PathBuf {
        self.inner.config.bpffs_pin_root.join(&self.inner.interface)
    }

    fn attached_ifindex(&self) -> Result<std::sync::MutexGuard<'_, Option<u32>>, IpsecLbError> {
        self.inner
            .attached_ifindex
            .lock()
            .map_err(|_| IpsecLbError::io("host_xdp_state", poisoned_lock()))
    }

    fn ensure_attached_sync(&self) -> Result<u32, IpsecLbError> {
        validate_interface_name(&self.inner.interface)?;
        if let Some(ifindex) = *self.attached_ifindex()? {
            return Ok(ifindex);
        }
        let ifindex = self.inner.runtime.ifindex_by_name(&self.inner.interface)?;
        if ifindex == 0 {
            return Err(IpsecLbError::invalid_config(
                "interface.ifindex",
                "ifindex must be nonzero",
            ));
        }
        self.inner
            .runtime
            .attach(&self.inner.interface, ifindex, &self.pin_dir())?;
        *self.attached_ifindex()? = Some(ifindex);
        Ok(ifindex)
    }

    fn detach_sync(&self) -> Result<(), IpsecLbError> {
        validate_interface_name(&self.inner.interface)?;
        let Some(ifindex) = *self.attached_ifindex()? else {
            return Ok(());
        };
        self.inner
            .runtime
            .detach(&self.inner.interface, ifindex, &self.pin_dir())?;
        *self.attached_ifindex()? = None;
        Ok(())
    }

    fn install_rule_sync(&self, rule: SteeringRule) -> Result<(), IpsecLbError> {
        let key = encode_rule_key(rule.key)?;
        let value = self.encode_rule_value(rule)?;
        let ifindex = self.ensure_attached_sync()?;
        match self.inner.runtime.rule_get(ifindex, key)? {
            Some(existing) if existing == value => Ok(()),
            Some(_) => Err(IpsecLbError::AlreadyExists),
            None => self.inner.runtime.rule_insert(ifindex, key, value),
        }
    }

    fn remove_rule_sync(&self, rule: SteeringRule) -> Result<(), IpsecLbError> {
        let key = encode_rule_key(rule.key)?;
        let ifindex = self.ensure_attached_sync()?;
        if self.inner.runtime.rule_remove(ifindex, key)? {
            Ok(())
        } else {
            Err(IpsecLbError::NotFound)
        }
    }

    fn encode_rule_value(&self, rule: SteeringRule) -> Result<[u8; RULE_VALUE_LEN], IpsecLbError> {
        let redirect_ifindex = self
            .inner
            .config
            .owner_redirect_ifindexes
            .get(&rule.owner)
            .copied()
            .ok_or_else(|| {
                IpsecLbError::invalid_config("rule.owner", "owner shard has no redirect ifindex")
            })?
            .get();
        Ok(XdpRuleValue {
            owner_shard: rule.owner.get(),
            redirect_ifindex,
            flags: RULE_FLAG_REDIRECT_IFINDEX,
        }
        .encode())
    }

    fn probe_sync(&self) -> SteeringProbe {
        let env = self.inner.runtime.probe_environment();
        let mutation_ready = env.platform_supported
            && env.bpffs_present
            && env.btf_present
            && env.net_admin_capable
            && env.bpf_capable
            && !self.inner.config.owner_redirect_ifindexes.is_empty();
        let details = if !env.platform_supported {
            Some("Host-XDP steering unsupported on this platform")
        } else if !env.bpffs_present {
            Some("bpffs is not available for map pinning")
        } else if !env.btf_present {
            Some("kernel BTF is not present")
        } else if !env.net_admin_capable {
            Some("CAP_NET_ADMIN is not effective")
        } else if !env.bpf_capable {
            Some("CAP_BPF or CAP_SYS_ADMIN is not effective")
        } else if self.inner.config.owner_redirect_ifindexes.is_empty() {
            Some("no owner redirect targets configured")
        } else {
            Some("Host-XDP steering mutation ready")
        };
        SteeringProbe {
            kind: SteeringBackendKind::HostXdp,
            platform_supported: env.platform_supported,
            mutation_ready,
            key_material_free: true,
            details,
        }
    }
}

#[async_trait]
impl SteeringBackend for HostXdpSteeringBackend {
    async fn install_rule(&self, rule: SteeringRule) -> Result<(), IpsecLbError> {
        self.run_blocking("host_xdp_install_rule", move |backend| {
            backend.install_rule_sync(rule)
        })
        .await
    }

    async fn remove_rule(&self, rule: SteeringRule) -> Result<(), IpsecLbError> {
        self.run_blocking("host_xdp_remove_rule", move |backend| {
            backend.remove_rule_sync(rule)
        })
        .await
    }

    async fn probe(&self) -> Result<SteeringProbe, IpsecLbError> {
        self.run_blocking("host_xdp_probe", move |backend| Ok(backend.probe_sync()))
            .await
    }
}

fn encode_rule_key(key: SteerKey) -> Result<[u8; RULE_KEY_LEN], IpsecLbError> {
    match key {
        SteerKey::IkeResponderSpi(spi) => Ok(XdpRuleKey::ike_responder_spi(spi).encode()),
        SteerKey::EspSpi(spi) => Ok(XdpRuleKey::esp_spi(spi).encode()),
        SteerKey::IkeInit { .. } => Err(IpsecLbError::invalid_config(
            "rule.key",
            "IKE_SA_INIT bootstrap is stateless and is not installed as a per-flow rule",
        )),
    }
}

const IFNAMSIZ: usize = 16;

fn validate_interface_name(name: &str) -> Result<(), IpsecLbError> {
    if name.is_empty() {
        return Err(IpsecLbError::invalid_config(
            "interface.name",
            "name must be nonempty",
        ));
    }
    if name.len() >= IFNAMSIZ {
        return Err(IpsecLbError::invalid_config(
            "interface.name",
            "name must fit Linux IFNAMSIZ",
        ));
    }
    if name.as_bytes().contains(&0) || name.contains('/') {
        return Err(IpsecLbError::invalid_config(
            "interface.name",
            "name must not contain NUL or path separators",
        ));
    }
    Ok(())
}

fn poisoned_lock() -> io::Error {
    io::Error::other("host XDP backend mutex poisoned")
}

#[derive(Debug, Clone, Copy, Default)]
struct UnsupportedHostXdpRuntime;

impl HostXdpRuntime for UnsupportedHostXdpRuntime {
    fn ifindex_by_name(&self, _name: &str) -> Result<u32, IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    fn attach(&self, _interface: &str, _ifindex: u32, _pin_dir: &Path) -> Result<(), IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    fn detach(&self, _interface: &str, _ifindex: u32, _pin_dir: &Path) -> Result<(), IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    fn rule_get(
        &self,
        _ifindex: u32,
        _key: [u8; RULE_KEY_LEN],
    ) -> Result<Option<[u8; RULE_VALUE_LEN]>, IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    fn rule_insert(
        &self,
        _ifindex: u32,
        _key: [u8; RULE_KEY_LEN],
        _value: [u8; RULE_VALUE_LEN],
    ) -> Result<(), IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    fn rule_remove(&self, _ifindex: u32, _key: [u8; RULE_KEY_LEN]) -> Result<bool, IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    fn probe_environment(&self) -> HostXdpEnvironment {
        HostXdpEnvironment::default()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::model::SteerKey;

    #[derive(Debug, Default)]
    struct TestRuntime {
        state: Mutex<TestState>,
    }

    #[derive(Debug)]
    struct TestState {
        ifindex: u32,
        env: HostXdpEnvironment,
        attached: Vec<(String, u32, PathBuf)>,
        detached: Vec<(String, u32, PathBuf)>,
        rules: HashMap<(u32, [u8; RULE_KEY_LEN]), [u8; RULE_VALUE_LEN]>,
    }

    impl Default for TestState {
        fn default() -> Self {
            Self {
                ifindex: 7,
                env: HostXdpEnvironment {
                    platform_supported: true,
                    bpffs_present: true,
                    btf_present: true,
                    net_admin_capable: true,
                    bpf_capable: true,
                },
                attached: Vec::new(),
                detached: Vec::new(),
                rules: HashMap::new(),
            }
        }
    }

    impl TestRuntime {
        fn with_env(env: HostXdpEnvironment) -> Self {
            Self {
                state: Mutex::new(TestState {
                    env,
                    ..TestState::default()
                }),
            }
        }

        fn attached_count(&self) -> usize {
            self.state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .attached
                .len()
        }

        fn rule_count(&self) -> usize {
            self.state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .rules
                .len()
        }
    }

    impl HostXdpRuntime for TestRuntime {
        fn ifindex_by_name(&self, _name: &str) -> Result<u32, IpsecLbError> {
            Ok(self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .ifindex)
        }

        fn attach(
            &self,
            interface: &str,
            ifindex: u32,
            pin_dir: &Path,
        ) -> Result<(), IpsecLbError> {
            self.state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .attached
                .push((interface.to_owned(), ifindex, pin_dir.to_path_buf()));
            Ok(())
        }

        fn detach(
            &self,
            interface: &str,
            ifindex: u32,
            pin_dir: &Path,
        ) -> Result<(), IpsecLbError> {
            self.state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .detached
                .push((interface.to_owned(), ifindex, pin_dir.to_path_buf()));
            Ok(())
        }

        fn rule_get(
            &self,
            ifindex: u32,
            key: [u8; RULE_KEY_LEN],
        ) -> Result<Option<[u8; RULE_VALUE_LEN]>, IpsecLbError> {
            Ok(self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .rules
                .get(&(ifindex, key))
                .copied())
        }

        fn rule_insert(
            &self,
            ifindex: u32,
            key: [u8; RULE_KEY_LEN],
            value: [u8; RULE_VALUE_LEN],
        ) -> Result<(), IpsecLbError> {
            self.state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .rules
                .insert((ifindex, key), value);
            Ok(())
        }

        fn rule_remove(&self, ifindex: u32, key: [u8; RULE_KEY_LEN]) -> Result<bool, IpsecLbError> {
            Ok(self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .rules
                .remove(&(ifindex, key))
                .is_some())
        }

        fn probe_environment(&self) -> HostXdpEnvironment {
            self.state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .env
        }
    }

    fn config(owner: ShardId, ifindex: u32) -> HostXdpSteeringBackendConfig {
        let mut owner_redirect_ifindexes = BTreeMap::new();
        owner_redirect_ifindexes.insert(owner, NonZeroU32::new(ifindex).unwrap());
        HostXdpSteeringBackendConfig {
            bpffs_pin_root: PathBuf::from("/tmp/opc-ipsec-lb-test"),
            owner_redirect_ifindexes,
        }
    }

    fn rule(owner: ShardId, key: SteerKey) -> SteeringRule {
        SteeringRule {
            shard: owner,
            owner,
            key,
        }
    }

    #[tokio::test]
    async fn install_is_lazy_idempotent_and_keyless() {
        let runtime = Arc::new(TestRuntime::default());
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            runtime.clone(),
            config(ShardId::new(1), 42),
        );
        let rule = rule(ShardId::new(1), SteerKey::EspSpi(0x1234_5678));

        backend.install_rule(rule).await.unwrap();
        backend.install_rule(rule).await.unwrap();

        assert_eq!(runtime.attached_count(), 1);
        assert_eq!(runtime.rule_count(), 1);
        let probe = backend.probe().await.unwrap();
        assert_eq!(probe.kind, SteeringBackendKind::HostXdp);
        assert!(probe.key_material_free);
        assert!(probe.mutation_ready);
    }

    #[tokio::test]
    async fn conflicting_owner_for_same_key_is_rejected() {
        let runtime = Arc::new(TestRuntime::default());
        let mut config = config(ShardId::new(1), 42);
        config
            .owner_redirect_ifindexes
            .insert(ShardId::new(2), NonZeroU32::new(43).unwrap());
        let backend = HostXdpSteeringBackend::with_runtime_and_config("swu0", runtime, config);
        let first = rule(ShardId::new(1), SteerKey::IkeResponderSpi(0x0102_0304));
        let second = SteeringRule {
            shard: ShardId::new(1),
            owner: ShardId::new(2),
            key: first.key,
        };

        backend.install_rule(first).await.unwrap();
        assert_eq!(
            backend.install_rule(second).await.unwrap_err(),
            IpsecLbError::AlreadyExists
        );
    }

    #[tokio::test]
    async fn missing_redirect_target_fails_before_attach() {
        let runtime = Arc::new(TestRuntime::default());
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            runtime.clone(),
            HostXdpSteeringBackendConfig {
                bpffs_pin_root: PathBuf::from("/tmp/opc-ipsec-lb-test"),
                owner_redirect_ifindexes: BTreeMap::new(),
            },
        );

        assert!(matches!(
            backend
                .install_rule(rule(ShardId::new(9), SteerKey::EspSpi(1)))
                .await,
            Err(IpsecLbError::InvalidConfig {
                field: "rule.owner",
                ..
            })
        ));
        assert_eq!(runtime.attached_count(), 0);
    }

    #[tokio::test]
    async fn ike_init_rules_are_rejected_as_stateless_bootstrap() {
        let runtime = Arc::new(TestRuntime::default());
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            runtime.clone(),
            config(ShardId::new(1), 42),
        );

        assert!(matches!(
            backend
                .install_rule(rule(
                    ShardId::new(1),
                    SteerKey::IkeInit {
                        initiator_spi: 7,
                        source_ip: crate::model::IpAddress::V4([198, 51, 100, 7]),
                    },
                ))
                .await,
            Err(IpsecLbError::InvalidConfig {
                field: "rule.key",
                ..
            })
        ));
        assert_eq!(runtime.attached_count(), 0);
    }

    #[tokio::test]
    async fn invalid_interface_name_fails_closed() {
        let runtime = Arc::new(TestRuntime::default());
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "bad/name",
            runtime.clone(),
            config(ShardId::new(1), 42),
        );

        assert!(matches!(
            backend
                .install_rule(rule(ShardId::new(1), SteerKey::EspSpi(1)))
                .await,
            Err(IpsecLbError::InvalidConfig {
                field: "interface.name",
                ..
            })
        ));
        assert_eq!(runtime.attached_count(), 0);
    }

    #[tokio::test]
    async fn probe_requires_owner_targets_for_mutation_ready() {
        let runtime = Arc::new(TestRuntime::with_env(HostXdpEnvironment {
            platform_supported: true,
            bpffs_present: true,
            btf_present: true,
            net_admin_capable: true,
            bpf_capable: true,
        }));
        let backend = HostXdpSteeringBackend::with_runtime_and_config(
            "swu0",
            runtime,
            HostXdpSteeringBackendConfig::default(),
        );
        let probe = backend.probe().await.unwrap();
        assert_eq!(probe.kind, SteeringBackendKind::HostXdp);
        assert!(!probe.mutation_ready);
        assert!(probe.key_material_free);
    }
}
