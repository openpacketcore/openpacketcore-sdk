//! Deterministic mock port implementations.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::error::IpsecLbError;
use crate::model::{
    ClusterNode, SaId, ShardId, SteeringProbe, SteeringRule, VipAdvertisement, VipProbe,
};
use crate::ports::{OwnershipSource, SteeringBackend, VipAdvertiser};

/// Recorded steering operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MockSteeringOperation {
    /// Rule installation.
    Install(SteeringRule),
    /// Rule removal.
    Remove(SteeringRule),
    /// Probe call.
    Probe,
}

/// Mock steering backend.
#[derive(Debug, Clone)]
pub struct MockSteeringBackend {
    state: Arc<Mutex<MockSteeringState>>,
}

#[derive(Debug)]
struct MockSteeringState {
    rules: BTreeSet<SteeringRuleOrder>,
    operations: Vec<MockSteeringOperation>,
    failure: Option<IpsecLbError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SteeringRuleOrder {
    shard: u16,
    owner: u16,
    key_tag: u8,
    key_value_hi: u64,
    key_value_lo: u64,
}

impl From<SteeringRule> for SteeringRuleOrder {
    fn from(rule: SteeringRule) -> Self {
        let (key_tag, key_value_hi, key_value_lo) = match rule.key {
            crate::model::SteerKey::IkeResponderSpi(spi) => (1, spi, 0),
            crate::model::SteerKey::IkeInit {
                initiator_spi,
                source_ip,
            } => {
                let source = source_ip.octets();
                let mut lo = 0u64;
                for byte in source.into_iter().take(8) {
                    lo = (lo << 8) | u64::from(byte);
                }
                (2, initiator_spi, lo)
            }
            crate::model::SteerKey::EspSpi(spi) => (3, u64::from(spi), 0),
        };
        Self {
            shard: rule.shard.get(),
            owner: rule.owner.get(),
            key_tag,
            key_value_hi,
            key_value_lo,
        }
    }
}

impl MockSteeringBackend {
    /// Build a mock backend.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(MockSteeringState {
                rules: BTreeSet::new(),
                operations: Vec::new(),
                failure: None,
            })),
        }
    }

    /// Inject a failure for future operations.
    pub fn set_failure(&self, failure: IpsecLbError) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.failure = Some(failure);
    }

    /// Return recorded operations.
    #[must_use]
    pub fn operations(&self) -> Vec<MockSteeringOperation> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.operations.clone()
    }
}

impl Default for MockSteeringBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SteeringBackend for MockSteeringBackend {
    async fn install_rule(&self, rule: SteeringRule) -> Result<(), IpsecLbError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(failure) = &state.failure {
            return Err(failure.clone());
        }
        if !state.rules.insert(rule.into()) {
            return Err(IpsecLbError::AlreadyExists);
        }
        state.operations.push(MockSteeringOperation::Install(rule));
        Ok(())
    }

    async fn remove_rule(&self, rule: SteeringRule) -> Result<(), IpsecLbError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(failure) = &state.failure {
            return Err(failure.clone());
        }
        if !state.rules.remove(&rule.into()) {
            return Err(IpsecLbError::NotFound);
        }
        state.operations.push(MockSteeringOperation::Remove(rule));
        Ok(())
    }

    async fn probe(&self) -> Result<SteeringProbe, IpsecLbError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(failure) = &state.failure {
            return Err(failure.clone());
        }
        state.operations.push(MockSteeringOperation::Probe);
        Ok(SteeringProbe::mock())
    }
}

/// Recorded VIP operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MockVipOperation {
    /// Advertisement.
    Advertise(VipAdvertisement),
    /// Withdrawal.
    Withdraw(VipAdvertisement),
    /// Probe call.
    Probe,
}

/// Mock VIP advertiser.
#[derive(Debug, Clone)]
pub struct MockVipAdvertiser {
    state: Arc<Mutex<MockVipState>>,
}

#[derive(Debug, Default)]
struct MockVipState {
    operations: Vec<MockVipOperation>,
    active: BTreeSet<(String, Vec<u8>)>,
}

impl MockVipAdvertiser {
    /// Build a mock advertiser.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(MockVipState::default())),
        }
    }

    /// Return recorded operations.
    #[must_use]
    pub fn operations(&self) -> Vec<MockVipOperation> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.operations.clone()
    }
}

impl Default for MockVipAdvertiser {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl VipAdvertiser for MockVipAdvertiser {
    async fn advertise(&self, advertisement: VipAdvertisement) -> Result<(), IpsecLbError> {
        let key = (
            advertisement.node.as_str().to_owned(),
            advertisement.vip.octets(),
        );
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.active.insert(key) {
            return Err(IpsecLbError::AlreadyExists);
        }
        state
            .operations
            .push(MockVipOperation::Advertise(advertisement));
        Ok(())
    }

    async fn withdraw(&self, advertisement: VipAdvertisement) -> Result<(), IpsecLbError> {
        let key = (
            advertisement.node.as_str().to_owned(),
            advertisement.vip.octets(),
        );
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.active.remove(&key) {
            return Err(IpsecLbError::NotFound);
        }
        state
            .operations
            .push(MockVipOperation::Withdraw(advertisement));
        Ok(())
    }

    async fn probe(&self) -> Result<VipProbe, IpsecLbError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.operations.push(MockVipOperation::Probe);
        Ok(VipProbe::mock())
    }
}

/// Mock ownership source.
#[derive(Debug, Clone, Default)]
pub struct MockOwnershipSource {
    state: Arc<Mutex<MockOwnershipState>>,
}

#[derive(Debug, Default)]
struct MockOwnershipState {
    shard_owners: BTreeMap<ShardId, ClusterNode>,
    sa_owners: BTreeMap<SaId, ClusterNode>,
}

impl MockOwnershipSource {
    /// Set a shard owner.
    pub fn set_shard_owner(&self, shard: ShardId, owner: ClusterNode) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.shard_owners.insert(shard, owner);
    }

    /// Set an SA owner.
    pub fn set_sa_owner(&self, sa: SaId, owner: ClusterNode) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.sa_owners.insert(sa, owner);
    }
}

#[async_trait]
impl OwnershipSource for MockOwnershipSource {
    async fn shard_owner(&self, shard: ShardId) -> Result<Option<ClusterNode>, IpsecLbError> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(state.shard_owners.get(&shard).cloned())
    }

    async fn sa_owner(&self, sa: SaId) -> Result<Option<ClusterNode>, IpsecLbError> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(state.sa_owners.get(&sa).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{IpAddress, SteerKey};

    #[tokio::test]
    async fn mock_steering_lifecycle_records_operations() {
        let backend = MockSteeringBackend::new();
        let rule = SteeringRule {
            shard: ShardId::new(1),
            owner: ShardId::new(1),
            key: SteerKey::EspSpi(0x1234),
        };
        backend.install_rule(rule).await.unwrap();
        backend.remove_rule(rule).await.unwrap();
        assert_eq!(
            backend.operations(),
            vec![
                MockSteeringOperation::Install(rule),
                MockSteeringOperation::Remove(rule),
            ]
        );
    }

    #[tokio::test]
    async fn mock_vip_lifecycle_records_operations() {
        let advertiser = MockVipAdvertiser::new();
        let ad = VipAdvertisement {
            vip: IpAddress::V4([203, 0, 113, 10]),
            node: ClusterNode::new("node-a"),
        };
        advertiser.advertise(ad.clone()).await.unwrap();
        advertiser.withdraw(ad.clone()).await.unwrap();
        assert_eq!(
            advertiser.operations(),
            vec![
                MockVipOperation::Advertise(ad.clone()),
                MockVipOperation::Withdraw(ad)
            ]
        );
    }

    #[tokio::test]
    async fn ownership_source_is_read_only() {
        let source = MockOwnershipSource::default();
        source.set_shard_owner(ShardId::new(2), ClusterNode::new("node-b"));
        assert_eq!(
            source
                .shard_owner(ShardId::new(2))
                .await
                .unwrap()
                .unwrap()
                .as_str(),
            "node-b"
        );
    }
}
