//! Deterministic mock XFRM backend for tests and offline development.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::backend::XfrmBackend;
use crate::error::XfrmError;
use crate::model::{
    AllocateSpiRequest, InstallPolicyRequest, InstallSaRequest, IpAddress, LifetimeConfig,
    RekeyPolicyRequest, RekeySaRequest, RemovePolicyRequest, RemoveSaRequest, SpiAllocation,
    XfrmAction, XfrmDirection, XfrmMode, XfrmProbe, XfrmSelector, XfrmTemplate,
};

/// One recorded call against the mock backend.
///
/// These snapshots deliberately include all non-secret request fields plus the
/// lengths of any key material, relying on [`crate::model::KeyMaterial`]'s
/// redacted `Debug` for sensitive bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MockOperation {
    /// SPI allocation.
    AllocateSpi {
        /// Requested destination.
        destination: IpAddress,
        /// Requested protocol.
        protocol: u8,
        /// Requested minimum SPI.
        min_spi: u32,
        /// Requested maximum SPI.
        max_spi: u32,
    },
    /// SA installation.
    InstallSa {
        /// Packet selector.
        selector: XfrmSelector,
        /// Source tunnel endpoint.
        source_address: IpAddress,
        /// Destination tunnel endpoint.
        destination: IpAddress,
        /// SPI in host byte order.
        spi: u32,
        /// Transform protocol.
        protocol: u8,
        /// Authentication algorithm name, if present.
        auth_algo: Option<String>,
        /// Authentication truncation length in bits, if present.
        auth_truncation_len_bits: Option<u32>,
        /// Authentication key length in bytes.
        auth_key_len: usize,
        /// Encryption algorithm name, if present.
        crypt_algo: Option<String>,
        /// Encryption key length in bytes.
        crypt_key_len: usize,
        /// XFRM mode.
        mode: XfrmMode,
        /// Lifetime limits.
        lifetime: LifetimeConfig,
        /// Replay window size.
        replay_window: u8,
    },
    /// SA rekey.
    RekeySa {
        /// Packet selector.
        selector: XfrmSelector,
        /// Source tunnel endpoint.
        source_address: IpAddress,
        /// Destination tunnel endpoint.
        destination: IpAddress,
        /// SPI in host byte order.
        spi: u32,
        /// Transform protocol.
        protocol: u8,
        /// Authentication algorithm name, if present.
        auth_algo: Option<String>,
        /// Authentication truncation length in bits, if present.
        auth_truncation_len_bits: Option<u32>,
        /// Authentication key length in bytes.
        auth_key_len: usize,
        /// Encryption algorithm name, if present.
        crypt_algo: Option<String>,
        /// Encryption key length in bytes.
        crypt_key_len: usize,
        /// XFRM mode.
        mode: XfrmMode,
        /// Lifetime limits.
        lifetime: LifetimeConfig,
        /// Replay window size.
        replay_window: u8,
    },
    /// SA removal.
    RemoveSa {
        /// Destination address.
        destination: IpAddress,
        /// SPI in host byte order.
        spi: u32,
        /// Transform protocol.
        protocol: u8,
    },
    /// Policy installation.
    InstallPolicy {
        /// Policy selector.
        selector: XfrmSelector,
        /// Policy direction.
        direction: XfrmDirection,
        /// Policy action.
        action: XfrmAction,
        /// Policy priority.
        priority: u32,
        /// Templates describing SAs that satisfy the policy.
        templates: Vec<XfrmTemplate>,
    },
    /// Policy rekey.
    RekeyPolicy {
        /// Policy selector.
        selector: XfrmSelector,
        /// Policy direction.
        direction: XfrmDirection,
        /// Policy action.
        action: XfrmAction,
        /// Policy priority.
        priority: u32,
        /// Templates describing SAs that satisfy the policy.
        templates: Vec<XfrmTemplate>,
    },
    /// Policy removal.
    RemovePolicy {
        /// Policy selector.
        selector: XfrmSelector,
        /// Policy direction.
        direction: XfrmDirection,
    },
    /// Capability probe.
    Probe,
}

/// Deterministic in-memory XFRM backend.
///
/// Records every operation so tests can assert on the requests that reached the
/// backend. SPI allocations choose the first free SPI in the requested
/// inclusive range, skipping reserved SPI 0. Errors can be injected to exercise
/// caller recovery paths.
#[derive(Debug, Clone)]
pub struct MockXfrmBackend {
    state: Arc<Mutex<MockState>>,
}

/// Allocated SPI identity used to allow the same SPI value to be reused for a
/// different destination or protocol.
type AllocatedSpiKey = (IpAddress, u8, u32);

#[derive(Debug)]
struct MockState {
    operations: Vec<MockOperation>,
    allocated_spis: BTreeSet<AllocatedSpiKey>,
    probe_result: XfrmProbe,
    failure: Option<XfrmError>,
}

impl MockXfrmBackend {
    /// Create a mock backend that reports itself as a dry-run/mock probe.
    pub fn new() -> Self {
        Self::with_probe(XfrmProbe::mock())
    }

    /// Create a mock backend with a specific probe result.
    pub fn with_probe(probe_result: XfrmProbe) -> Self {
        Self {
            state: Arc::new(Mutex::new(MockState {
                operations: Vec::new(),
                allocated_spis: BTreeSet::new(),
                probe_result,
                failure: None,
            })),
        }
    }

    /// Inject an error that every subsequent operation will return.
    pub fn set_failure(&self, error: XfrmError) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.failure = Some(error);
    }

    /// Clear any injected failure.
    pub fn clear_failure(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.failure = None;
    }

    /// Set the result returned by `probe`.
    pub fn set_probe_result(&self, probe_result: XfrmProbe) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.probe_result = probe_result;
    }

    /// Return all recorded operations, in order.
    pub fn operations(&self) -> Vec<MockOperation> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.operations.clone()
    }

    /// Clear the recorded operation log.
    pub fn clear_operations(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.operations.clear();
    }

    fn check_failure(state: &MockState) -> Result<(), XfrmError> {
        if let Some(ref error) = state.failure {
            return Err(error.clone());
        }
        Ok(())
    }
}

impl Default for MockXfrmBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl XfrmBackend for MockXfrmBackend {
    async fn allocate_spi(&self, request: AllocateSpiRequest) -> Result<SpiAllocation, XfrmError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;

        if request.min_spi > request.max_spi {
            return Err(XfrmError::invalid_config(
                "min_spi",
                "min_spi must not exceed max_spi",
            ));
        }

        // SPI 0 is reserved ("any" / wildcard) in XFRM; never allocate it.
        let start = request.min_spi.max(1);
        let spi = (start..=request.max_spi)
            .find(|spi| {
                !state
                    .allocated_spis
                    .contains(&(request.destination, request.protocol, *spi))
            })
            .ok_or(XfrmError::Unavailable)?;

        state
            .allocated_spis
            .insert((request.destination, request.protocol, spi));
        state.operations.push(MockOperation::AllocateSpi {
            destination: request.destination,
            protocol: request.protocol,
            min_spi: request.min_spi,
            max_spi: request.max_spi,
        });
        Ok(SpiAllocation {
            destination: request.destination,
            protocol: request.protocol,
            spi,
        })
    }

    async fn install_sa(&self, request: InstallSaRequest) -> Result<(), XfrmError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        state.operations.push(MockOperation::InstallSa {
            selector: request.parameters.selector.clone(),
            source_address: request.parameters.source_address,
            destination: request.parameters.id.destination,
            spi: request.parameters.id.spi,
            protocol: request.parameters.id.protocol,
            auth_algo: request
                .parameters
                .auth
                .as_ref()
                .map(|(a, _)| a.name.clone()),
            auth_truncation_len_bits: request
                .parameters
                .auth
                .as_ref()
                .map(|(a, _)| a.truncation_len_bits),
            auth_key_len: request
                .parameters
                .auth
                .as_ref()
                .map(|(_, k)| k.len())
                .unwrap_or(0),
            crypt_algo: request
                .parameters
                .crypt
                .as_ref()
                .map(|(a, _)| a.name.clone()),
            crypt_key_len: request
                .parameters
                .crypt
                .as_ref()
                .map(|(_, k)| k.len())
                .unwrap_or(0),
            mode: request.parameters.mode,
            lifetime: request.parameters.lifetime,
            replay_window: request.parameters.replay_window,
        });
        Ok(())
    }

    async fn rekey_sa(&self, request: RekeySaRequest) -> Result<(), XfrmError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        state.operations.push(MockOperation::RekeySa {
            selector: request.parameters.selector.clone(),
            source_address: request.parameters.source_address,
            destination: request.parameters.id.destination,
            spi: request.parameters.id.spi,
            protocol: request.parameters.id.protocol,
            auth_algo: request
                .parameters
                .auth
                .as_ref()
                .map(|(a, _)| a.name.clone()),
            auth_truncation_len_bits: request
                .parameters
                .auth
                .as_ref()
                .map(|(a, _)| a.truncation_len_bits),
            auth_key_len: request
                .parameters
                .auth
                .as_ref()
                .map(|(_, k)| k.len())
                .unwrap_or(0),
            crypt_algo: request
                .parameters
                .crypt
                .as_ref()
                .map(|(a, _)| a.name.clone()),
            crypt_key_len: request
                .parameters
                .crypt
                .as_ref()
                .map(|(_, k)| k.len())
                .unwrap_or(0),
            mode: request.parameters.mode,
            lifetime: request.parameters.lifetime,
            replay_window: request.parameters.replay_window,
        });
        Ok(())
    }

    async fn remove_sa(&self, request: RemoveSaRequest) -> Result<(), XfrmError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        state.operations.push(MockOperation::RemoveSa {
            destination: request.destination,
            spi: request.spi,
            protocol: request.protocol,
        });
        Ok(())
    }

    async fn install_policy(&self, request: InstallPolicyRequest) -> Result<(), XfrmError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        state.operations.push(MockOperation::InstallPolicy {
            selector: request.parameters.selector.clone(),
            direction: request.parameters.direction,
            action: request.parameters.action,
            priority: request.parameters.priority,
            templates: request.parameters.templates.clone(),
        });
        Ok(())
    }

    async fn rekey_policy(&self, request: RekeyPolicyRequest) -> Result<(), XfrmError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        state.operations.push(MockOperation::RekeyPolicy {
            selector: request.parameters.selector.clone(),
            direction: request.parameters.direction,
            action: request.parameters.action,
            priority: request.parameters.priority,
            templates: request.parameters.templates.clone(),
        });
        Ok(())
    }

    async fn remove_policy(&self, request: RemovePolicyRequest) -> Result<(), XfrmError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        state.operations.push(MockOperation::RemovePolicy {
            selector: request.selector.clone(),
            direction: request.direction,
        });
        Ok(())
    }

    async fn probe(&self) -> Result<XfrmProbe, XfrmError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        state.operations.push(MockOperation::Probe);
        Ok(state.probe_result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Algorithm, AuthAlgorithm, IpAddress, KeyMaterial, LifetimeConfig, PolicyParameters,
        SaParameters, XfrmAction, XfrmBackendKind, XfrmCapability, XfrmDirection, XfrmId, XfrmMode,
        XfrmSelector, XfrmTemplate,
    };

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddress {
        IpAddress::Ipv4([a, b, c, d])
    }

    fn sample_selector() -> XfrmSelector {
        XfrmSelector::new(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 50)
    }

    fn sample_sa_parameters() -> SaParameters {
        SaParameters {
            selector: sample_selector(),
            id: XfrmId {
                destination: ipv4(10, 0, 0, 2),
                spi: 0x1234_5678,
                protocol: 50,
            },
            source_address: ipv4(10, 0, 0, 1),
            auth: Some((
                AuthAlgorithm::new("hmac-sha256", 96),
                KeyMaterial::new(vec![0xab; 32]),
            )),
            crypt: Some((Algorithm::new("aes-cbc"), KeyMaterial::new(vec![0xcd; 32]))),
            mode: XfrmMode::Tunnel,
            lifetime: LifetimeConfig::default(),
            replay_window: 32,
        }
    }

    fn sample_policy_parameters() -> PolicyParameters {
        PolicyParameters {
            selector: sample_selector(),
            direction: XfrmDirection::Out,
            action: XfrmAction::Allow,
            priority: 100,
            templates: vec![XfrmTemplate {
                id: XfrmId {
                    destination: ipv4(10, 0, 0, 2),
                    spi: 0x1234_5678,
                    protocol: 50,
                },
                source_address: ipv4(10, 0, 0, 1),
                mode: XfrmMode::Tunnel,
            }],
        }
    }

    #[tokio::test]
    async fn mock_allocate_spi_records_operation_and_returns_spi() {
        let backend = MockXfrmBackend::new();
        let request = AllocateSpiRequest {
            destination: ipv4(10, 0, 0, 2),
            protocol: 50,
            min_spi: 0x100,
            max_spi: 0xffff_ffff,
        };
        let allocation = backend.allocate_spi(request).await.unwrap();
        assert_eq!(allocation.spi, 0x100);
        assert_eq!(allocation.destination, request.destination);
        assert_eq!(allocation.protocol, request.protocol);

        let ops = backend.operations();
        assert_eq!(ops.len(), 1);
        assert_eq!(
            ops[0],
            MockOperation::AllocateSpi {
                destination: request.destination,
                protocol: 50,
                min_spi: 0x100,
                max_spi: 0xffff_ffff,
            }
        );
    }

    fn expected_install_sa(params: &SaParameters) -> MockOperation {
        MockOperation::InstallSa {
            selector: params.selector.clone(),
            source_address: params.source_address,
            destination: params.id.destination,
            spi: params.id.spi,
            protocol: params.id.protocol,
            auth_algo: Some("hmac-sha256".to_string()),
            auth_truncation_len_bits: Some(96),
            auth_key_len: 32,
            crypt_algo: Some("aes-cbc".to_string()),
            crypt_key_len: 32,
            mode: XfrmMode::Tunnel,
            lifetime: LifetimeConfig::default(),
            replay_window: 32,
        }
    }

    fn expected_rekey_sa(params: &SaParameters) -> MockOperation {
        MockOperation::RekeySa {
            selector: params.selector.clone(),
            source_address: params.source_address,
            destination: params.id.destination,
            spi: params.id.spi,
            protocol: params.id.protocol,
            auth_algo: Some("hmac-sha256".to_string()),
            auth_truncation_len_bits: Some(96),
            auth_key_len: 32,
            crypt_algo: Some("aes-cbc".to_string()),
            crypt_key_len: 32,
            mode: XfrmMode::Tunnel,
            lifetime: LifetimeConfig::default(),
            replay_window: 32,
        }
    }

    #[tokio::test]
    async fn mock_install_sa_records_operation() {
        let backend = MockXfrmBackend::new();
        let params = sample_sa_parameters();
        backend
            .install_sa(InstallSaRequest {
                parameters: params.clone(),
            })
            .await
            .unwrap();

        let ops = backend.operations();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0], expected_install_sa(&params));
    }

    #[tokio::test]
    async fn mock_rekey_sa_records_operation() {
        let backend = MockXfrmBackend::new();
        let params = sample_sa_parameters();
        backend
            .rekey_sa(RekeySaRequest {
                parameters: params.clone(),
            })
            .await
            .unwrap();

        let ops = backend.operations();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0], expected_rekey_sa(&params));
    }

    #[tokio::test]
    async fn mock_remove_sa_records_operation() {
        let backend = MockXfrmBackend::new();
        let request = RemoveSaRequest {
            destination: ipv4(10, 0, 0, 2),
            protocol: 50,
            spi: 0x1234_5678,
        };
        backend.remove_sa(request).await.unwrap();

        let ops = backend.operations();
        assert_eq!(ops.len(), 1);
        assert_eq!(
            ops[0],
            MockOperation::RemoveSa {
                destination: request.destination,
                spi: request.spi,
                protocol: request.protocol,
            }
        );
    }

    fn expected_install_policy(params: &PolicyParameters) -> MockOperation {
        MockOperation::InstallPolicy {
            selector: params.selector.clone(),
            direction: params.direction,
            action: params.action,
            priority: params.priority,
            templates: params.templates.clone(),
        }
    }

    fn expected_rekey_policy(params: &PolicyParameters) -> MockOperation {
        MockOperation::RekeyPolicy {
            selector: params.selector.clone(),
            direction: params.direction,
            action: params.action,
            priority: params.priority,
            templates: params.templates.clone(),
        }
    }

    #[tokio::test]
    async fn mock_install_policy_records_operation() {
        let backend = MockXfrmBackend::new();
        let params = sample_policy_parameters();
        backend
            .install_policy(InstallPolicyRequest {
                parameters: params.clone(),
            })
            .await
            .unwrap();

        let ops = backend.operations();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0], expected_install_policy(&params));
    }

    #[tokio::test]
    async fn mock_rekey_policy_records_operation() {
        let backend = MockXfrmBackend::new();
        let params = sample_policy_parameters();
        backend
            .rekey_policy(RekeyPolicyRequest {
                parameters: params.clone(),
            })
            .await
            .unwrap();

        let ops = backend.operations();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0], expected_rekey_policy(&params));
    }

    #[tokio::test]
    async fn mock_remove_policy_records_operation() {
        let backend = MockXfrmBackend::new();
        let request = RemovePolicyRequest {
            selector: sample_selector(),
            direction: XfrmDirection::Out,
        };
        backend.remove_policy(request.clone()).await.unwrap();

        let ops = backend.operations();
        assert_eq!(ops.len(), 1);
        assert_eq!(
            ops[0],
            MockOperation::RemovePolicy {
                selector: request.selector,
                direction: request.direction,
            }
        );
    }

    #[tokio::test]
    async fn mock_probe_returns_configured_result() {
        let probe = XfrmProbe {
            kind: XfrmBackendKind::Mock,
            platform_supported: true,
            kernel_reachable: false,
            net_admin_capable: false,
            algorithms: XfrmCapability::Available,
            details: Some("configured probe"),
        };
        let backend = MockXfrmBackend::with_probe(probe);
        let result = backend.probe().await.unwrap();
        assert_eq!(result, probe);
        assert_eq!(backend.operations(), vec![MockOperation::Probe]);
    }

    #[tokio::test]
    async fn mock_failure_is_returned_and_prevents_recording() {
        let backend = MockXfrmBackend::new();
        backend.set_failure(XfrmError::Unavailable);
        let request = RemoveSaRequest {
            destination: ipv4(10, 0, 0, 2),
            protocol: 50,
            spi: 0x1234_5678,
        };
        let err = backend.remove_sa(request).await.unwrap_err();
        assert!(matches!(err, XfrmError::Unavailable));
        assert!(backend.operations().is_empty());

        backend.clear_failure();
        backend.remove_sa(request).await.unwrap();
        assert_eq!(backend.operations().len(), 1);
    }

    #[tokio::test]
    async fn mock_spi_allocation_is_deterministic() {
        let backend = MockXfrmBackend::new();
        let request = AllocateSpiRequest {
            destination: ipv4(10, 0, 0, 2),
            protocol: 50,
            min_spi: 0,
            max_spi: 0xffff_ffff,
        };
        let a1 = backend.allocate_spi(request).await.unwrap();
        let a2 = backend.allocate_spi(request).await.unwrap();
        // SPI 0 is reserved, so allocation starts at 1.
        assert_eq!(a1.spi, 1);
        assert_eq!(a2.spi, 2);
    }

    #[tokio::test]
    async fn mock_allocate_spi_respects_requested_range() {
        let backend = MockXfrmBackend::new();
        let request = AllocateSpiRequest {
            destination: ipv4(10, 0, 0, 2),
            protocol: 50,
            min_spi: 0x200,
            max_spi: 0x200,
        };
        let allocation = backend.allocate_spi(request).await.unwrap();
        assert_eq!(allocation.spi, 0x200);
    }

    #[tokio::test]
    async fn mock_allocate_spi_rejects_invalid_range() {
        let backend = MockXfrmBackend::new();
        let request = AllocateSpiRequest {
            destination: ipv4(10, 0, 0, 2),
            protocol: 50,
            min_spi: 0x300,
            max_spi: 0x200,
        };
        let err = backend.allocate_spi(request).await.unwrap_err();
        assert!(
            matches!(err, XfrmError::InvalidConfig { field, .. } if field == "min_spi"),
            "expected InvalidConfig for min_spi, got {err:?}"
        );
    }

    #[tokio::test]
    async fn mock_allocate_spi_returns_unavailable_when_exhausted() {
        let backend = MockXfrmBackend::new();
        let request = AllocateSpiRequest {
            destination: ipv4(10, 0, 0, 2),
            protocol: 50,
            min_spi: 0x10,
            max_spi: 0x12,
        };
        backend.allocate_spi(request).await.unwrap();
        backend.allocate_spi(request).await.unwrap();
        backend.allocate_spi(request).await.unwrap();
        let err = backend.allocate_spi(request).await.unwrap_err();
        assert!(matches!(err, XfrmError::Unavailable));
    }

    #[tokio::test]
    async fn mock_allocate_spi_allows_same_spi_for_different_destination_or_protocol() {
        let backend = MockXfrmBackend::new();
        let base = AllocateSpiRequest {
            destination: ipv4(10, 0, 0, 2),
            protocol: 50,
            min_spi: 0x100,
            max_spi: 0x100,
        };
        let a1 = backend.allocate_spi(base).await.unwrap();
        assert_eq!(a1.spi, 0x100);

        let different_destination = AllocateSpiRequest {
            destination: ipv4(10, 0, 0, 3),
            ..base
        };
        let a2 = backend.allocate_spi(different_destination).await.unwrap();
        assert_eq!(a2.spi, 0x100);

        let different_protocol = AllocateSpiRequest {
            destination: ipv4(10, 0, 0, 2),
            protocol: 51,
            ..base
        };
        let a3 = backend.allocate_spi(different_protocol).await.unwrap();
        assert_eq!(a3.spi, 0x100);

        let same_identity = AllocateSpiRequest {
            destination: ipv4(10, 0, 0, 2),
            protocol: 50,
            min_spi: 0x100,
            max_spi: 0x100,
        };
        let err = backend.allocate_spi(same_identity).await.unwrap_err();
        assert!(matches!(err, XfrmError::Unavailable));
    }
}
