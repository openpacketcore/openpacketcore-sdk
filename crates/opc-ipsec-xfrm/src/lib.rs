//! Safe Linux XFRM IPsec backend model for OpenPacketCore.
//!
//! This crate provides a backend trait for XFRM SA/policy lifecycle operations,
//! a deterministic mock backend for tests, an unsupported-platform backend, and
//! redaction-safe error types. It deliberately does not implement IKE,
//! ESP processing, namespace management, or deployment policy.
//!
//! Raw Linux netlink work stays in [`opc_linux_xfrm_sys`]; this crate is safe
//! Rust and never performs `unsafe` operations.

#![forbid(unsafe_code)]

pub mod backend;
pub mod composite;
pub mod error;
#[cfg(feature = "ikev2")]
pub mod ikev2;
pub mod linux;
pub mod mock;
pub mod model;
pub mod unsupported;

pub use backend::XfrmBackend;
pub use composite::{
    install_sa_policy_with_rollback, rekey_sa_policy, remove_policy_sa, XfrmCompositeInstallError,
    XfrmCompositeInstallRequest, XfrmCompositeOperation, XfrmCompositeOutcome,
    XFRM_COMPOSITE_INSTALL_ORDER, XFRM_COMPOSITE_INSTALL_ROLLBACK_ORDER,
    XFRM_COMPOSITE_REKEY_ORDER, XFRM_COMPOSITE_REMOVE_ORDER,
};
pub use error::XfrmError;
#[cfg(feature = "ikev2")]
pub use ikev2::{
    build_xfrm_requests_from_ikev2_child_sa, Ikev2ChildSaXfrmError, Ikev2ChildSaXfrmKeys,
    Ikev2ChildSaXfrmRequest, Ikev2ChildSaXfrmRequests, IKEV2_SECURITY_PROTOCOL_ID_ESP, IPPROTO_ESP,
};
pub use linux::{LinuxXfrmBackend, LinuxXfrmBackendConfig};
pub use mock::{MockOperation, MockXfrmBackend};
pub use model::{
    Algorithm, AllocateSpiRequest, AuthAlgorithm, InstallPolicyRequest, InstallSaRequest,
    IpAddress, KeyMaterial, LifetimeConfig, PolicyParameters, RekeyPolicyRequest, RekeySaRequest,
    RemovePolicyRequest, RemoveSaRequest, SaParameters, SpiAllocation, XfrmAction, XfrmBackendKind,
    XfrmCapability, XfrmDirection, XfrmId, XfrmMode, XfrmProbe, XfrmSelector, XfrmTemplate,
};
pub use unsupported::UnsupportedXfrmBackend;

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::model::{
        Algorithm, AuthAlgorithm, InstallPolicyRequest, InstallSaRequest, IpAddress, KeyMaterial,
        LifetimeConfig, PolicyParameters, RekeyPolicyRequest, RekeySaRequest, RemovePolicyRequest,
        RemoveSaRequest, SaParameters, XfrmAction, XfrmBackendKind, XfrmDirection, XfrmId,
        XfrmMode, XfrmProbe, XfrmSelector, XfrmTemplate,
    };
    use crate::XfrmBackend;

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
    async fn mock_backend_lifecycle_round_trip() {
        let backend = MockXfrmBackend::new();

        let allocate = AllocateSpiRequest {
            destination: ipv4(10, 0, 0, 2),
            protocol: 50,
            min_spi: 0x100,
            max_spi: 0xffff_ffff,
        };
        let spi = backend.allocate_spi(allocate).await.unwrap();
        assert_eq!(spi.spi, 0x100);

        let params = sample_sa_parameters();
        backend
            .install_sa(InstallSaRequest {
                parameters: params.clone(),
            })
            .await
            .unwrap();

        backend
            .rekey_sa(RekeySaRequest {
                parameters: params.clone(),
            })
            .await
            .unwrap();

        backend
            .remove_sa(RemoveSaRequest {
                destination: params.id.destination,
                protocol: params.id.protocol,
                spi: params.id.spi,
            })
            .await
            .unwrap();

        let policy = sample_policy_parameters();
        backend
            .install_policy(InstallPolicyRequest {
                parameters: policy.clone(),
            })
            .await
            .unwrap();

        backend
            .rekey_policy(RekeyPolicyRequest {
                parameters: policy.clone(),
            })
            .await
            .unwrap();

        backend
            .remove_policy(RemovePolicyRequest {
                selector: policy.selector.clone(),
                direction: policy.direction,
            })
            .await
            .unwrap();

        let probe = backend.probe().await.unwrap();
        assert_eq!(probe.kind, XfrmBackendKind::Mock);
        assert!(probe.platform_supported);
        assert!(!probe.kernel_reachable);
        assert!(!probe.net_admin_capable);

        assert_eq!(backend.operations().len(), 8);
    }

    #[tokio::test]
    async fn sa_request_with_key_material_does_not_leak_in_error() {
        let backend = MockXfrmBackend::new();
        backend.set_failure(XfrmError::NotFound);
        let params = sample_sa_parameters();
        let err = backend
            .install_sa(InstallSaRequest {
                parameters: params.clone(),
            })
            .await
            .unwrap_err();
        let debug = format!("{err:?}");
        let display = err.to_string();
        assert!(
            !debug.contains("ab") && !debug.contains("cd"),
            "debug leaked key material: {debug}"
        );
        assert!(
            !display.contains("ab") && !display.contains("cd"),
            "display leaked key material: {display}"
        );
    }

    #[tokio::test]
    async fn unsupported_backend_is_trait_object_safe() {
        let backend: Box<dyn XfrmBackend> = Box::new(UnsupportedXfrmBackend::new());
        let probe = backend.probe().await.unwrap();
        assert_eq!(probe, XfrmProbe::unsupported());
    }
}
