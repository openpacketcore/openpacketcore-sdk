use opc_ipsec_xfrm::{
    ExclusiveNamespaceResetAcknowledgement, InstallPolicyRequest, IpAddress, MockXfrmBackend,
    PolicyParameters, UnsupportedXfrmBackend, XfrmAction, XfrmBackend, XfrmDirection, XfrmError,
    XfrmSelector,
};

fn acknowledgement() -> ExclusiveNamespaceResetAcknowledgement {
    ExclusiveNamespaceResetAcknowledgement::sole_xfrm_writer_and_retains_no_predecessor_state()
}

fn policy() -> InstallPolicyRequest {
    InstallPolicyRequest {
        parameters: PolicyParameters {
            selector: XfrmSelector::new(
                IpAddress::Ipv4([192, 0, 2, 1]),
                IpAddress::Ipv4([192, 0, 2, 2]),
                17,
            ),
            direction: XfrmDirection::Out,
            action: XfrmAction::Block,
            priority: 100,
            templates: Vec::new(),
            mark: None,
            if_id: None,
        },
    }
}

#[tokio::test]
async fn mock_reset_releases_predecessor_selectors_and_is_idempotent() {
    let predecessor = MockXfrmBackend::new();
    predecessor.install_policy(policy()).await.unwrap();
    let successor = predecessor.rebind_namespace();
    drop(predecessor);
    assert!(matches!(
        successor.install_policy(policy()).await,
        Err(XfrmError::AlreadyExists)
    ));
    assert!(successor
        .reset_exclusively_owned_namespace(acknowledgement())
        .await
        .is_err());
    let successor = successor.rebind_namespace();
    let report = successor
        .reset_exclusively_owned_namespace(acknowledgement())
        .await
        .unwrap();
    assert_eq!(report.stores_reset, 0);
    successor
        .reset_exclusively_owned_namespace(acknowledgement())
        .await
        .unwrap();
    assert_eq!(successor.namespace_resets().len(), 2);
    successor.install_policy(policy()).await.unwrap();
    assert!(successor
        .reset_exclusively_owned_namespace(acknowledgement())
        .await
        .is_err());
    assert!(matches!(
        successor.install_policy(policy()).await,
        Err(XfrmError::AlreadyExists)
    ));
}

#[tokio::test]
async fn mock_reset_failure_requires_retry_before_mutation() {
    let backend = MockXfrmBackend::new();
    backend.set_failure(XfrmError::StateIndeterminate {
        operation: "exclusive_namespace_reset",
    });
    assert!(matches!(
        backend
            .reset_exclusively_owned_namespace(acknowledgement())
            .await,
        Err(XfrmError::StateIndeterminate { .. })
    ));
    backend.clear_failure();
    assert!(backend.install_policy(policy()).await.is_err());
    backend
        .reset_exclusively_owned_namespace(acknowledgement())
        .await
        .unwrap();
    backend.install_policy(policy()).await.unwrap();
}

#[tokio::test]
async fn unsupported_reset_fails_closed() {
    assert!(matches!(
        UnsupportedXfrmBackend::new()
            .reset_exclusively_owned_namespace(acknowledgement())
            .await,
        Err(XfrmError::UnsupportedFeature { .. }) | Err(XfrmError::UnsupportedPlatform)
    ));
}
