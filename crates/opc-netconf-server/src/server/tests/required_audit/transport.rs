//! Real transport authentication, distinct RPC identities and opaque correlation.

use super::*;
use opc_persist::audit_authority::continuity::AuditExportVerifier;
use opc_persist::audit_authority::{AuditCaller, AuditPrivacyProjection, AuditPrivacyPurpose};
use opc_persist::{
    ManagementAuditOperationCode, ManagementAuditOutcomeCode, ManagementAuditTransportCode,
};

fn identity() -> ConfigConsensusIdentity {
    ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::new("netconf-required-audit-fixture").unwrap(),
        ConfigConsensusConfigurationId::from_bytes([0x70; 32]),
        ConfigConsensusConfigurationEpoch::new(1).unwrap(),
    )
}

#[tokio::test]
async fn mtls_edits_with_duplicate_xml_ids_keep_distinct_requests_and_opaque_exact_audit() {
    let h = Harness::start().await;
    let server = Arc::new(running::required_server(&h));
    let state = identity_state(
        "spiffe://test-domain/tenant/tenant-a/ns/default/sa/netconf/nf/amf/instance/0",
    );
    let expected_principal =
        crate::transport::principal_from_identity_state(&state.svid.cert_chain, &state).unwrap();
    assert!(
        expected_principal.tenant == principal().tenant,
        "fixture tenant mismatch"
    );
    assert_eq!(expected_principal.auth_strength, AuthStrength::MutualTls);
    let (_identity_tx, identity_rx) = watch::channel(Some(state));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = ShutdownToken::new();
    let limits = MgmtLimits::default();
    let listener_task = tokio::spawn(run_read_only_tls_listener(
        server.clone(),
        listener,
        TlsBootstrap::new(RuntimeMode::Production, peer_policy()),
        identity_rx.clone(),
        shutdown.clone(),
        TlsListenerConfig {
            session: SessionConfig {
                limits,
                frame_timeout: Duration::from_secs(5),
            },
            drain_timeout: Duration::from_secs(5),
            ..TlsListenerConfig::default()
        },
    ));
    let connector = TlsConnector::from(Arc::new(
        TlsConfigBuilder::new(identity_rx)
            .with_policy(peer_policy())
            .build_client_config()
            .unwrap(),
    ));
    let tcp = TcpStream::connect(address).await.unwrap();
    let mut tls = connector
        .connect(ServerName::try_from("localhost").unwrap().to_owned(), tcp)
        .await
        .unwrap();
    let hello = tokio::time::timeout(Duration::from_secs(5), read_base10_frame(&mut tls))
        .await
        .unwrap();
    let hello = String::from_utf8(hello).unwrap();
    assert!(hello.contains(WRITABLE_RUNNING_1_0));
    for unsupported in [CANDIDATE_1_0, CONFIRMED_COMMIT_1_1, STARTUP_1_0] {
        assert!(
            !hello.contains(unsupported),
            "unexpected capability in running-only fixture"
        );
    }
    let hello = format!(
        r#"<hello xmlns="{NETCONF_BASE_NS}"><capabilities><capability>{NETCONF_BASE_1_0}</capability></capabilities></hello>"#
    );
    tls.write_all(&base10::encode_message(hello.as_bytes(), &limits).unwrap())
        .await
        .unwrap();

    let mut committed = Vec::new();
    for (index, hostname) in ["fixture-tls-first", "fixture-tls-second"]
        .into_iter()
        .enumerate()
    {
        // XML correlation can repeat. The session must allocate a distinct SDK
        // request for each received RPC, never treat this value as replay power.
        let xml = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="synthetic-duplicate"><edit-config><target><running/></target><config><sys:system xmlns:sys="urn:opc:demo"><sys:hostname>{hostname}</sys:hostname></sys:system></config></edit-config></rpc>"#
        );
        tls.write_all(&base10::encode_message(xml.as_bytes(), &limits).unwrap())
            .await
            .unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(5), read_base10_frame(&mut tls))
            .await
            .unwrap();
        let reply = String::from_utf8(reply).unwrap();
        assert!(
            reply.contains("<ok/>"),
            "authenticated edit was not committed"
        );
        assert!(reply.contains("message-id=\"synthetic-duplicate\""));
        let stored = h.source.load_committed_latest().await.unwrap().unwrap();
        assert!(
            stored.principal == expected_principal,
            "transport caller binding mismatch"
        );
        assert_eq!(stored.version, ConfigVersion::new(index as u64 + 2));
        assert_eq!(stored.config.hostname, hostname);
        assert!(
            stored.request_id.is_some(),
            "session did not retain the original request"
        );
        committed.push(stored);
    }
    assert!(
        committed[0].request_id != committed[1].request_id,
        "XML correlation reused an SDK request"
    );
    assert!(
        committed[0].tx_id != committed[1].tx_id,
        "distinct effects reused a transaction"
    );
    assert_eq!(h.checkpoints.sequence(), 9);

    let privacy = AuditPrivacyKey::new([0x81; 32]).unwrap();
    let descriptor = opc_mgmt_audit::principal_descriptor(&expected_principal);
    let caller =
        AuditCaller::project(&privacy, expected_principal.tenant.as_str(), &descriptor).unwrap();
    let export = h
        .authority
        .freeze_audit_export(caller, 0, Duration::from_secs(60))
        .await
        .unwrap();
    let page = export.page(None, 256, caller).unwrap();
    assert!(page.next_cursor().is_none());
    // This is trusted authority-side inspection. The fixture deliberately has
    // signing keys; it makes no recipient-only verification claim for #959.
    let mut verifier = AuditExportVerifier::new(
        Arc::new(AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x91; 32]).unwrap()]).unwrap()),
        export.manifest().clone(),
        identity(),
        caller,
        ::time::OffsetDateTime::now_utc().unix_timestamp(),
    )
    .unwrap();
    verifier.accept(&page).unwrap();
    verifier.finish().unwrap();
    let encoded = page.encode().unwrap();
    let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    let rows = value["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 9);
    let text = std::str::from_utf8(&encoded).unwrap();
    for raw in [
        expected_principal.tenant.as_str(),
        descriptor.as_str(),
        "fixture-tls-first",
        "fixture-tls-second",
        "synthetic-secret",
        "synthetic-duplicate",
    ] {
        assert!(
            !text.contains(raw),
            "private input escaped into audit export"
        );
    }
    for stored in &committed {
        let request_id = stored.request_id.unwrap();
        assert!(
            !text.contains(&request_id.to_string()),
            "raw request escaped into audit export"
        );
        assert!(
            !text.contains(&stored.tx_id.to_string()),
            "raw transaction escaped into audit export"
        );
        let request = privacy
            .project(
                AuditPrivacyPurpose::Request,
                &[
                    expected_principal.tenant.as_str().as_bytes(),
                    descriptor.as_bytes(),
                    request_id.as_uuid().as_bytes(),
                ],
            )
            .unwrap();
        let request = serde_json::to_value(request).unwrap();
        let matched: Vec<_> = rows
            .iter()
            .filter(|row| row["entry"]["payload"]["intent"]["body"]["event"]["request"] == request)
            .collect();
        assert_eq!(
            matched.len(),
            1,
            "effect does not have one exact protocol intent"
        );
        let handle = &matched[0]["entry"]["payload"]["intent"];
        let event = &handle["body"]["event"];
        assert!(
            event["caller"] == serde_json::to_value(caller).unwrap(),
            "projected caller mismatch"
        );
        assert_eq!(
            event["transport"],
            serde_json::to_value(ManagementAuditTransportCode::NetconfTls).unwrap()
        );
        assert_eq!(
            event["operation"],
            serde_json::to_value(ManagementAuditOperationCode::Update).unwrap()
        );
        assert_eq!(
            event["outcome"],
            serde_json::to_value(ManagementAuditOutcomeCode::Intent).unwrap()
        );
        let transaction = privacy
            .project(
                AuditPrivacyPurpose::Transaction,
                &[
                    expected_principal.tenant.as_str().as_bytes(),
                    descriptor.as_bytes(),
                    stored.tx_id.to_string().as_bytes(),
                ],
            )
            .unwrap();
        assert!(
            event["transaction"] == serde_json::to_value(transaction).unwrap(),
            "projected effect mismatch"
        );
        for terminal in ["outcome", "terminal"] {
            let matches = rows
                .iter()
                .filter(|row| row["entry"]["payload"][terminal]["operation"] == handle["mac"])
                .count();
            assert_eq!(
                matches, 1,
                "exact effect completion row missing or duplicated"
            );
        }
    }
    drop(export);
    tls.shutdown().await.unwrap();
    drop(tls);
    shutdown.request_shutdown();
    let finished = tokio::time::timeout(Duration::from_secs(5), listener_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            finished.accepted_sessions,
            finished.completed_sessions,
            finished.failed_sessions,
            finished.rejected_sessions
        ),
        (1, 1, 0, 0)
    );
    drop(server);
    h.shutdown().await;
}

#[tokio::test]
async fn reply_write_timeout_preserves_the_exact_commit_and_its_terminal_fence() {
    let h = Harness::start().await;
    let server = Arc::new(running::required_server(&h));
    let sessions = SessionRegistry::new();
    let session_server = server.clone();
    let session_registry = sessions.clone();
    let (mut client, mut server_io) = tokio::io::duplex(1);
    // Exercise the actual session write timeout with its unchanged default.
    // The one-byte stream cannot accept an RPC reply while its peer stops
    // reading. No synthetic RPC deadline or sleep advances the operation.
    let config = SessionConfig::default();
    h.checkpoints.refuse_from.store(6, Ordering::Release);
    let session = tokio::spawn(async move {
        crate::session::run_read_only_session_with_registry(
            session_server.as_ref(),
            &principal(),
            &mut server_io,
            config,
            1,
            &session_registry,
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(5), read_base10_frame(&mut client))
        .await
        .unwrap();
    let hello = format!(
        r#"<hello xmlns="{NETCONF_BASE_NS}"><capabilities><capability>{NETCONF_BASE_1_0}</capability></capabilities></hello>"#
    );
    client
        .write_all(&base10::encode_message(hello.as_bytes(), &config.limits).unwrap())
        .await
        .unwrap();
    let edit = edit_config_rpc_to(
        "running",
        r#"<sys:system xmlns:sys="urn:opc:demo"><sys:hostname>fixture-timeout</sys:hostname></sys:system>"#,
        "merge",
    );
    client
        .write_all(&base10::encode_message(edit.as_bytes(), &config.limits).unwrap())
        .await
        .unwrap();
    let result = tokio::time::timeout(config.frame_timeout + Duration::from_secs(5), session)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(result, Err(crate::session::SessionError::Io(ref error))
            if error.kind() == std::io::ErrorKind::TimedOut),
        "blocked reply did not reach the session write timeout"
    );
    assert!(!sessions.contains_session_for_test(1));

    let first = h.source.load_committed_latest().await.unwrap().unwrap();
    assert_eq!(first.version, ConfigVersion::new(2));
    assert_eq!(first.config.hostname, "fixture-timeout");
    assert!(first.principal == principal(), "timed-out caller changed");
    let original_request = first.request_id.unwrap();
    let resolved = h
        .bus
        .resolve_request_id(original_request)
        .await
        .unwrap()
        .unwrap();
    assert!(
        resolved.tx_id == first.tx_id,
        "reply timeout lost the original committed result"
    );
    assert_eq!(resolved.new_version, Some(ConfigVersion::new(2)));
    assert_eq!(h.checkpoints.sequence(), 4);

    let later_session = sessions.register(2).unwrap();
    let later = edit.replace("fixture-timeout", "fixture-after-timeout");
    let refused = server
        .handle_rpc_for_session_async(
            RequestId::new(),
            &principal(),
            &later,
            &config.limits,
            2,
            &sessions,
        )
        .await;
    assert!(refused.reply_xml.contains("operation-failed"));
    let pending = h.authority.reconcile_audit_obligations(30).await.unwrap();
    assert_eq!(
        (pending.completed, pending.pending, pending.unknown),
        (0, 0, 1)
    );
    let latest = h.source.load_committed_latest().await.unwrap().unwrap();
    assert!(
        latest.tx_id == first.tx_id,
        "terminal fence allowed another effect"
    );

    h.checkpoints.refuse_from.store(0, Ordering::Release);
    let recovered = h.authority.reconcile_audit_obligations(30).await.unwrap();
    assert_eq!(
        (recovered.completed, recovered.pending, recovered.unknown),
        (1, 0, 0)
    );
    assert_eq!(h.checkpoints.sequence(), 6);
    let exact = h
        .bus
        .resolve_request_id(original_request)
        .await
        .unwrap()
        .unwrap();
    assert!(
        exact.tx_id == first.tx_id,
        "recovery changed the original effect"
    );
    // Recovery resolved only the original request. A new write is permitted
    // after that obligation is complete and has its own audit operation.
    let permitted = server
        .handle_rpc_for_session_async(
            RequestId::new(),
            &principal(),
            &later,
            &config.limits,
            2,
            &sessions,
        )
        .await;
    assert!(
        permitted.reply_xml.contains("<ok/>"),
        "recovered fence stayed closed"
    );
    let latest = h.source.load_committed_latest().await.unwrap().unwrap();
    assert_eq!(latest.version, ConfigVersion::new(3));
    assert!(
        latest.request_id != Some(original_request) && latest.tx_id != first.tx_id,
        "new write reused the recovered operation"
    );
    assert_eq!(h.checkpoints.sequence(), 9);
    drop(later_session);
    drop(client);
    drop(server);
    h.shutdown().await;
}
