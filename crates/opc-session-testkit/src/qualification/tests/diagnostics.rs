use super::*;
use std::collections::BTreeMap;

fn lifecycle() -> QualificationConnectionLifecycleMetrics {
    QualificationConnectionLifecycleMetrics {
        retirement_maximum_age: 0,
        retirement_local_leaf_expiry: 0,
        retirement_peer_leaf_expiry: 0,
        retirement_local_certificate_chain_expiry: 0,
        retirement_peer_certificate_chain_expiry: 0,
        retirement_material_epoch: 0,
        retirement_explicit: 0,
        retirement_idle_timeout: 0,
        active_connections: 4,
        draining_connections: 0,
        drain_started: 0,
        drain_completed: 0,
        drain_overruns: 0,
        connection_attempts: 5,
        connection_successes: 4,
        connection_failure_transport: 1,
        connection_failure_authentication: 0,
        connection_failure_timeout: 0,
        connection_superseded: 0,
        connection_abandoned: 0,
        connection_failure_protocol: 0,
        connection_failure_backend: 0,
        reconnect_attempts: 1,
        reconnect_failures: 0,
        empty_vote_dispatches: 0,
    }
}

fn client_connections() -> BTreeMap<usize, serde_json::Value> {
    [0, 2].into_iter().map(|remote_node| {
        (remote_node, serde_json::json!({
            "local_node": 1,
            "remote_node": remote_node,
            "generation": 0,
            "material_epoch": 1,
            "pool": {
                "primary": {"available_permits": 1, "cached_connection": true},
                "overflow": {"available_permits": 1, "cached_connection": false},
                "cold": {"phase": "idle", "failure": null, "remote_retirement_probe_gate": false},
            },
            "classified_pools": null,
        }))
    }).collect()
}

#[test]
fn consensus_diagnostics_round_trips_nonempty_client_connections_within_control_bound() {
    let metrics = opc_session_store::ConsensusStoreDiagnosticSnapshot {
        raw_read_barrier_deadline: 3,
        ..Default::default()
    };
    let lifecycle = lifecycle();
    // The empty control isolates the numeric map-key shape used by projected
    // mTLS peers from the FoundationPlaintext reply and ordinary counters.
    for client_connections in [BTreeMap::new(), client_connections()] {
        let reply = QualificationNodeReply::ConsensusDiagnostics {
            metrics,
            lifecycle: Box::new(lifecycle),
            client_connections: client_connections.clone(),
        };
        let mut encoded = Vec::new();
        write_json_line(&mut encoded, &reply).expect("bounded diagnostics writer");
        assert_eq!(encoded.last(), Some(&b'\n'));
        assert!(encoded.len() - 1 <= QUALIFICATION_MAX_CONTROL_LINE_BYTES);
        eprintln!(
            "ConsensusDiagnostics: peers={}, bytes={}, bound={}",
            client_connections.len(),
            encoded.len() - 1,
            QUALIFICATION_MAX_CONTROL_LINE_BYTES
        );
        let mut reader = io::BufReader::new(encoded.as_slice());
        let decoded = read_bounded_json_line::<_, QualificationNodeReply>(&mut reader)
            .unwrap_or_else(|error| {
                panic!(
                    "bounded diagnostics reader: {error}; JSON decode: {:?}",
                    serde_json::from_slice::<QualificationNodeReply>(&encoded)
                )
            })
            .expect("one complete diagnostics frame");
        let QualificationNodeReply::ConsensusDiagnostics {
            metrics: decoded_metrics,
            lifecycle: decoded_lifecycle,
            client_connections: decoded_connections,
        } = decoded
        else {
            panic!("diagnostics reply kind changed")
        };
        assert_eq!(decoded_metrics, metrics);
        assert_eq!(*decoded_lifecycle, lifecycle);
        assert_eq!(decoded_connections, client_connections);
        assert!(
            read_bounded_json_line::<_, QualificationNodeReply>(&mut reader)
                .unwrap()
                .is_none()
        );
    }
}

fn empty_diagnostics() -> QualificationNodeReply {
    QualificationNodeReply::ConsensusDiagnostics {
        metrics: Default::default(),
        lifecycle: Box::new(lifecycle()),
        client_connections: BTreeMap::new(),
    }
}

#[test]
fn consensus_diagnostics_rejects_invalid_or_duplicate_peer_indexes() {
    let encoded = serde_json::to_string(&empty_diagnostics()).unwrap();
    for connections in [
        r#"{"peer":null}"#.to_owned(),
        r#"{"-1":null}"#.to_owned(),
        r#"{"+1":null}"#.to_owned(),
        r#"{"01":null}"#.to_owned(),
        r#"{"1.0":null}"#.to_owned(),
        r#"{"0":null,"0":true}"#.to_owned(),
        format!(r#"{{"{}0":null}}"#, usize::MAX),
        "null".to_owned(),
        "[]".to_owned(),
    ] {
        let malformed = encoded.replace(
            r#""client_connections":{}"#,
            &format!(r#""client_connections":{connections}"#),
        );
        assert_ne!(malformed, encoded);
        assert!(matches!(
            read_bounded_json_line::<_, QualificationNodeReply>(&mut malformed.as_bytes()),
            Err(QualificationLineError::Invalid)
        ));
    }
}

#[test]
fn consensus_diagnostics_retains_strict_fields_and_control_line_bound() {
    let mut encoded = serde_json::to_value(empty_diagnostics()).unwrap();
    encoded["unexpected"] = serde_json::json!(true);
    let mut bytes = Vec::new();
    write_json_line(&mut bytes, &encoded).unwrap();
    assert!(matches!(
        read_bounded_json_line::<_, QualificationNodeReply>(&mut bytes.as_slice()),
        Err(QualificationLineError::Invalid)
    ));

    let oversized = QualificationNodeReply::ConsensusDiagnostics {
        metrics: Default::default(),
        lifecycle: Box::new(lifecycle()),
        client_connections: BTreeMap::from([(
            0,
            serde_json::json!("x".repeat(QUALIFICATION_MAX_CONTROL_LINE_BYTES)),
        )]),
    };
    let mut bytes = Vec::new();
    assert!(matches!(
        write_json_line(&mut bytes, &oversized),
        Err(QualificationLineError::TooLarge)
    ));
    assert!(bytes.is_empty());
    let encoded = serde_json::to_vec(&oversized).unwrap();
    assert!(matches!(
        read_bounded_json_line::<_, QualificationNodeReply>(&mut encoded.as_slice()),
        Err(QualificationLineError::TooLarge)
    ));
}
