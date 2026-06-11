use opc_persist::{
    AuditKey, AuditOpType, AuditRecord, ClusterMembership, CommitRecord, CommitSource, ConfigStore,
    ConsensusClock, ConsensusConfigStore, NodeIdentity, Role, RollbackTarget, SqliteBackend,
    TcpPeer, TcpRpcServer,
};
use opc_types::{ConfigVersion, SchemaDigest, Timestamp, TxId};
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

fn decode_hex(hex_str: &str) -> Result<Vec<u8>, String> {
    let hex_str = hex_str.trim_start_matches("0x");
    if hex_str.len() % 2 != 0 {
        return Err("Odd number of hex characters".to_string());
    }
    let mut bytes = Vec::with_capacity(hex_str.len() / 2);
    for i in 0..(hex_str.len() / 2) {
        let s = &hex_str[i * 2..i * 2 + 2];
        let b = u8::from_str_radix(s, 16).map_err(|e| e.to_string())?;
        bytes.push(b);
    }
    Ok(bytes)
}

fn decode_hex_32(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = decode_hex(hex_str)?;
    if bytes.len() != 32 {
        return Err(format!("Expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn extract_tenant(principal: &str) -> String {
    opc_persist::extract_tenant(principal)
}

fn print_success<T: serde::Serialize>(data: T) {
    let resp = serde_json::json!({
        "success": true,
        "data": data
    });
    println!("{}", resp);
    std::io::stdout().flush().ok();
}

fn print_error(err: &str) {
    let resp = serde_json::json!({
        "success": false,
        "error": err
    });
    println!("{}", resp);
    std::io::stdout().flush().ok();
}

async fn handle_command_line(
    line: &str,
    store: &Arc<ConsensusConfigStore>,
    audit_key: &AuditKey,
) -> Result<(), String> {
    let val: serde_json::Value =
        serde_json::from_str(line).map_err(|e| format!("invalid JSON: {}", e))?;
    let cmd = val["command"]
        .as_str()
        .or_else(|| val["cmd"].as_str())
        .ok_or_else(|| "missing 'command' or 'cmd' field".to_string())?;

    match cmd {
        "Campaign" => {
            store.campaign().await.map_err(|e| e.to_string())?;
            print_success(serde_json::Value::Null);
        }
        "AppendCommit" => {
            let tx_id_str = val["tx_id"].as_str().ok_or("missing tx_id")?;
            let tx_id = TxId::from_str(tx_id_str).map_err(|e| e.to_string())?;
            let version = val["version"].as_u64().ok_or("missing version")?;
            let principal = val["principal"]
                .as_str()
                .ok_or("missing principal")?
                .to_string();
            let encrypted_blob_hex = val["encrypted_blob"]
                .as_str()
                .ok_or("missing encrypted_blob")?;
            let encrypted_blob = decode_hex(encrypted_blob_hex)?;

            let audit_paths_val = val["audit_paths"]
                .as_array()
                .ok_or("missing or invalid audit_paths")?;
            let mut audit_paths = Vec::new();
            for path_v in audit_paths_val {
                let path_str = path_v
                    .as_str()
                    .ok_or("audit_paths must be string array")?
                    .to_string();
                audit_paths.push(path_str);
            }

            let confirmed_deadline_val = val
                .get("confirmed_deadline")
                .or_else(|| val.get("confirmed-deadline"))
                .or_else(|| val.get("--confirmed-deadline"))
                .or_else(|| val.get("--confirmed_deadline"));
            let confirmed_deadline = if let Some(deadline_val) = confirmed_deadline_val {
                if deadline_val.is_null() {
                    None
                } else if let Some(secs) = deadline_val
                    .as_i64()
                    .or_else(|| deadline_val.as_f64().map(|f| f as i64))
                {
                    Some(Timestamp::from_offset_datetime(
                        *Timestamp::now_utc().as_offset_datetime() + time::Duration::seconds(secs),
                    ))
                } else if let Some(s) = deadline_val.as_str() {
                    let ts = Timestamp::from_str(s).map_err(|e| e.to_string())?;
                    Some(ts)
                } else {
                    None
                }
            } else {
                None
            };

            let record = CommitRecord {
                tx_id,
                parent_tx_id: None,
                version: ConfigVersion::new(version),
                committed_at: Timestamp::now_utc(),
                principal: principal.clone(),
                source: CommitSource::LocalOperator,
                schema_digest: SchemaDigest::from_bytes([0u8; 32]),
                plaintext_digest: vec![],
                encrypted_blob,
                rollback_point: false,
                confirmed_deadline,
            };

            let mut audits = Vec::new();
            let mut prev_hash = [0u8; 32];
            let tenant = extract_tenant(&principal);
            for (i, path) in audit_paths.iter().enumerate() {
                let mut rec = AuditRecord {
                    tx_id,
                    sequence: i as u32,
                    yang_path: path.clone(),
                    op_type: AuditOpType::Create,
                    previous_value: None,
                    new_value: Some(r#""value""#.to_string()),
                    redaction_applied: false,
                    previous_hash: prev_hash,
                    entry_hmac: [0u8; 32],
                };
                rec.entry_hmac = rec.calculate_hmac(audit_key, &tenant);
                prev_hash = rec.entry_hmac;
                audits.push(rec);
            }

            ConfigStore::append_commit(store.as_ref(), record, audits)
                .await
                .map_err(|e| e.to_string())?;
            print_success(serde_json::Value::Null);
        }
        "MarkConfirmed" => {
            let tx_id_str = val["tx_id"].as_str().ok_or("missing tx_id")?;
            let tx_id = TxId::from_str(tx_id_str).map_err(|e| e.to_string())?;
            store
                .mark_confirmed(tx_id)
                .await
                .map_err(|e| e.to_string())?;
            print_success(serde_json::Value::Null);
        }
        "LoadLatest" => {
            let res = ConfigStore::load_latest(store.as_ref())
                .await
                .map_err(|e| e.to_string())?;
            print_success(res);
        }
        "LoadRollback" => {
            let tx_id_str = val["tx_id"].as_str().ok_or("missing tx_id")?;
            let tx_id = TxId::from_str(tx_id_str).map_err(|e| e.to_string())?;
            let res = ConfigStore::load_rollback(store.as_ref(), RollbackTarget::ByTxId(tx_id))
                .await
                .map_err(|e| e.to_string())?;
            print_success(res);
        }
        "AddNodeAsNonVoter" => {
            let peer_id = val["peer_id"]
                .as_u64()
                .or_else(|| val["peer_id_usize"].as_u64())
                .ok_or("missing peer_id")? as usize;
            store
                .add_node_as_non_voter(peer_id)
                .await
                .map_err(|e| e.to_string())?;
            print_success(serde_json::Value::Null);
        }
        "PromoteNode" => {
            let peer_id = val["peer_id"]
                .as_u64()
                .or_else(|| val["peer_id_usize"].as_u64())
                .ok_or("missing peer_id")? as usize;
            store
                .promote_node(peer_id)
                .await
                .map_err(|e| e.to_string())?;
            print_success(serde_json::Value::Null);
        }
        "RemoveNode" => {
            let peer_id = val["peer_id"]
                .as_u64()
                .or_else(|| val["peer_id_usize"].as_u64())
                .ok_or("missing peer_id")? as usize;
            store
                .remove_node(peer_id)
                .await
                .map_err(|e| e.to_string())?;
            print_success(serde_json::Value::Null);
        }
        "DumpMetrics" => {
            let res = store.dump_metrics().await.map_err(|e| e.to_string())?;
            print_success(res);
        }
        "Sync" => {
            store.sync().await.map_err(|e| e.to_string())?;
            print_success(serde_json::Value::Null);
        }
        "ForceStepDown" => {
            {
                let mut state = store.state.lock().await;
                state.role = Role::Follower;
                state.voted_for = None;
                state.leader_id = None;
                store
                    .inner
                    .consensus_set_state(state.current_term, None)
                    .await
                    .map_err(|e| e.to_string())?;
            }
            print_success(serde_json::Value::Null);
        }
        "ChangeMembershipRaw" => {
            let voting_members_val = val["voting_members"]
                .as_array()
                .ok_or("missing voting_members")?;
            let mut voting_members = Vec::new();
            for v in voting_members_val {
                voting_members.push(v.as_u64().ok_or("invalid voting member ID")? as usize);
            }
            let non_voting_members_val = val["non_voting_members"]
                .as_array()
                .ok_or("missing non_voting_members")?;
            let mut non_voting_members = Vec::new();
            for v in non_voting_members_val {
                non_voting_members.push(v.as_u64().ok_or("invalid non voting member ID")? as usize);
            }
            let epoch = val["epoch"].as_u64().ok_or("missing epoch")?;

            let active_membership = store
                .inner
                .consensus_get_active_membership()
                .await
                .unwrap()
                .unwrap();
            let membership = ClusterMembership {
                cluster_id: active_membership.cluster_id,
                node_id: store.node_id,
                voting_members,
                non_voting_members,
                old_voting_members: None,
                removed_members: vec![],
                epoch,
            };

            use opc_persist::ConsensusOp;
            let op = ConsensusOp::ChangeMembership { membership };
            store
                .replicate_and_commit(op)
                .await
                .map_err(|e| e.to_string())?;
            print_success(serde_json::Value::Null);
        }
        "SetSnapshot" => {
            let index = val["index"].as_u64().ok_or("missing index")?;
            let term = val["term"].as_u64().ok_or("missing term")?;
            let data_hex = val["data"].as_str().ok_or("missing data")?;
            let data = decode_hex(data_hex)?;
            store
                .inner
                .consensus_set_snapshot(index, term, &data)
                .await
                .map_err(|e| e.to_string())?;
            print_success(serde_json::Value::Null);
        }
        "CompactLogs" => {
            let index = val["index"].as_u64().ok_or("missing index")?;
            store
                .inner
                .consensus_compact_logs(index)
                .await
                .map_err(|e| e.to_string())?;
            print_success(serde_json::Value::Null);
        }
        "AppendLogsRaw" => {
            let index = val["index"].as_u64().ok_or("missing index")?;
            let term = val["term"].as_u64().ok_or("missing term")?;
            let tx_id_str = val["tx_id"].as_str().ok_or("missing tx_id")?;
            let tx_id = TxId::from_str(tx_id_str).map_err(|e| e.to_string())?;
            let version = val["version"].as_u64().ok_or("missing version")?;
            let principal = val["principal"]
                .as_str()
                .ok_or("missing principal")?
                .to_string();
            let encrypted_blob_hex = val["encrypted_blob"]
                .as_str()
                .ok_or("missing encrypted_blob")?;
            let encrypted_blob = decode_hex(encrypted_blob_hex)?;
            let audit_paths_val = val["audit_paths"]
                .as_array()
                .ok_or("missing or invalid audit_paths")?;
            let mut audit_paths = Vec::new();
            for path_v in audit_paths_val {
                audit_paths.push(
                    path_v
                        .as_str()
                        .ok_or("audit_paths must be string array")?
                        .to_string(),
                );
            }

            let record = CommitRecord {
                tx_id,
                parent_tx_id: None,
                version: ConfigVersion::new(version),
                committed_at: Timestamp::now_utc(),
                principal: principal.clone(),
                source: CommitSource::LocalOperator,
                schema_digest: SchemaDigest::from_bytes([0u8; 32]),
                plaintext_digest: vec![],
                encrypted_blob,
                rollback_point: false,
                confirmed_deadline: None,
            };

            let mut audits = Vec::new();
            let mut prev_hash = [0u8; 32];
            let tenant = extract_tenant(&principal);
            for (i, path) in audit_paths.iter().enumerate() {
                let mut rec = AuditRecord {
                    tx_id,
                    sequence: i as u32,
                    yang_path: path.clone(),
                    op_type: AuditOpType::Create,
                    previous_value: None,
                    new_value: Some(r#""value""#.to_string()),
                    redaction_applied: false,
                    previous_hash: prev_hash,
                    entry_hmac: [0u8; 32],
                };
                rec.entry_hmac = rec.calculate_hmac(audit_key, &tenant);
                prev_hash = rec.entry_hmac;
                audits.push(rec);
            }

            use opc_persist::{ConsensusOp, LogEntry};
            let op = ConsensusOp::AppendCommit {
                record,
                audit: audits,
            };
            let entry = LogEntry { index, term, op };

            store
                .inner
                .consensus_append_logs(index - 1, vec![entry])
                .await
                .map_err(|e| e.to_string())?;
            print_success(serde_json::Value::Null);
        }
        _ => return Err(format!("unknown command: {}", cmd)),
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut node_id = None;
    let mut db_path = None;
    let mut addr = None;
    let mut cluster_id = None;
    let mut audit_key_hex = None;
    let mut cert_chain_path = None;
    let mut private_key_path = None;
    let mut ca_cert_path = None;
    let mut voting_members = None;
    let mut peers = Vec::new();
    let mut election_timeout_min = 150;
    let mut election_timeout_max = 300;
    let mut rpc_timeout = 150;

    let args_vec: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args_vec.len() {
        let arg = &args_vec[i];
        let (name, val) = if arg.starts_with("--") && arg.contains('=') {
            let parts: Vec<&str> = arg.splitn(2, '=').collect();
            (parts[0].to_string(), Some(parts[1].to_string()))
        } else {
            (arg.clone(), None)
        };

        let get_value = |idx: &mut usize, val_opt: Option<String>, arg_list: &[String]| -> String {
            if let Some(v) = val_opt {
                v
            } else {
                *idx += 1;
                if *idx >= arg_list.len() {
                    panic!("missing value for argument {}", arg_list[*idx - 1]);
                }
                arg_list[*idx].clone()
            }
        };

        match name.as_str() {
            "--node-id" => {
                let v = get_value(&mut i, val, &args_vec);
                node_id = Some(v.parse::<usize>().expect("invalid node-id"));
            }
            "--db-path" => {
                db_path = Some(get_value(&mut i, val, &args_vec));
            }
            "--addr" => {
                addr = Some(get_value(&mut i, val, &args_vec));
            }
            "--cluster-id" => {
                cluster_id = Some(get_value(&mut i, val, &args_vec));
            }
            "--audit-key-hex" => {
                audit_key_hex = Some(get_value(&mut i, val, &args_vec));
            }
            "--cert-chain-path" => {
                cert_chain_path = Some(get_value(&mut i, val, &args_vec));
            }
            "--private-key-path" => {
                private_key_path = Some(get_value(&mut i, val, &args_vec));
            }
            "--ca-cert-path" => {
                ca_cert_path = Some(get_value(&mut i, val, &args_vec));
            }
            "--voting-members" => {
                let v = get_value(&mut i, val, &args_vec);
                let members: Vec<usize> = v
                    .split(',')
                    .map(|s| s.trim().parse::<usize>().expect("invalid voting member ID"))
                    .collect();
                voting_members = Some(members);
            }
            "--peer" => {
                let v = get_value(&mut i, val, &args_vec);
                let parts: Vec<&str> = v.splitn(2, '=').collect();
                if parts.len() != 2 {
                    panic!("invalid peer format, expected id=addr");
                }
                let peer_id = parts[0].parse::<usize>().expect("invalid peer id");
                let peer_addr = parts[1].to_string();
                peers.push((peer_id, peer_addr));
            }
            "--election-timeout-min" => {
                let v = get_value(&mut i, val, &args_vec);
                election_timeout_min = v.parse::<u64>().expect("invalid election-timeout-min");
            }
            "--election-timeout-max" => {
                let v = get_value(&mut i, val, &args_vec);
                election_timeout_max = v.parse::<u64>().expect("invalid election-timeout-max");
            }
            "--rpc-timeout" => {
                let v = get_value(&mut i, val, &args_vec);
                rpc_timeout = v.parse::<u64>().expect("invalid rpc-timeout");
            }
            _ => {
                panic!("unknown argument: {}", name);
            }
        }
        i += 1;
    }

    let node_id = node_id.expect("missing required --node-id");
    let db_path_str = db_path.expect("missing required --db-path");
    let addr = addr.expect("missing required --addr");
    let audit_key_hex = audit_key_hex.expect("missing required --audit-key-hex");

    let audit_key_bytes = decode_hex_32(&audit_key_hex).expect("invalid audit-key-hex");
    let audit_key = AuditKey::new(audit_key_bytes).expect("failed to create AuditKey");

    let sqlite_path = PathBuf::from(db_path_str);
    let backend = SqliteBackend::open_with_audit_key(&sqlite_path, true, 0, audit_key.clone())
        .await
        .expect("failed to open SQLite backend");
    let backend_arc = Arc::new(backend);

    let membership = ClusterMembership {
        cluster_id: cluster_id.unwrap_or_else(|| "default-cluster".to_string()),
        node_id,
        voting_members: voting_members.unwrap_or_else(|| vec![node_id]),
        non_voting_members: vec![],
        old_voting_members: None,
        removed_members: vec![],
        epoch: 1,
    };

    let clock = ConsensusClock {
        election_timeout_min: std::time::Duration::from_millis(election_timeout_min),
        election_timeout_max: std::time::Duration::from_millis(election_timeout_max),
        heartbeat_interval: std::time::Duration::from_millis(election_timeout_min / 3),
        enable_timers: true,
    };

    let store = ConsensusConfigStore::new(node_id, backend_arc, Some(membership), Some(clock))
        .await
        .expect("failed to create ConsensusConfigStore");
    let store = Arc::new(store);

    if let (Some(cert_chain_p), Some(private_key_p), Some(ca_cert_p)) =
        (&cert_chain_path, &private_key_path, &ca_cert_path)
    {
        let cert_chain_pem =
            std::fs::read_to_string(cert_chain_p).expect("failed to read cert chain");
        let private_key_pem =
            std::fs::read_to_string(private_key_p).expect("failed to read private key");
        let ca_cert_pem = std::fs::read_to_string(ca_cert_p).expect("failed to read CA cert");
        let identity = NodeIdentity {
            cert_chain_pem,
            private_key_pem,
            ca_cert_pem,
        };
        store
            .set_identity(identity)
            .await
            .expect("failed to set identity");
    }

    let server = TcpRpcServer::new(store.clone(), addr.clone());
    let _server_handle = server.start().await.expect("failed to start RPC server");

    for (peer_id, peer_addr) in peers {
        let peer = TcpPeer::new(
            peer_id,
            peer_addr,
            std::time::Duration::from_millis(rpc_timeout),
        );
        store.add_peer(peer_id, Arc::new(peer)).await;
    }

    let (tx, mut rx) = tokio::sync::mpsc::channel(100);
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lines() {
            if let Ok(l) = line {
                if tx.blocking_send(l).is_err() {
                    break;
                }
            } else {
                break;
            }
        }
    });

    while let Some(line) = rx.recv().await {
        if let Err(e) = handle_command_line(&line, &store, &audit_key).await {
            print_error(&e);
        }
    }

    server.shutdown().await;
    Ok(())
}
