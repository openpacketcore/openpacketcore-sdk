//! Native three-voter store reached through the actual RFC026 TLS endpoint.
use super::*;
use crate::scope::*;
use futures_util::FutureExt;
use opc_session_store::{scope_authority::*, scope_scheduler::ScopeSchedulerOwner};
use std::collections::HashMap;

#[path = "scope_transport/batch.rs"]
mod batch;
#[path = "scope_transport/cross_slot.rs"]
mod cross_slot;

struct ScopeClock;
impl AuthenticationClock for ScopeClock {
    fn interval(&self) -> Result<opc_tls::AuthenticationTimeInterval, AuthenticationTimeError> {
        let now = opc_types::Timestamp::from_offset_datetime(time::OffsetDateTime::now_utc());
        opc_tls::AuthenticationTimeInterval::new(now, now).map_err(|_| AuthenticationTimeError)
    }
}
#[derive(Default)]
struct SwitchClock(std::sync::atomic::AtomicBool);
impl AuthenticationClock for SwitchClock {
    fn interval(&self) -> Result<opc_tls::AuthenticationTimeInterval, AuthenticationTimeError> {
        if self.0.load(Ordering::Acquire) {
            Err(AuthenticationTimeError)
        } else {
            ScopeClock.interval()
        }
    }
}
struct Boots(
    std::sync::Mutex<BootAuthorityRecord>,
    std::sync::Mutex<Option<BootAuthorityRecord>>,
);
#[async_trait]
impl ScopeBootAuthority for Boots {
    async fn read_current(
        &self,
        _scope: &ScopeBinding,
    ) -> Result<BootAuthorityRecord, ScopeEvidenceError> {
        let observed = self.0.lock().unwrap().clone();
        if let Some(next) = self.1.lock().unwrap().take() {
            *self.0.lock().unwrap() = next;
        }
        Ok(observed)
    }
    async fn read_known(
        &self,
        _scope: &ScopeBinding,
        _key: [u8; 32],
    ) -> Result<BootAuthorityRecord, ScopeEvidenceError> {
        Ok(self.0.lock().unwrap().clone())
    }
}
#[derive(Default)]
struct Closures {
    local: std::sync::Mutex<HashMap<[u8; 32], LocalClosureRecord>>,
    final_records: std::sync::Mutex<HashMap<[u8; 32], FinalTerminationRecord>>,
    hold_publication: std::sync::atomic::AtomicBool,
}
#[async_trait]
impl ScopeLocalClosurePublisher for Closures {
    async fn publish(&self, evidence: &LocalClosurePublication) -> Result<(), ScopeEvidenceError> {
        self.local
            .lock()
            .unwrap()
            .insert(evidence.record().digest()?, evidence.record().clone());
        if self.hold_publication.load(Ordering::Acquire) {
            std::future::pending::<()>().await;
        }
        Ok(())
    }
}
#[async_trait]
impl ScopeClosureSource for Closures {
    async fn read_final(
        &self,
        _: &ScopeAuthorityStamp,
        digest: [u8; 32],
    ) -> Result<FinalTerminationRecord, ScopeEvidenceError> {
        self.final_records
            .lock()
            .unwrap()
            .get(&digest)
            .cloned()
            .ok_or(ScopeEvidenceError::Unavailable)
    }
    async fn read_local(
        &self,
        _: &ScopeAuthorityStamp,
        digest: [u8; 32],
    ) -> Result<LocalClosureRecord, ScopeEvidenceError> {
        self.local
            .lock()
            .unwrap()
            .get(&digest)
            .cloned()
            .ok_or(ScopeEvidenceError::Unavailable)
    }
}
fn client_tls(
    pki: &TestPki,
    worker: &str,
    server_instance: &str,
) -> opc_tls::AuthenticatedClientConfig {
    let (_tx, rx) = tokio::sync::watch::channel(Some(pki.identity_state(worker)));
    TlsConfigBuilder::new(rx)
        .with_policy(opc_tls::PeerPolicy {
            allowed_instances: Some(std::collections::HashSet::from([
                opc_types::InstanceId::new(server_instance).unwrap(),
            ])),
            ..Default::default()
        })
        .build_authenticated_client_config()
        .unwrap()
}
fn server_tls(
    pki: &TestPki,
    server: &str,
    worker_instance: &str,
) -> opc_tls::AuthenticatedServerConfig {
    rotating_server_tls(pki, server, worker_instance).0
}
fn rotating_server_tls(
    pki: &TestPki,
    server: &str,
    worker_instance: &str,
) -> (
    opc_tls::AuthenticatedServerConfig,
    tokio::sync::watch::Sender<Option<opc_identity::IdentityState>>,
) {
    let (source, rx) = tokio::sync::watch::channel(Some(pki.identity_state(server)));
    let config = TlsConfigBuilder::new(rx)
        .with_policy(opc_tls::PeerPolicy {
            allowed_instances: Some(std::collections::HashSet::from([
                opc_types::InstanceId::new(worker_instance).unwrap(),
                opc_types::InstanceId::new("scope-controller").unwrap(),
                opc_types::InstanceId::new("scope-observer").unwrap(),
            ])),
            ..Default::default()
        })
        .build_authenticated_server_config()
        .unwrap();
    (config, source)
}

#[test]
fn native_scope_tls_admission_receipt_after_ticket_change_and_irreversible_close() {
    run_native(false, "stateless_quorum_consumer::scope_transport::native_scope_tls_admission_receipt_after_ticket_change_and_irreversible_close");
}
#[test]
fn native_scope_tls_boot_binding_survives_snapshot_leader_loss_and_full_reopen() {
    run_native(true, "stateless_quorum_consumer::scope_transport::native_scope_tls_boot_binding_survives_snapshot_leader_loss_and_full_reopen");
}
fn run_native(durable_recovery: bool, name: &str) {
    if std::env::var_os("OPC_SCOPE_NATIVE_TLS_TEST_CHILD").is_none() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("OPC_SCOPE_NATIVE_TLS_TEST_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }
    tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap().block_on(async {
        let pki=Arc::new(TestPki::new());
        let mut fleet_slot=Some(ThreeVoterConsumerFleet::start_fixed_durable_classified(pki.clone()).await);
        let result=std::panic::AssertUnwindSafe(async {
            let fleet=fleet_slot.as_mut().unwrap();
            let (leader,_,_)=fleet.wait_for_observed_leader().await;
            fleet.stores[leader].activate_scope_profile().await.unwrap();
            let follower=(leader+1)%3;
            let scope=ScopeId::new(fleet.manifest.fixed_durable_quorum_consensus_identity(),TenantId::new("test").unwrap(),NetworkFunctionKind::new("scope").unwrap(),[0x55;32]).unwrap();
            let binding=ScopeBinding::from_scope(&scope).unwrap();
            let local=tempfile::tempdir().unwrap();
            let process=Arc::new(ScopeProcess::new(binding.clone(),[3;16],BootIdentity::generate().unwrap(),std::fs::File::open(local.path()).unwrap()).unwrap());
            let worker=spiffe("scope-worker");let worker_id=opc_types::SpiffeId::new(worker.clone()).unwrap();
            let execution=ScopeExecution::new(SessionConsumerIdentity::new(worker.clone()).unwrap(),127,[3;16],*process.boot().process_nonce(),process.boot().key_digest()).unwrap();
            let record=BootAuthorityRecord::new(binding.clone(),execution.clone(),*process.boot().public_key(),b"authority-uid".to_vec(),b"rv:127".to_vec()).unwrap();
            let ticket=BootTicket::from_authority_record(&process,&record).unwrap();
            let boots=Arc::new(Boots(std::sync::Mutex::new(record),std::sync::Mutex::new(None)));
            let closures=Arc::new(Closures::default());
            let server_scheduler=ScopeSchedulerOwner::default();let client_scheduler=ScopeSchedulerOwner::default();
            let grants=vec![PrincipalGrant::new(worker_id,ScopeRole::Worker,vec![binding.clone()]).unwrap(),
                PrincipalGrant::new(opc_types::SpiffeId::new(spiffe("scope-controller")).unwrap(),ScopeRole::Controller,vec![binding.clone()]).unwrap(),
                PrincipalGrant::new(opc_types::SpiffeId::new(spiffe("scope-observer")).unwrap(),ScopeRole::Observer,vec![binding.clone()]).unwrap(),
            ];
            let policy=ScopePolicy::new(grants.clone()).unwrap();
            let (server_material,server_updates)=rotating_server_tls(&pki,&three_voter_spiffe(follower),"scope-worker");
            let server_clock=Arc::new(SwitchClock::default());
            let server=Arc::new(ScopeServer::new(ScopeServerConfig{tls:server_material,clock:server_clock.clone(),policy:policy.clone(),store:Arc::new(fleet.stores[follower].clone()),scopes:vec![scope.clone()],boots:boots.clone(),closures:closures.clone(),scheduler:server_scheduler.scheduler(),proofs:ProofBudgets::default()}).unwrap());
            let handle=server.clone().serve([SocketAddr::from(([127,0,0,1],0));5]).await.unwrap();
            let tls=client_tls(&pki,&worker,&follower.to_string());
            let clock=Arc::new(SwitchClock::default());
            let client=ScopeClient::new(ScopeClientConfig{process:process.clone(),scope:scope.clone(),ticket,tls:tls.clone(),server:opc_types::SpiffeId::new(three_voter_spiffe(follower)).unwrap(),addresses:handle.addresses(),clock:clock.clone(),scheduler:client_scheduler.scheduler(),local_closure:closures.clone()}).unwrap();
            assert!(process.enter_peer_control().await.is_err());
            let request=Arc::new(client.prepare_initial().await.unwrap());
            let original=request.request().encode_canonical().unwrap();
            let issuance=boots.0.lock().unwrap().clone();
            let replacement=ScopeExecution::new(execution.identity().clone(),128,[3;16],[9;16],*execution.boot_key()).unwrap();
            *boots.1.lock().unwrap()=Some(BootAuthorityRecord::new(binding.clone(),replacement,*process.boot().public_key(),b"authority-uid".to_vec(),b"rv:128".to_vec()).unwrap());
            assert!(matches!(client.submit(&request,Duration::from_secs(5)).await,Err(ScopeRpcError::Unauthorized)),"issuance changes after initial verification must be rechecked before proposing");
            *boots.0.lock().unwrap()=issuance;
            assert!(client.current(Duration::from_secs(5)).await.unwrap().stamp().is_none());
            if !durable_recovery {
                // Exercise the actual five-second server idle limit, as an
                // interoperability regression rather than a latency requirement.
                tokio::time::sleep(Duration::from_secs(6)).await;
                let idle=client.current(Duration::from_secs(5)).await.map(|_|());
                client.current(Duration::from_secs(5)).await.unwrap();
                server_updates.send_replace(Some(pki.identity_state(&three_voter_spiffe(follower))));
                let rotated=client.current(Duration::from_secs(5)).await.map(|_|());
                client.current(Duration::from_secs(5)).await.unwrap();
                server_clock.0.store(true,Ordering::Release);
                let unavailable=client.current(Duration::from_secs(5)).await.map(|_|());
                server_clock.0.store(false,Ordering::Release);
                assert_eq!((idle,rotated,unavailable),(Ok(()),Ok(()),Err(ScopeRpcError::AuthTimeUnavailable)),
                    "idle close and rotation reconnect before proof; server clock refusal is typed and never uncertain");
            }
            let known=boots.0.lock().unwrap().clone();
            for mismatched in crate::scope::attack_test_support::mismatched_retained_records(&known) {
                *boots.0.lock().unwrap()=mismatched;
                assert_eq!(client.current(Duration::from_secs(5)).await.err(),Some(ScopeRpcError::Unauthorized),
                    "a valid possession proof cannot use a retained record with another scope, key or execution digest");
            }
            *boots.0.lock().unwrap()=known;
            assert!(client.current(Duration::from_secs(5)).await.unwrap().stamp().is_none());
            assert!(process.enter_peer_control().await.is_err());
            let occupied=server_scheduler.scheduler().reserve(opc_session_store::scope_scheduler::ScopeSchedulerKey::from_bytes([99;32]),opc_session_store::scope_scheduler::ScopeWorkClass::SafetyControl).await.unwrap().start().await.unwrap();
            let submitted=client.clone();let pending=request.clone();
            let routed=tokio::spawn(async move { submitted.submit(&pending,Duration::from_secs(5)).await });
            tokio::time::timeout(Duration::from_secs(2),async {
                while server_scheduler.scheduler().snapshot().class(opc_session_store::scope_scheduler::ScopeWorkClass::SafetyControl).start_waiting == 0 { tokio::task::yield_now().await; }
            }).await.unwrap();
            policy.replace(Vec::new()).unwrap();
            drop(occupied);
            assert!(matches!(routed.await.unwrap(),Err(ScopeRpcError::OutcomeUnknown)),"revoked proof cannot dispatch after waiting for capacity");
            policy.replace(grants.clone()).unwrap();
            assert!(client.current(Duration::from_secs(5)).await.unwrap().stamp().is_none());
            assert!(process.enter_peer_control().await.is_err());
            server.lose_next_committed_reply_for_test();
            assert!(matches!(client.submit(&request,Duration::from_secs(5)).await,Err(ScopeRpcError::OutcomeUnknown)));
            assert!(process.enter_peer_control().await.is_err(),"a lost response cannot activate local effects");
            let retained=client_scheduler.scheduler().snapshot().class(opc_session_store::scope_scheduler::ScopeWorkClass::SafetyControl);
            assert_eq!((retained.resident,retained.running),(1,0),"uncertainty retains one resident credit and releases the attempt");
            let observed=client.outcome(&request,Duration::from_secs(5)).await.unwrap();
            assert_eq!(observed.execution(),&execution);
            assert!(process.enter_peer_control().await.is_err(),"an outcome read is not capability delivery");
            assert_eq!(client_scheduler.scheduler().snapshot().class(opc_session_store::scope_scheduler::ScopeWorkClass::SafetyControl).resident,0,"an exact committed lookup releases the resolved resident entitlement");
            for kind in 1..=5 {
                server.corrupt_next_committed_reply_for_test(kind);
                assert!(matches!(client.submit(&request,Duration::from_secs(5)).await,Err(ScopeRpcError::OutcomeUnknown)),"a mismatched post-commit response is uncertain, never proven no-effect (case {kind})");
                assert!(process.enter_peer_control().await.is_err());
            }
            let authority=match client.submit(&request,Duration::from_secs(5)).await.unwrap(){ScopeAuthorityReply::Admitted(value)=>value,_=>panic!("own initial capability")};
            assert_eq!(authority.stamp().execution(),&execution);
            let duplicate=client.prepare_initial().await.unwrap();
            assert!(matches!(client.submit(&duplicate,Duration::from_secs(5)).await,Err(ScopeRpcError::Invalid)),"a different request ID from the current boot is invalid, not evidence that the boot was superseded");
            assert_eq!(client.current(Duration::from_secs(5)).await.unwrap().stamp(),Some(authority.stamp()));
            drop(process.enter_peer_control().await.unwrap());
            drop(duplicate);
            let forged_execution=ScopeExecution::new(execution.identity().clone(),500,[3;16],*process.boot().process_nonce(),process.boot().key_digest()).unwrap();
            let forged_record=BootAuthorityRecord::new(ScopeBinding::from_scope(&scope).unwrap(),forged_execution,*process.boot().public_key(),b"forged-uid".to_vec(),b"rv:500".to_vec()).unwrap();
            let forged=ScopeClient::new(ScopeClientConfig{process:process.clone(),scope:scope.clone(),ticket:BootTicket::from_authority_record(&process,&forged_record).unwrap(),tls:tls.clone(),server:opc_types::SpiffeId::new(three_voter_spiffe(follower)).unwrap(),addresses:handle.addresses(),clock:Arc::new(ScopeClock),scheduler:client_scheduler.scheduler(),local_closure:closures.clone()}).unwrap();
            let fabricated=forged.prepare_initial().await.unwrap();
            assert!(matches!(forged.submit(&fabricated,Duration::from_secs(5)).await,Err(ScopeRpcError::Unauthorized)),"a signed high generation and copied ticket hints cannot replace independently current issuance");
            assert_eq!(client.current(Duration::from_secs(5)).await.unwrap().stamp(),Some(authority.stamp()));
            drop(fabricated);drop(forged);
            crate::scope::attack_test_support::replay_between_connections(&tls,handle.addresses()[0],&scope,&process,&execution,&ScopeClock).await;
            assert_eq!(client.current(Duration::from_secs(5)).await.unwrap().stamp(),Some(authority.stamp()));
            let read_scheduler=ScopeSchedulerOwner::default();
            for role in ["scope-controller","scope-observer"] {
                crate::scope::attack_test_support::controller_cannot_submit_worker_mutation(&client_tls(&pki,&spiffe(role),&follower.to_string()),handle.addresses()[0],&scope,request.request()).await;
                let reader=ScopeReadClient::new(ScopeReadClientConfig{scope:scope.clone(),tls:client_tls(&pki,&spiffe(role),&follower.to_string()),server:opc_types::SpiffeId::new(three_voter_spiffe(follower)).unwrap(),addresses:handle.addresses(),clock:Arc::new(ScopeClock),scheduler:read_scheduler.scheduler()}).unwrap();
                assert_eq!(reader.current(Duration::from_secs(2)).await.unwrap().stamp(),Some(authority.stamp()));
                let receipt=reader.outcome(*request.request().request_id(),request.request().digest().unwrap(),Duration::from_secs(2)).await.unwrap();
                assert_eq!(receipt.stamp(),authority.stamp());assert!(receipt.is_active());
            }
            drop(process.enter_peer_control().await.unwrap());
            let view=client.current(Duration::from_secs(5)).await.unwrap();assert_eq!(view.stamp(),Some(authority.stamp()));
            let future=ScopeExecution::new(execution.identity().clone(),128,[3;16],[9;16],*execution.boot_key()).unwrap();
            *boots.0.lock().unwrap()=BootAuthorityRecord::new(binding,future,*process.boot().public_key(),b"authority-uid".to_vec(),b"rv:128".to_vec()).unwrap();
            assert_eq!(client.outcome(&request,Duration::from_secs(5)).await.unwrap(),*authority.stamp());
            let replay=match client.submit(&request,Duration::from_secs(5)).await.unwrap(){ScopeAuthorityReply::Admitted(value)=>value,_=>panic!("exact retry must recover its own capability")};
            assert_eq!(replay.stamp(),authority.stamp());
            let pause=server.pause_next_committed_reply_for_test();
            let submitted=client.clone();let pending=request.clone();
            let observer=tokio::spawn(async move{submitted.submit(&pending,Duration::from_secs(5)).await});
            tokio::time::timeout(Duration::from_secs(2),pause.entered()).await.unwrap();
            observer.abort();let _=observer.await;
            let active=client_scheduler.scheduler().snapshot().class(opc_session_store::scope_scheduler::ScopeWorkClass::SafetyControl);
            assert_eq!((active.resident,active.running),(1,1),"cancelling the observer cannot release the still-running native attempt");
            pause.release();
            assert!(matches!(client.submit(&request,Duration::from_secs(5)).await.unwrap(),ScopeAuthorityReply::Admitted(_)));
            assert_eq!(client_scheduler.scheduler().snapshot().class(opc_session_store::scope_scheduler::ScopeWorkClass::SafetyControl).resident,0);
            let mut siblings=Vec::new();
            for tag in 20..22 {
                siblings.push(crate::scope::protocol_test_support::pending_proof(tls.clone(),handle.addresses()[0],&scope,None,tag).await);
                siblings.push(crate::scope::protocol_test_support::pending_proof(tls.clone(),handle.addresses()[0],&scope,Some(request.request()),tag+2).await);
            }
            assert!(tokio::time::timeout(Duration::from_millis(100),crate::scope::protocol_test_support::pending_proof(tls.clone(),handle.addresses()[0],&scope,None,25)).await.is_err(),"same-SVID unproven capacity is exhausted");
            assert!(matches!(client.submit(&request,Duration::from_secs(1)).await.unwrap(),ScopeAuthorityReply::Admitted(_)),"a proven current connection does not rejoin the saturated candidate share for exact recovery");
            assert_eq!(client.current(Duration::from_secs(1)).await.unwrap().stamp(),Some(authority.stamp()),"only the proven connection retains current-worker SafetyControl capacity");
            drop(siblings);
            assert_eq!(request.request().encode_canonical().unwrap(),original);
            clock.0.store(true,Ordering::Release);
            assert!(matches!(client.current(Duration::from_secs(1)).await,Err(ScopeRpcError::AuthTimeUnavailable)));
            drop(process.enter_peer_control().await.unwrap());
            clock.0.store(false,Ordering::Release);
            assert_eq!(client.current(Duration::from_secs(2)).await.unwrap().stamp(),Some(authority.stamp()),"authentication time cannot change untimed ownership");
            client_scheduler.quiesce();
            server_scheduler.quiesce();
            assert!(client_scheduler.scheduler().reserve(opc_session_store::scope_scheduler::ScopeSchedulerKey::from_bytes([11;32]),opc_session_store::scope_scheduler::ScopeWorkClass::Normal).await.is_err());
            closures.hold_publication.store(true,Ordering::Release);
            let publication=tokio::time::timeout(Duration::from_secs(6),client.prepare_close(&authority)).await;
            assert!(matches!(publication,Ok(Err(ScopeRpcError::Retry))),"publication has a bounded attempt and leaves the irreversible gate closed");
            assert!(process.enter_peer_control().await.is_err());
            let retained_fence=*closures.local.lock().unwrap().keys().next().unwrap();
            closures.hold_publication.store(false,Ordering::Release);
            let close=client.prepare_close(&authority).await.unwrap();
            match close.request().operation() { ScopeAuthorityOperation::Close{evidence,..}=>assert_eq!(evidence.digest(),&retained_fence), _=>panic!("typed Close") }
            assert_eq!(closures.local.lock().unwrap().len(),1,"publication retries retain the exact fence");
            assert!(process.enter_peer_control().await.is_err());
            let response=client.submit(&close,Duration::from_secs(5)).await;
            let response=if matches!(response,Err(ScopeRpcError::OutcomeUnknown)|Err(ScopeRpcError::Retry)) { client.submit(&close,Duration::from_secs(5)).await } else { response };
            let closed=match response.unwrap(){ScopeAuthorityReply::Closed(value)=>value,_=>panic!("Close is not a capability")};
            assert_eq!(closed.revision(),authority.stamp().revision()+1);
            let view=client.current(Duration::from_secs(5)).await.unwrap();assert!(!view.is_active());assert_eq!(view.stamp(),Some(closed.as_ref()));
            assert!(process.enter_peer_control().await.is_err());
            assert_eq!(client.outcome(&request,Duration::from_secs(5)).await,Err(ScopeRpcError::ReceiptUnavailable));
            let closed_evidence=view.closed_evidence().unwrap();
            drop(request);drop(close);drop(client);drop(process);
            let binding=ScopeBinding::from_scope(&scope).unwrap();
            let next_process=Arc::new(ScopeProcess::new(binding.clone(),[3;16],BootIdentity::generate().unwrap(),std::fs::File::open(local.path()).unwrap()).unwrap());
            let next_execution=ScopeExecution::new(execution.identity().clone(),129,[3;16],*next_process.boot().process_nonce(),next_process.boot().key_digest()).unwrap();
            let record=BootAuthorityRecord::new(binding.clone(),next_execution,*next_process.boot().public_key(),b"authority-uid".to_vec(),b"rv:129".to_vec()).unwrap();
            let ticket=BootTicket::from_authority_record(&next_process,&record).unwrap();*boots.0.lock().unwrap()=record;
            let next=ScopeClient::new(ScopeClientConfig{process:next_process.clone(),scope:scope.clone(),ticket,tls:tls.clone(),server:opc_types::SpiffeId::new(three_voter_spiffe(follower)).unwrap(),addresses:handle.addresses(),clock:Arc::new(ScopeClock),scheduler:client_scheduler.scheduler(),local_closure:closures.clone()}).unwrap();
            let pending=next.prepare_successor(&closed,closed_evidence).await.unwrap();
            let uncertain_request=pending.request().clone();
            server.lose_next_committed_reply_for_test();
            assert!(matches!(next.submit(&pending,Duration::from_secs(5)).await,Err(ScopeRpcError::OutcomeUnknown)));
            assert!(next_process.enter_peer_control().await.is_err());
            drop(pending);drop(next);drop(next_process);
            let final_process=Arc::new(ScopeProcess::new(binding.clone(),[3;16],BootIdentity::generate().unwrap(),std::fs::File::open(local.path()).unwrap()).unwrap());
            let final_execution=ScopeExecution::new(execution.identity().clone(),130,[3;16],*final_process.boot().process_nonce(),final_process.boot().key_digest()).unwrap();
            let record=BootAuthorityRecord::new(binding,final_execution,*final_process.boot().public_key(),b"authority-uid".to_vec(),b"rv:130".to_vec()).unwrap();
            let ticket=BootTicket::from_authority_record(&final_process,&record).unwrap();*boots.0.lock().unwrap()=record;
            let final_client=ScopeClient::new(ScopeClientConfig{process:final_process.clone(),scope:scope.clone(),ticket,tls,server:opc_types::SpiffeId::new(three_voter_spiffe(follower)).unwrap(),addresses:handle.addresses(),clock:Arc::new(ScopeClock),scheduler:client_scheduler.scheduler(),local_closure:closures.clone()}).unwrap();
            let resolved=final_client.lookup_outcome(&uncertain_request,Duration::from_secs(5)).await.unwrap();
            assert_eq!(resolved.stamp().execution(),uncertain_request.operation().execution());
            assert_ne!(resolved.stamp(),closed.as_ref(),"B2 must close the B1 that actually committed");
            assert!(final_process.enter_peer_control().await.is_err(),"predecessor resolution is read-only");
            let termination=FinalTerminationRecord::new(resolved.stamp().clone(),"test".into(),"worker".into(),[3;16],"worker".into(),"containerd://boot-129".into(),0,0,"Completed".into(),"".into(),"2026-01-01T00:00:00Z".into(),"2026-01-01T00:01:00Z".into(),b"termination-129".to_vec(),b"rv:129-closed".to_vec()).unwrap();
            let digest=termination.digest().unwrap();
            let wrong=FinalTerminationRecord::new((*closed).clone(),"test".into(),"worker".into(),[3;16],"worker".into(),"containerd://boot-127".into(),0,0,"Completed".into(),"".into(),"2026-01-01T00:00:00Z".into(),"2026-01-01T00:01:00Z".into(),b"termination-wrong".to_vec(),b"rv:wrong".to_vec()).unwrap();
            closures.final_records.lock().unwrap().insert(digest,wrong);
            let request=final_client.prepare_successor(resolved.stamp(),ScopeClosureEvidence::new(ScopeClosureKind::FinalTermination,digest).unwrap()).await.unwrap();
            assert!(matches!(final_client.submit(&request,Duration::from_secs(5)).await,Err(ScopeRpcError::Invalid)),"the independently retained evidence must name the exact committed predecessor");
            assert!(final_process.enter_peer_control().await.is_err());
            assert_eq!(final_client.current(Duration::from_secs(5)).await.unwrap().stamp(),Some(resolved.stamp()));
            closures.final_records.lock().unwrap().insert(digest,termination);
            let last=match final_client.submit(&request,Duration::from_secs(5)).await.unwrap(){ScopeAuthorityReply::Admitted(value)=>value,_=>panic!("final successor capability")};
            assert_eq!(last.closed_predecessor(),Some(resolved.stamp()));
            drop(final_process.enter_peer_control().await.unwrap());
            assert!(matches!(final_client.lookup_outcome(&uncertain_request,Duration::from_secs(5)).await,Err(ScopeRpcError::ReceiptUnavailable)));
            let addresses=handle.addresses();
            handle.shutdown().await;
            drop(server);
            if durable_recovery {
                let (leader,_,_)=fleet.wait_for_observed_leader().await;
                let protected_index=fleet.stores[leader].status().last_log_index.unwrap();
                advance_protected_roster_process_loss_snapshot_workload(fleet,leader,0,PROTECTED_ROSTER_PROCESS_LOSS_SNAPSHOT_COMMANDS,PROTECTED_ROSTER_PROCESS_LOSS_SNAPSHOT_BOUND,"scope authority").await;
                wait_for_protected_roster_snapshot_coverage(fleet,protected_index,"scope boot binding").await;
                let (leader,leader_id,term)=fleet.wait_for_observed_leader().await;
                let survivor=(0..3).find(|index|*index!=leader).unwrap();
                // The authenticated scope endpoint is a facade over a native
                // follower; its stable service identity survives voter failover.
                let endpoint=Arc::new(ScopeServer::new(ScopeServerConfig{tls:server_tls(&pki,&three_voter_spiffe(follower),"scope-worker"),clock:Arc::new(ScopeClock),policy:policy.clone(),store:Arc::new(fleet.stores[survivor].clone()),scopes:vec![scope.clone()],boots:boots.clone(),closures:closures.clone(),scheduler:server_scheduler.scheduler(),proofs:ProofBudgets::default()}).unwrap());
                let listener=endpoint.clone().serve(addresses).await.unwrap();
                fleet.isolate(leader).await;
                fleet.wait_for_new_leader(leader,leader_id,term,tokio::time::Instant::now()+THREE_VOTER_READY_TIMEOUT).await;
                let after_loss=reconnect_current(&final_client).await;
                assert_eq!(after_loss.stamp(),Some(last.stamp()));
                listener.shutdown().await;drop(endpoint);
                let old=fleet_slot.take().unwrap();
                fleet_slot=Some(old.restart_all().await);
                let fleet=fleet_slot.as_mut().unwrap();
                let (leader,_,_)=fleet.wait_for_admitted_quorum_leader(&[0,1,2],0).await;
                let survivor=(leader+1)%3;
                let endpoint=Arc::new(ScopeServer::new(ScopeServerConfig{tls:server_tls(&pki,&three_voter_spiffe(follower),"scope-worker"),clock:Arc::new(ScopeClock),policy:policy.clone(),store:Arc::new(fleet.stores[survivor].clone()),scopes:vec![scope.clone()],boots:boots.clone(),closures:closures.clone(),scheduler:server_scheduler.scheduler(),proofs:ProofBudgets::default()}).unwrap());
                let listener=endpoint.clone().serve(addresses).await.unwrap();
                let restored=reconnect_current(&final_client).await;
                assert_eq!(restored,after_loss,"snapshot/reopen retains the exact nonce, public-key commitment, revision and generation floor");
                assert_eq!(restored.admission_generation_floor(),130);
                let retry=final_client.submit(&request,Duration::from_secs(5)).await.unwrap();
                assert!(matches!(retry,ScopeAuthorityReply::Admitted(ref recovered) if recovered.stamp()==last.stamp() && recovered.closed_predecessor()==last.closed_predecessor()));
                assert!(matches!(final_client.lookup_outcome(&uncertain_request,Duration::from_secs(5)).await,Err(ScopeRpcError::ReceiptUnavailable)));
                listener.shutdown().await;drop(endpoint);
            }
        }).catch_unwind().await;
        if let Some(fleet)=fleet_slot.as_mut() { fleet.quiesce().await; }
        result.unwrap_or_else(|panic|std::panic::resume_unwind(panic));
    });
}

async fn reconnect_current(client: &ScopeClient) -> ScopeAuthorityView {
    for _ in 0..3 {
        match client.current(Duration::from_secs(5)).await {
            Ok(view) => return view,
            Err(ScopeRpcError::OutcomeUnknown | ScopeRpcError::Retry) => {}
            Err(error) => panic!("unexpected reconnect refusal: {error:?}"),
        }
    }
    panic!("scope reconnect did not recover within three bounded attempts")
}
