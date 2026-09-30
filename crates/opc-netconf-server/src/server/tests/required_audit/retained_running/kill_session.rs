//! A peer's acknowledged kill fences admission without waiting for the victim
//! runner to be scheduled. Accepted originals remain owned by the real worker.

use super::*;
use opc_crypto::ConfigCapacityProfile;
use opc_persist::RetainedConfigProfile;
use std::{
    future::Future,
    task::{Poll, Waker},
};

#[derive(Default)]
struct RunnerGate {
    paused: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl RunnerGate {
    fn pause(&self) {
        self.paused.store(true, Ordering::Release);
    }

    fn resume(&self) {
        self.paused.store(false, Ordering::Release);
        if let Some(waker) = self.waker.lock().unwrap().take() {
            waker.wake();
        }
    }
}

async fn victim(
    server: Arc<NativeServer>,
    sessions: SessionRegistry,
    id: u64,
) -> (Client, Arc<RunnerGate>) {
    let gate = Arc::new(RunnerGate::default());
    let task_gate = gate.clone();
    let (mut stream, client) = tokio::io::duplex(8192);
    let runner = tokio::spawn(async move {
        let principal = principal();
        let mut running = Box::pin(crate::session::run_read_only_session_with_registry(
            &server,
            &principal,
            &mut stream,
            SessionConfig::default(),
            id,
            &sessions,
        ));
        std::future::poll_fn(|cx| {
            if task_gate.paused.load(Ordering::Acquire) {
                let mut waker = task_gate.waker.lock().unwrap();
                if task_gate.paused.load(Ordering::Acquire) {
                    *waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
            }
            running.as_mut().poll(cx)
        })
        .await
    });
    let mut client = Client {
        stream: client,
        runner,
    };
    assert!(client.reply().await.contains(":writable-running"));
    client.send(&format!(r#"<hello xmlns="{NETCONF_BASE_NS}"><capabilities><capability>{NETCONF_BASE_1_0}</capability></capabilities></hello>"#)).await;
    (client, gate)
}

async fn joined(mut client: Client) -> bool {
    match tokio::time::timeout(WAIT, &mut client.runner).await {
        Ok(Ok(Ok(_))) => true,
        Ok(_) => false,
        Err(_) => {
            client.runner.abort();
            let _ = client.runner.await;
            false
        }
    }
}

fn profiles() -> [(RetainedConfigProfile, ConfigCapacityProfile); 2] {
    [
        (
            RetainedConfigProfile::NetconfRunningV1,
            ConfigCapacityProfile::BoundedV1,
        ),
        (
            RetainedConfigProfile::NetconfTargetsV1,
            ConfigCapacityProfile::Legacy,
        ),
    ]
}

#[tokio::test]
async fn retained_running_kill_before_intent_revokes_before_acknowledgement() {
    for (profile, capacity) in profiles() {
        let f = Fixture::with_profiles(profile, capacity).await;
        let server = f.server(policy_allow_system_with_secret_writes()).unwrap();
        let sessions = SessionRegistry::new();
        let (mut target, runner_gate) = victim(server.clone(), sessions.clone(), 91).await;
        let mut killer = Client::start(server.clone(), sessions, 92).await;
        let release = f.provider.encrypt_gate.arm();
        target.send(&edit("fixture-killed", false, "replace")).await;
        let reached = tokio::time::timeout(WAIT, f.provider.encrypt_gate.entered())
            .await
            .is_ok();
        runner_gate.pause();
        let before = no_running_intent(&f).await;
        let killed = killer.rpc(&kill_session_rpc(91)).await;
        // Resume the real provider immediately after acknowledgement while the
        // victim runner cannot poll its termination signal or drop its owner.
        drop(release);
        let barrier = f
            .audit
            .recover_request(RequestId::new(), &principal())
            .await;
        let no_history = f.encrypted.load_latest().await.unwrap().is_none();
        let no_intent = no_running_intent(&f).await;
        let empty = f.bus.current_snapshot().version.get() == 0;
        eprintln!(
            "RETAINED_RUNNING_KILL_OBSERVED profile={profile:?} reached={reached} no_intent_before={before} acknowledged={} barrier_ok={} no_history={no_history} no_intent={no_intent} empty_snapshot={empty}",
            killed.contains("<ok/>"), barrier.is_ok(),
        );
        runner_gate.resume();
        let finished = joined(target).await;
        let closed = killer.close().await;
        drop(server);
        let drained = f.close().await;
        eprintln!("{CLEAN}: killed-before-intent profile={profile:?} finished={finished} closed={closed} drained={drained}");
        assert!(
            finished && closed && drained,
            "RETAINED_RUNNING_PROTOCOL_CLEANUP"
        );
        assert!(
            reached
                && before
                && killed.contains("<ok/>")
                && barrier.is_ok()
                && no_history
                && no_intent
                && empty,
            "RETAINED_RUNNING_KILL_ACK_REVOKES_BEFORE_INTENT"
        );
    }
}

#[tokio::test]
async fn retained_running_kill_after_effect_preserves_exact_original_publication() {
    for (profile, capacity) in profiles() {
        let f = Fixture::with_profiles(profile, capacity).await;
        let server = f.server(policy_allow_system_with_secret_writes()).unwrap();
        let sessions = SessionRegistry::new();
        let (mut target, runner_gate) = victim(server.clone(), sessions.clone(), 93).await;
        let mut killer = Client::start(server.clone(), sessions, 94).await;
        let release = f.provider.readback_gate.arm();
        target
            .send(&edit("fixture-accepted", false, "replace"))
            .await;
        let reached = tokio::time::timeout(WAIT, f.provider.readback_gate.entered())
            .await
            .is_ok();
        runner_gate.pause();
        let killed = killer.rpc(&kill_session_rpc(93)).await;
        // Termination must also interrupt the RPC while the real worker still
        // owns its blocked publication. Only the response future is cancelled.
        runner_gate.resume();
        let finished = joined(target).await;
        drop(release);
        let barrier = f
            .audit
            .recover_request(RequestId::new(), &principal())
            .await;
        let record = f.encrypted.load_committed_latest().await.unwrap();
        let mut exact = false;
        let mut audited = false;
        if let Some(record) = &record {
            exact = exact_record(&f, record, "fixture-accepted", 1).await;
            if let Some(receipt) = recovered(&f, record).await {
                audited = original_audit(&f, &receipt).await;
            }
        }
        let encrypted = f.provider.active.load(Ordering::Acquire);
        let closed = killer.close().await;
        drop(server);
        let drained = f.close().await;
        eprintln!("{CLEAN}: killed-after-effect profile={profile:?} finished={finished} closed={closed} drained={drained}");
        assert!(closed && drained, "RETAINED_RUNNING_PROTOCOL_CLEANUP");
        assert!(
            reached
                && finished
                && killed.contains("<ok/>")
                && barrier.is_ok()
                && exact
                && audited
                && encrypted == 1,
            "RETAINED_RUNNING_KILL_PRESERVES_ACCEPTED_ORIGINAL"
        );
    }
}

#[tokio::test]
async fn retained_running_failed_kill_observation_preserves_session_authority() {
    let f = Fixture::with_profiles(
        RetainedConfigProfile::NetconfRunningV1,
        ConfigCapacityProfile::BoundedV1,
    )
    .await;
    let server = f.server(policy_allow_system_with_secret_writes()).unwrap();
    let sessions = SessionRegistry::new();
    let (mut target, runner_gate) = victim(server.clone(), sessions.clone(), 95).await;
    let mut killer = Client::start(server.clone(), sessions, 96).await;
    let release = f.provider.encrypt_gate.arm();
    target
        .send(&edit("fixture-still-live", false, "replace"))
        .await;
    let reached = tokio::time::timeout(WAIT, f.provider.encrypt_gate.entered())
        .await
        .is_ok();
    runner_gate.pause();
    f.checkpoint
        .inner
        .readback_unavailable
        .store(true, Ordering::Release);
    let rejected = killer.rpc(&kill_session_rpc(95)).await;
    f.checkpoint
        .inner
        .readback_unavailable
        .store(false, Ordering::Release);
    drop(release);
    let barrier = f
        .audit
        .recover_request(RequestId::new(), &principal())
        .await;
    let record = f.encrypted.load_committed_latest().await.unwrap();
    let mut exact = false;
    if let Some(record) = &record {
        exact = exact_record(&f, record, "fixture-still-live", 1).await;
    }
    runner_gate.resume();
    let reply = target.reply().await;
    let target_closed = target.close().await;
    let killer_closed = killer.close().await;
    drop(server);
    let drained = f.close().await;
    eprintln!("{CLEAN}: refused-kill target_closed={target_closed} killer_closed={killer_closed} drained={drained}");
    assert!(
        target_closed && killer_closed && drained,
        "RETAINED_RUNNING_PROTOCOL_CLEANUP"
    );
    assert!(
        reached
            && rejected.contains("<rpc-error>")
            && !rejected.contains("<ok/>")
            && barrier.is_ok()
            && exact
            && reply.contains("<ok/>"),
        "RETAINED_RUNNING_FAILED_KILL_RETAINS_AUTHORITY"
    );
}
