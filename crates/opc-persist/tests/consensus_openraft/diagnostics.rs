//! Exercise the real rejection paths with and without diagnostic output.

use super::*;

const CHILD: &str = "OPC_PERSIST_DIAGNOSTIC_CHILD";

pub(super) fn is_read_proof(request: &ConsensusWireRequest) -> bool {
    // The ordinary read barrier and compatibility probe share a wire family.
    // Decode the existing postcard layout to leave all probes available.
    type ReadRequest = (u16, ((u16, u16, u64, [u8; 32]), bool, u64));
    let (revision, (_, compatibility_probe, _)) =
        opc_consensus::decode_bounded::<ReadRequest>(&request.payload).unwrap();
    assert_eq!(revision, opc_persist::CONFIG_CONSENSUS_WIRE_VERSION);
    !compatibility_probe
}

async fn child_output(test: &str) -> String {
    let output = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(CHILD, test)
        .output()
        .await
        .expect("run diagnostic subprocess");
    assert!(
        output.status.success(),
        "diagnostic child failed: {output:?}"
    );
    String::from_utf8(output.stderr).expect("diagnostic UTF-8")
}

#[tokio::test]
async fn initialization_rejection_diagnostics_are_opt_in() {
    let test = "diagnostics::initialization_rejection_diagnostics_are_opt_in";
    if std::env::var(CHILD).as_deref() == Ok(test) {
        let cluster = ThreeNodeCluster::build([[0x55; 32]; 3]).await;
        // This is a real deadline control, intentionally outside the functional
        // formation clock. No canonical voter is allowed to bootstrap it.
        assert_eq!(
            cluster.stores[1].initialize_cluster().await,
            Err(opc_persist::ConfigConsensusOpenError::ClusterFormationRejected),
        );
        assert!(!cluster.stores[1].status().admitted);
        cluster.shutdown().await;
        return;
    }
    let stderr = child_output(test).await;
    if cfg!(feature = "test-control") {
        let line = stderr
            .lines()
            .find(|line| line.starts_with("config_consensus_initialization:"))
            .expect("initialization rejection is diagnosed");
        for field in [
            "stage=membership",
            "elapsed=",
            "wall_elapsed=",
            "operation_timeout=3s",
            "deadline=Some(",
            "expired=Some(true)",
            "error=ClusterFormationRejected",
            "admitted=false",
            "metrics=",
        ] {
            assert!(line.contains(field), "missing {field}: {line}");
        }
    } else {
        assert!(stderr.is_empty(), "production build wrote stderr: {stderr}");
    }
}

#[tokio::test(start_paused = true)]
async fn unconfirmed_successor_diagnostics_survive_deadline() {
    let test = "diagnostics::unconfirmed_successor_diagnostics_survive_deadline";
    if std::env::var(CHILD).as_deref() == Ok(test) {
        scripted_election::schedule::with_frozen_time(async {
            let cluster = ThreeNodeCluster::start().await;
            let leader = cluster.leader();
            let followers: Vec<_> = (0..3).filter(|index| *index != leader).collect();
            let first = &cluster.paths[&(leader, followers[0])];
            let second = &cluster.paths[&(leader, followers[1])];
            for path in [first, second] {
                path.stall_read_proof.store(true, Ordering::SeqCst);
            }
            let store = cluster.stores[leader].clone();
            let stopped_at = tokio::time::Instant::now();
            let shutdown = tokio::spawn(async move { store.shutdown_with_report().await });
            // An accepted leadership transfer and higher committed successor
            // vote must precede this real, deliberately stalled read proof.
            tokio::select! {
                () = first.read_barrier_stalled.notified() => {},
                () = second.read_barrier_stalled.notified() => {},
            }
            let preparation = opc_consensus::planned_shutdown_timeout(Duration::from_secs(3));
            tokio::time::advance(preparation + Duration::from_millis(1)).await;
            assert_eq!(
                shutdown.await.unwrap().unwrap(),
                opc_consensus::PlannedShutdownOutcome::Fallback {
                    reason: opc_consensus::PlannedShutdownFallback::SuccessorUnconfirmed,
                },
            );
            assert!(stopped_at.elapsed() < Duration::from_secs(3));
            cluster.shutdown().await;
        })
        .await;
        return;
    }
    let stderr = child_output(test).await;
    if cfg!(feature = "test-control") {
        let line = stderr
            .lines()
            .find(|line| line.contains("result=Err(SuccessorUnconfirmed)"))
            .expect("unconfirmed successor retains its read-proof diagnostic");
        for field in [
            "config_consensus_shutdown:",
            "preparation_timeout=1.5s",
            "expired=Some(true)",
            "successor=Some(",
            "from_term=Some(",
            "successor_vote=Some(",
            "committed: true",
            "committed_index=Some(",
            "metrics=",
        ] {
            assert!(line.contains(field), "missing {field}: {line}");
        }
        // The inner RPC deadline and outer preparation deadline are equal.
        // Whichever timeout is observed must explain the corresponding read
        // state; neither may erase the successor or the attempted proof.
        let fields = if line.contains("outer_timeout=true") {
            [
                "stage=successor-read-proof",
                "read_state=in-flight",
                "read_error=None",
            ]
        } else {
            [
                "stage=successor-route-refresh",
                "read_state=returned",
                "read_error=Some(Unavailable)",
            ]
        };
        for field in fields {
            assert!(line.contains(field), "missing {field}: {line}");
        }
    } else {
        assert!(stderr.is_empty(), "production build wrote stderr: {stderr}");
    }
}
