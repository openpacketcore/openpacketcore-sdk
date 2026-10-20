//! Shared first formation for functional configuration-consensus fixtures.

use std::future::{poll_fn, Future};
use std::task::Poll;

use super::*;
use opc_persist::ConfigConsensusOpenError;
use tokio::sync::oneshot;

type FormationResults = (
    Result<(), ConfigConsensusOpenError>,
    Result<(), ConfigConsensusOpenError>,
    Result<(), ConfigConsensusOpenError>,
);

struct FirstPollPause {
    entered: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
}

pub(super) async fn initialize(stores: Vec<ConsensusConfigStore>) -> FormationResults {
    initialize_with_pause(stores, None).await
}

async fn initialize_with_pause(
    stores: Vec<ConsensusConfigStore>,
    pause: Option<FirstPollPause>,
) -> FormationResults {
    let formation = async move {
        let initializing = async {
            tokio::join!(
                stores[0].initialize_cluster(),
                stores[1].initialize_cluster(),
                stores[2].initialize_cluster(),
            )
        };
        tokio::pin!(initializing);
        if let Some(pause) = pause {
            // Poll the real initializers once: they establish their original
            // deadlines before the caller imposes a scheduling pause. Engine
            // tasks stay on the runtime on which the stores were opened.
            poll_fn(|context| match initializing.as_mut().poll(context) {
                Poll::Pending => Poll::Ready(()),
                Poll::Ready(_) => panic!("first formation must await its engine"),
            })
            .await;
            pause.entered.send(()).expect("observe formation pause");
            pause.release.await.expect("release formation pause");
        }
        initializing.await
    };
    super::formation_clock::run(formation).await
}

#[tokio::test(start_paused = true)]
async fn setup_pause_does_not_spend_initialization_deadline() {
    let cluster = ThreeNodeCluster::build([[0x55; 32]; 3]).await;
    let (entered, paused) = oneshot::channel();
    let (release, resumed) = oneshot::channel();
    let initializing = tokio::spawn(initialize_with_pause(
        cluster.stores.clone(),
        Some(FirstPollPause {
            entered,
            release: resumed,
        }),
    ));
    paused
        .await
        .expect("initializers established their deadlines");
    // The fixture's operation bound remains three seconds. Advancing only
    // the caller's clock models a pause in polling the setup future.
    tokio::time::advance(Duration::from_secs(4)).await;
    release.send(()).expect("resume the setup future");
    let results = initializing.await.expect("join fixture formation");
    assert_eq!(
        results,
        (Ok(()), Ok(()), Ok(())),
        "one-shot fixture formation"
    );
    tokio::time::resume();
    cluster.wait_ready().await;
    for store in &cluster.stores {
        assert!(store.status().admitted, "every original voter is admitted");
    }
    cluster.shutdown().await;
}
