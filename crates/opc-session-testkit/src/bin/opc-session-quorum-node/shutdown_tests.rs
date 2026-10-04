//! The qualification child observes a clone-wide drain through bounded API
//! waits. Timing out one observer never completes or cancels the owned drain.

use super::*;
use tokio::sync::{oneshot, watch};
use tokio::time::{advance, timeout, Instant};

fn unavailable() -> StoreError {
    StoreError::BackendUnavailable("fixed shutdown observation unavailable".to_owned())
}

async fn bounded_observation(
    mut completion: watch::Receiver<Option<Result<(), StoreError>>>,
) -> Result<(), StoreError> {
    timeout(Duration::from_millis(10), async {
        loop {
            let state = completion.borrow_and_update().clone();
            if let Some(result) = state {
                return result;
            }
            completion.changed().await.map_err(|_| unavailable())?;
        }
    })
    .await
    .unwrap_or_else(|_| Err(unavailable()))
}

#[tokio::test(start_paused = true)]
async fn shutdown_wait_retains_the_same_owned_drain_after_an_observer_timeout() {
    let (complete, completion) = watch::channel(None);
    let (release, released) = oneshot::channel();
    let drain = tokio::spawn(async move {
        released.await.expect("release the one owned drain");
        complete.send_replace(Some(Ok(())));
    });
    let deadline = Instant::now() + Duration::from_millis(45);
    let joined = tokio::spawn(async move {
        join_qualification_shutdown_before(deadline, || bounded_observation(completion.clone()))
            .await
    });
    tokio::task::yield_now().await;
    advance(Duration::from_millis(11)).await;
    tokio::task::yield_now().await;
    let prematurely_finished = joined.is_finished();
    let drain_still_owned = !drain.is_finished();
    release
        .send(())
        .expect("observer timeout retained the drain");
    drain.await.expect("join the one actual drain");
    let result = joined.await.expect("join the qualification observer");
    assert!(drain_still_owned, "the first wait did not finish the drain");
    assert!(
        !prematurely_finished,
        "one API timeout is not a terminal drain result"
    );
    assert_eq!(
        result,
        Ok(()),
        "only actual drain completion permits shutdown"
    );
}

#[tokio::test(start_paused = true)]
async fn shutdown_wait_preserves_one_absolute_control_deadline() {
    let (complete, completion) = watch::channel(None);
    let started = Instant::now();
    let deadline = started + Duration::from_millis(45);
    let result =
        join_qualification_shutdown_before(deadline, || bounded_observation(completion.clone()))
            .await;
    assert!(
        result.is_err(),
        "an unfinished drain cannot pass the deadline"
    );
    assert_eq!(
        Instant::now(),
        deadline,
        "API waits share one control deadline"
    );
    assert!(
        complete.borrow().is_none(),
        "timeout cannot invent drain completion"
    );
}

#[tokio::test(start_paused = true)]
async fn shutdown_wait_preserves_an_already_completed_storage_failure() {
    let error = unavailable();
    let (_complete, completion) = watch::channel(Some(Err(error.clone())));
    let started = Instant::now();
    let result = join_qualification_shutdown_before(started + Duration::from_millis(45), || {
        bounded_observation(completion.clone())
    })
    .await;
    assert_eq!(result, Err(error));
    assert_eq!(
        Instant::now(),
        started,
        "a latched failure is terminal without a wait"
    );
}

#[tokio::test(start_paused = true)]
async fn shutdown_wait_accepts_an_already_completed_drain() {
    let (_complete, completion) = watch::channel(Some(Ok(())));
    let started = Instant::now();
    assert_eq!(
        join_qualification_shutdown_before(started + Duration::from_millis(45), || {
            bounded_observation(completion.clone())
        })
        .await,
        Ok(())
    );
    assert_eq!(Instant::now(), started);
}

#[tokio::test(start_paused = true)]
async fn shutdown_wait_does_not_start_an_observation_at_the_expired_control_deadline() {
    let calls = std::cell::Cell::new(0);
    let result = join_qualification_shutdown_before(Instant::now(), || {
        calls.set(calls.get() + 1);
        std::future::ready(Ok(()))
    })
    .await;
    assert!(result.is_err());
    assert_eq!(
        calls.get(),
        0,
        "the inclusive cutoff forbids a new observation"
    );
}

#[tokio::test(start_paused = true)]
async fn shutdown_wait_rejects_a_ready_result_that_consumed_the_control_budget() {
    let deadline = Instant::now() + Duration::from_millis(45);
    let result = join_qualification_shutdown_before(deadline, || async {
        advance(Duration::from_millis(45)).await;
        Ok(())
    })
    .await;
    assert!(
        result.is_err(),
        "a late ready result cannot bypass the cutoff"
    );
    assert_eq!(Instant::now(), deadline);
}
