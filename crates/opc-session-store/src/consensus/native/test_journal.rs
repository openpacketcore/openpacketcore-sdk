//! Fixture reads share the unchanged process-wide optional page allowance.

use super::{NativeStorage, ReplicationEntry, StoreError};
use std::time::{Duration, Instant};

fn retry_page_refusal(error: &StoreError, deadline: Instant) -> bool {
    matches!(error, StoreError::BackendUnavailable(reason)
        if reason == "native committed state unavailable" && Instant::now() < deadline)
}

pub(crate) fn journal_page_result_for_test<T>(
    mut read: impl FnMut() -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match read() {
            Err(error) if retry_page_refusal(&error, deadline) => {
                std::thread::sleep(Duration::from_millis(1));
            }
            result => return result,
        }
    }
}

pub(crate) fn journal_page_for_test_sync<T>(mut read: impl FnMut() -> Result<T, StoreError>) -> T {
    journal_page_result_for_test(&mut read)
        .unwrap_or_else(|error| panic!("native fixture journal remains unavailable: {error:?}"))
}

// Keep asynchronous release tasks runnable while this fixture waits for an
// optional page. Persistent refusal still fails after a finite real-time guard.
pub(crate) async fn journal_page_result_for_test_async<T, F, Fut>(
    mut read: F,
) -> Result<T, StoreError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, StoreError>>,
{
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match read().await {
            Err(error) if retry_page_refusal(&error, deadline) => {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            result => return result,
        }
    }
}

pub(crate) async fn journal_page_for_test(
    native: &NativeStorage,
    start: u64,
    limit: usize,
) -> Vec<ReplicationEntry> {
    journal_page_result_for_test_async(|| async {
        native.business.replication_log(start, limit, &|| Ok(()))
    })
    .await
    .unwrap_or_else(|error| panic!("native fixture journal remains unavailable: {error:?}"))
}
