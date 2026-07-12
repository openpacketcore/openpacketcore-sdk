#![allow(dead_code)]

/// Poll a synchronous predicate until it succeeds or the bounded deadline expires.
pub async fn wait_until<F>(what: &str, deadline: std::time::Duration, mut check: F)
where
    F: FnMut() -> bool,
{
    let start = std::time::Instant::now();
    loop {
        if check() {
            return;
        }
        assert!(start.elapsed() <= deadline, "timed out waiting for {what}");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// Poll an asynchronous predicate until it succeeds or the bounded deadline expires.
pub async fn wait_until_async<F, Fut>(what: &str, deadline: std::time::Duration, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = std::time::Instant::now();
    loop {
        if check().await {
            return;
        }
        assert!(start.elapsed() <= deadline, "timed out waiting for {what}");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}
