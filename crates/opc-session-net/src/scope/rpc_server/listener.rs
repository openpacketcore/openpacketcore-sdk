//! Bounded connection supervision, independent of the accepted stream type.
use std::{future::Future, io, sync::Arc, time::Duration};
use tokio::{
    sync::{watch, Semaphore},
    task::JoinSet,
};

pub(super) async fn supervise<T, A, AF, H, HF>(
    mut accept: A,
    mut handle: H,
    mut stop: watch::Receiver<bool>,
) where
    T: Send + 'static,
    A: FnMut() -> AF,
    AF: Future<Output = io::Result<T>>,
    H: FnMut(T) -> HF,
    HF: Future<Output = ()> + Send + 'static,
{
    let slots = Arc::new(Semaphore::new(64));
    let mut connections = JoinSet::new();
    let mut backoff = Duration::from_millis(10);
    loop {
        let slot = tokio::select! {
            biased;
            _ = stop.changed() => break,
            permit = slots.clone().acquire_owned() => match permit {
                Ok(permit) => permit,
                Err(_) => break,
            },
        };
        let stream = tokio::select! {
            biased;
            _ = stop.changed() => break,
            result = accept() => match result {
                Ok(stream) => {
                    backoff = Duration::from_millis(10);
                    stream
                },
                Err(error) => {
                    drop(slot);
                    if !matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionAborted | io::ErrorKind::ConnectionReset
                    ) {
                        tokio::select! {
                            biased;
                            _ = stop.changed() => break,
                            _ = tokio::time::sleep(backoff) => {},
                        }
                        backoff = (backoff * 2).min(Duration::from_millis(250));
                    } else {
                        tokio::task::yield_now().await;
                    }
                    continue;
                },
            },
        };
        let handled = handle(stream);
        connections.spawn(async move {
            let _slot = slot;
            handled.await;
        });
        while connections.try_join_next().is_some() {}
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };
    use tokio::sync::{mpsc, Mutex};

    struct Live(Arc<AtomicUsize>);
    impl Drop for Live {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn accept_errors_preserve_live_connections_and_keep_accepting() {
        let (send, receive) = mpsc::unbounded_channel();
        let receive = Arc::new(Mutex::new(receive));
        let (started, mut starts) = mpsc::unbounded_channel();
        let active = Arc::new(AtomicUsize::new(0));
        let tracked = active.clone();
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(supervise(
            move || {
                let receive = receive.clone();
                async move { receive.lock().await.recv().await.unwrap() }
            },
            move |id| {
                let started = started.clone();
                let active = tracked.clone();
                async move {
                    active.fetch_add(1, Ordering::SeqCst);
                    let _live = Live(active);
                    started.send(id).unwrap();
                    std::future::pending::<()>().await;
                }
            },
            stopped,
        ));
        send.send(Ok(0)).unwrap();
        assert_eq!(starts.recv().await, Some(0));
        for (id, error) in [
            io::Error::from(io::ErrorKind::ConnectionAborted),
            io::Error::from_raw_os_error(rustix::io::Errno::MFILE.raw_os_error()),
            io::Error::from_raw_os_error(rustix::io::Errno::NFILE.raw_os_error()),
        ]
        .into_iter()
        .enumerate()
        {
            send.send(Err(error)).unwrap();
            send.send(Ok(id + 1)).unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(10), starts.recv())
                    .await
                    .unwrap(),
                Some(id + 1),
                "an accept error must not terminate the class listener"
            );
            assert_eq!(
                active.load(Ordering::SeqCst),
                id + 2,
                "existing connections remain alive"
            );
        }
        stop.send(true).unwrap();
        task.await.unwrap();
        assert_eq!(
            active.load(Ordering::SeqCst),
            0,
            "explicit shutdown reaps connections"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn descriptor_pressure_retries_with_a_short_capped_backoff() {
        assert_accept_backoff(rustix::io::Errno::MFILE).await;
        assert_accept_backoff(rustix::io::Errno::NFILE).await;
    }

    #[tokio::test(start_paused = true)]
    async fn other_persistent_accept_errors_retry_with_a_short_capped_backoff() {
        for error in [
            rustix::io::Errno::NOBUFS,
            rustix::io::Errno::NOMEM,
            rustix::io::Errno::INVAL,
        ] {
            assert_accept_backoff(error).await;
        }
    }

    async fn assert_accept_backoff(error: rustix::io::Errno) {
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let observed = calls.clone();
        let (started, mut starts) = mpsc::unbounded_channel();
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(supervise(
            move || {
                let calls = calls.clone();
                async move {
                    let count = {
                        let mut calls = calls.lock().unwrap();
                        calls.push(tokio::time::Instant::now());
                        calls.len()
                    };
                    if count <= 10 {
                        Err(io::Error::from_raw_os_error(error.raw_os_error()))
                    } else if count == 11 {
                        Ok(())
                    } else {
                        std::future::pending().await
                    }
                }
            },
            move |()| {
                let started = started.clone();
                async move {
                    started.send(()).unwrap();
                    std::future::pending::<()>().await;
                }
            },
            stopped,
        ));
        tokio::time::timeout(Duration::from_secs(10), starts.recv())
            .await
            .unwrap()
            .unwrap();
        stop.send(true).unwrap();
        task.await.unwrap();
        let calls = observed.lock().unwrap();
        for pair in calls[..11].windows(2) {
            let delay = pair[1].duration_since(pair[0]);
            assert!((Duration::from_millis(10)..=Duration::from_millis(251)).contains(&delay));
        }
        assert!(calls[10].duration_since(calls[9]) >= Duration::from_millis(250));
    }
}
