use crate::{backend::ReplicationEntry, error::StoreError};

pub(crate) struct SqliteWatchStream {
    pub(crate) rx: tokio::sync::mpsc::Receiver<Result<ReplicationEntry, StoreError>>,
}

impl futures_util::Stream for SqliteWatchStream {
    type Item = Result<ReplicationEntry, StoreError>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}
