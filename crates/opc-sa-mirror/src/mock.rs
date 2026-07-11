//! In-memory fake mesh for testing mirror producers and consumers.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use opc_ipsec_lb::SaId;

use crate::error::SaMirrorError;
use crate::keymat::{KeyEpoch, SaCounterCheckpoint, SaMirrorInstall};
use crate::ports::{SaMirrorProducer, SaMirrorSink};

/// [`SaMirrorProducer`] that hands frames straight to a local sink.
///
/// This is the fake mesh for deterministic tests: no network, no TLS, same
/// validation and custody semantics as the real transport. It is not a
/// production adapter — production mirroring crosses nodes and must use
/// [`crate::RemoteMirrorProducer`].
#[derive(Clone)]
pub struct InProcessMirrorProducer {
    sink: Arc<dyn SaMirrorSink>,
}

impl fmt::Debug for InProcessMirrorProducer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InProcessMirrorProducer")
            .finish_non_exhaustive()
    }
}

impl InProcessMirrorProducer {
    /// Wire a producer directly to a sink.
    #[must_use]
    pub fn new(sink: Arc<dyn SaMirrorSink>) -> Self {
        Self { sink }
    }
}

#[async_trait]
impl SaMirrorProducer for InProcessMirrorProducer {
    async fn mirror_install(&self, install: SaMirrorInstall) -> Result<(), SaMirrorError> {
        install.validate()?;
        self.sink.accept_install(install).await
    }

    async fn mirror_checkpoint(
        &self,
        checkpoint: SaCounterCheckpoint,
    ) -> Result<(), SaMirrorError> {
        checkpoint.validate()?;
        self.sink.accept_checkpoint(checkpoint).await
    }

    async fn mirror_withdraw(&self, sa: SaId, epoch: KeyEpoch) -> Result<(), SaMirrorError> {
        crate::keymat::validate_sa(sa)?;
        self.sink.accept_withdraw(sa, epoch).await
    }
}
