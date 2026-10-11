//! One scenario body for both concrete adapters, with real native supervision.
use super::*;
use opc_local_kernel_lifecycle::{
    CommittedScopeEffect, LocalEffectError, LocalKernelLifecycle, LocalResetParticipants,
    LocalScopeResetReceipt, ScopeKernelAuthority,
};

pub(crate) enum TestAuthority {
    Local(ScopeKernelAuthority),
    #[cfg(feature = "native-scope")]
    Native {
        authority: ScopeKernelAuthority<opc_local_kernel_lifecycle::NativeScopeAuthority>,
        transport: Arc<native_transport::NativeTransport>,
    },
}
impl TestAuthority {
    pub(crate) async fn new(
        lifecycle: LocalKernelLifecycle,
        quorum: &Quorum,
    ) -> Result<Self, LocalEffectError> {
        #[cfg(feature = "native-scope")]
        if let Some(transport) = &quorum.native {
            let authority = ScopeKernelAuthority::from_scope_client(
                lifecycle,
                quorum.execution().clone(),
                quorum.committed.clone(),
                transport.client.clone(),
                opc_session_store::scope_scheduler::ScopeWorkClass::Normal,
                Duration::from_secs(1),
            )
            .await?;
            return Ok(Self::Native {
                authority,
                transport: transport.clone(),
            });
        }
        ScopeKernelAuthority::new(
            lifecycle,
            quorum.execution().clone(),
            quorum.committed.clone(),
            quorum.authority.clone(),
            quorum.batches.clone(),
        )
        .await
        .map(Self::Local)
    }

    pub(crate) async fn commit_activation(
        &self,
        request: ScopeBatchRequest,
        child: ScopeChildKey,
    ) -> Result<CommittedScopeEffect, LocalEffectError> {
        match self {
            Self::Local(authority) => authority.commit_activation(request, child).await,
            #[cfg(feature = "native-scope")]
            Self::Native {
                authority,
                transport,
            } => {
                use opc_session_store::scope_scheduler::ScopeWorkClass;
                let mut pending = transport.pending.lock().await;
                let slot = &mut pending[usize::from(request.lane())];
                if let Some(old) = slot {
                    if old.request != request {
                        if old.request.request_id() == request.request_id() {
                            return Err(LocalEffectError::WrongRequest);
                        }
                        if !old.reconciled {
                            return Err(LocalEffectError::OutcomeUnknown);
                        }
                        assert!(transport.coordinator.ack(old.handle.attempt()));
                        *slot = None;
                    }
                }
                if slot.is_none() {
                    let command = request.clone();
                    let class = if request.lane() == 7 {
                        ScopeWorkClass::Emergency
                    } else {
                        ScopeWorkClass::Normal
                    };
                    let handle = transport
                        .coordinator
                        .reserve_lane(request.lane(), class)
                        .await
                        .map_err(|_| LocalEffectError::Unavailable)?
                        .submit(|context| async move {
                            assert_eq!(command.lane(), context.lane());
                            assert_eq!(command.sequence(), context.sequence());
                            Ok(command)
                        })
                        .await
                        .map_err(|_| LocalEffectError::Unavailable)?;
                    *slot = Some(native_transport::Pending {
                        request: request.clone(),
                        handle,
                        reconciled: false,
                    });
                }
                let pending = slot.as_mut().unwrap();
                // A lost response detaches this observer, while the exact
                // accepted attempt remains with its original supervisor.
                let completion =
                    tokio::time::timeout(Duration::from_secs(5), pending.handle.completion())
                        .await
                        .map_err(|_| LocalEffectError::OutcomeUnknown)?;
                let effect = authority
                    .readback_activation(request, child, &completion)
                    .await?;
                pending.reconciled = true;
                // Keep this one receipt until its next lane request so the
                // existing recovery/duplicate-consumption assertions exercise
                // readback again, including through a reconstructed adapter.
                Ok(effect)
            }
        }
    }

    pub(crate) async fn close_execution(&self) {
        match self {
            Self::Local(authority) => authority.close_execution().await,
            #[cfg(feature = "native-scope")]
            Self::Native { authority, .. } => authority.close_execution().await,
        }
    }
    #[cfg(feature = "native-scope")]
    pub(crate) async fn qualify_native_classes(&self, quorum: &Quorum) {
        use opc_session_store::scope_scheduler::ScopeWorkClass;
        let Self::Native {
            authority,
            transport,
        } = self
        else {
            panic!("the class case must use authenticated native readback");
        };
        let scheduler = transport.scheduler.scheduler();
        let scheduler_key =
            ConsensusSessionStore::scope_batch_scheduler_key(quorum.committed.stamp().scope());
        let reservation = transport
            .coordinator
            .reserve_lane(6, ScopeWorkClass::Normal)
            .await
            .unwrap();
        let mut inherited = Box::pin(
            transport
                .coordinator
                .reserve_lane(6, ScopeWorkClass::Emergency),
        );
        assert!(futures_util::poll!(&mut inherited).is_pending());
        let command = std::sync::Mutex::new(None);
        let saved = &command;
        let handle = reservation
            .submit(|context| async move {
                let request = context.request(
                    [201; 16],
                    vec![ScopeChildMutation::Create {
                        key: child_key(201),
                        value: value(201),
                        claims: vec![],
                    }],
                    vec![],
                )?;
                *saved.lock().unwrap() = Some(request.clone());
                Ok(request)
            })
            .await
            .unwrap();
        let completion = handle.completion().await;
        drop(inherited);
        let command = command.into_inner().unwrap().unwrap();
        let verified = transport
            .client
            .verify_batch_completion(&quorum.committed, &command, &completion)
            .unwrap();
        assert_eq!(
            verified.class(),
            ScopeWorkClass::Normal,
            "inherited running priority cannot retag the activation"
        );
        drop(verified);
        let hold = scheduler
            .reserve(scheduler_key, ScopeWorkClass::Normal)
            .await
            .unwrap()
            .start()
            .await
            .unwrap();
        assert!(
            matches!(
                authority
                    .readback_activation(command.clone(), child_key(201), &completion)
                    .await,
                Err(LocalEffectError::Unavailable)
            ),
            "ordinary readback must wait only for Normal capacity"
        );
        drop(hold);
        let normal = authority
            .readback_activation(command, child_key(201), &completion)
            .await
            .unwrap();
        assert!(transport.coordinator.ack(handle.attempt()));
        let hold = scheduler
            .reserve(scheduler_key, ScopeWorkClass::Normal)
            .await
            .unwrap()
            .start()
            .await
            .unwrap();
        assert_eq!(
            normal.recheck().await,
            Err(LocalEffectError::Unavailable),
            "ordinary recheck retains the original class"
        );
        let command = std::sync::Mutex::new(None);
        let saved = &command;
        let handle = transport
            .coordinator
            .reserve_lane(7, ScopeWorkClass::Emergency)
            .await
            .unwrap()
            .submit(|context| async move {
                let request = context.request(
                    [202; 16],
                    vec![ScopeChildMutation::Create {
                        key: child_key(202),
                        value: value(202),
                        claims: vec![],
                    }],
                    vec![],
                )?;
                *saved.lock().unwrap() = Some(request.clone());
                Ok(request)
            })
            .await
            .unwrap();
        let completion = handle.completion().await;
        let command = command.into_inner().unwrap().unwrap();
        let emergency = authority
            .readback_activation(command, child_key(202), &completion)
            .await
            .unwrap();
        emergency
            .recheck()
            .await
            .expect("Emergency readback and recheck progress while Normal is full");
        assert!(transport.coordinator.ack(handle.attempt()));
        drop(hold);
        normal.recheck().await.unwrap();
    }
    pub(crate) async fn shutdown_local(
        &self,
        participants: LocalResetParticipants,
    ) -> Result<LocalScopeResetReceipt, opc_local_kernel_lifecycle::LocalLifecycleError> {
        match self {
            Self::Local(authority) => authority.shutdown_local(participants).await,
            #[cfg(feature = "native-scope")]
            Self::Native { authority, .. } => authority.shutdown_local(participants).await,
        }
    }
}
