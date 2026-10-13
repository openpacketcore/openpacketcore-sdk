//! Process-bound observations under one absolute deadline and native read admission.
use super::*;
use opc_session_store::{scope_batch::*, scope_scheduler::ScopeWorkClass};

fn unavailable() -> ScopeChildReadError {
    ScopeBatchError::Unavailable.into()
}

impl ScopeClient {
    /// Observe 1–32 distinct children under this process's genuine current authority.
    /// The complete result preserves key order and all canonical record metadata.
    /// One absolute deadline covers admission, connection ownership, proof and reply.
    /// This read owns no replay lane and cannot issue an effect capability.
    pub async fn read_children(
        &self,
        authority: &CommittedScopeAuthority,
        keys: &[ScopeChildKey],
        class: ScopeWorkClass,
        deadline: Instant,
    ) -> Result<Vec<Option<ScopeChildRecord>>, ScopeChildReadError> {
        if !(1..=MAX_SCOPE_CHILD_READ_KEYS).contains(&keys.len()) {
            return Err(ScopeBatchError::InvalidRequest.into());
        }
        let request = ScopeChildReadRequest::new(authority.stamp(), keys.to_vec())?;
        if authority.check_execution(&self.0.execution).is_err() {
            return Err(ScopeBatchError::Scope(ScopeAuthorityError::Unauthorized).into());
        }
        self.check_child_read(&request, class, deadline)?;
        self.0
            .config
            .process
            .gate
            .observe(async {
                timeout_at(deadline, async {
                    let _running = self
                        .0
                        .config
                        .scheduler
                        .reserve(
                            opc_session_store::ConsensusSessionStore::scope_batch_scheduler_key(
                                &self.0.config.scope,
                            ),
                            class,
                        )
                        .await
                        .map_err(|_| unavailable())?
                        .start()
                        .await
                        .map_err(|_| unavailable())?;
                    self.child_read_exchange(&request, class, deadline).await
                })
                .await
                .map_err(|_| unavailable())?
            })
            .await
            .map_err(|_| ScopeBatchError::Scope(ScopeAuthorityError::StaleAuthority))?
    }

    /// Observe one opaque key with the same authority, admission and deadline rules.
    pub async fn read_child(
        &self,
        authority: &CommittedScopeAuthority,
        key: ScopeChildKey,
        class: ScopeWorkClass,
        deadline: Instant,
    ) -> Result<Option<ScopeChildRecord>, ScopeChildReadError> {
        self.read_children(authority, &[key], class, deadline)
            .await?
            .pop()
            .ok_or_else(unavailable)
    }

    // Only the trusted batch port calls this while its builder owns the original
    // resident/running entitlement. A wire response never supplies that class.
    pub(super) async fn read_children_admitted(
        &self,
        request: &ScopeChildReadRequest,
        class: ScopeWorkClass,
        deadline: Instant,
    ) -> Result<Vec<Option<ScopeChildRecord>>, ScopeChildReadError> {
        self.check_child_read(request, class, deadline)?;
        self.0
            .config
            .process
            .gate
            .observe(self.child_read_exchange(request, class, deadline))
            .await
            .map_err(|_| ScopeBatchError::Scope(ScopeAuthorityError::StaleAuthority))?
    }

    fn check_child_read(
        &self,
        request: &ScopeChildReadRequest,
        class: ScopeWorkClass,
        deadline: Instant,
    ) -> Result<(), ScopeChildReadError> {
        batch::data_class(class)?;
        if request.stamp().scope() != &self.0.config.scope
            || request.stamp().execution() != &self.0.execution
        {
            return Err(ScopeBatchError::Scope(ScopeAuthorityError::Unauthorized).into());
        }
        if Instant::now() >= deadline {
            return Err(unavailable());
        }
        Ok(())
    }

    async fn child_read_exchange(
        &self,
        request: &ScopeChildReadRequest,
        class: ScopeWorkClass,
        deadline: Instant,
    ) -> Result<Vec<Option<ScopeChildRecord>>, ScopeChildReadError> {
        self.check_child_read(request, class, deadline)?;
        let canonical = request.encode_canonical()?;
        let id = super::super::boot::random_nonzero().map_err(|_| unavailable())?;
        let digest = transport_request_digest(Method::ChildRead, &id, &canonical)
            .map_err(|_| ScopeBatchError::InvalidRequest)?;
        let payload = self
            .roundtrip_at(
                Method::ChildRead,
                batch::data_class(class)?,
                id,
                digest,
                &canonical,
                None,
                deadline,
            )
            .await
            .map_err(batch::batch_error)?
            .payload;
        if Instant::now() >= deadline {
            return Err(unavailable());
        }
        if payload.own_execution != [0; 32] {
            return Err(unavailable());
        }
        match payload.status {
            ResultStatus::ChildObservation => {
                super::super::child_read_wire::decode_observation(request, &payload.body)
            }
            ResultStatus::BatchError => Err(ScopeBatchError::decode_canonical(&payload.body)
                .map_err(|_| unavailable())?
                .into()),
            ResultStatus::ProvenNoEffect | ResultStatus::OutcomeUnknown => {
                Err(payload_error(&payload)
                    .map(batch::batch_error)
                    .map(ScopeChildReadError::from)
                    .unwrap_or_else(|_| unavailable()))
            }
            _ => Err(unavailable()),
        }
    }
}
