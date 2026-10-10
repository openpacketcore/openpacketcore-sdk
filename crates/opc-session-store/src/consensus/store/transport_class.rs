//! Decode authenticated forwarding metadata before selecting a transport pool.
use super::*;
use crate::scope_scheduler::ScopeWorkClass;

/// Select the fixed transport class from the native bounded consensus request.
/// This conveys scheduling only; membership and apply authorization still run.
pub fn session_consensus_work_class(
    request: &SessionConsensusWireRequest,
) -> Result<ScopeWorkClass, SessionConsensusPeerError> {
    request.validate()?;
    match request.family {
        SessionConsensusRpcFamily::InstallSnapshot => Ok(ScopeWorkClass::Maintenance),
        SessionConsensusRpcFamily::Vote
        | SessionConsensusRpcFamily::AppendEntries
        | SessionConsensusRpcFamily::AppendEntriesRoster
        | SessionConsensusRpcFamily::ReadBarrier
        | SessionConsensusRpcFamily::TopologyAdmissionBarrier
        | SessionConsensusRpcFamily::LeadershipTransfer => Ok(ScopeWorkClass::SafetyControl),
        SessionConsensusRpcFamily::ForwardMutation
        | SessionConsensusRpcFamily::ForwardRosterMutation => {
            // Recognize the existing persistence envelope without assigning
            // authority to its mode. The native handler checks the installed mode.
            let payload = persistence_protocol::unwrap_payload(
                SessionPersistenceMode::Async,
                &request.payload,
            )
            .or_else(|_| {
                persistence_protocol::unwrap_payload(
                    SessionPersistenceMode::Durable,
                    &request.payload,
                )
            })?;
            let forwarded: ForwardRequest = if request.family
                == SessionConsensusRpcFamily::ForwardRosterMutation
            {
                decode_roster_bounded(payload).map_err(|_| SessionConsensusPeerError::Protocol)?
            } else {
                decode_bounded(payload).map_err(|_| SessionConsensusPeerError::Protocol)?
            };
            if postcard::to_allocvec(&forwarded).map_err(|_| SessionConsensusPeerError::Protocol)?
                != payload
            {
                return Err(SessionConsensusPeerError::Protocol);
            }
            if request.family == SessionConsensusRpcFamily::ForwardRosterMutation
                && !matches!(&forwarded,ForwardRequest::Mutation(value) if is_roster_mutation_intent(&value.intent))
            {
                return Err(SessionConsensusPeerError::Protocol);
            }
            match forwarded {
                ForwardRequest::Mutation(value) => value
                    .scheduling()
                    .map(|(_, class)| class)
                    .map_err(|_| SessionConsensusPeerError::Protocol),
                ForwardRequest::RecordExpiryPreflight { .. }
                | ForwardRequest::FencedTransitionV2StatusLogicalTimeTicket { .. } => {
                    Ok(ScopeWorkClass::Maintenance)
                }
            }
        }
        _ => Err(SessionConsensusPeerError::Protocol),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{SessionConsensusClusterId, SessionConsensusConfigurationId};
    fn wire(intent: SessionMutationIntent, class: ForwardWorkClass) -> SessionConsensusWireRequest {
        let request = ForwardRequest::Mutation(ForwardMutationRequest {
            request_id: SessionConsensusRequestId::from_bytes([1; 16]),
            intent,
            required_consumer_scope: ForwardConsumerScope::Internal,
            work_class: class,
        });
        let identity = SessionConsensusIdentity::new(
            SessionConsensusClusterId::from_bytes([1; 32]),
            SessionConsensusConfigurationId::from_bytes([2; 32]),
            SessionConsensusConfigurationEpoch::new(1).unwrap(),
        );
        SessionConsensusWireRequest::try_new(
            identity,
            SessionConsensusNodeId::new(1).unwrap(),
            SessionConsensusRpcFamily::ForwardMutation,
            encode_bounded(&request).unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn native_control_and_read_fence_decode_before_transport_selection() {
        let control = wire(
            SessionMutationIntent::PreflightScopeProfile,
            ForwardWorkClass::Inferred,
        );
        assert_eq!(
            session_consensus_work_class(&control),
            Ok(ScopeWorkClass::SafetyControl)
        );
        let read_fence = wire(
            SessionMutationIntent::AdvanceLogicalTime,
            ForwardWorkClass::Inferred,
        );
        assert_eq!(
            session_consensus_work_class(&read_fence),
            Ok(ScopeWorkClass::Normal)
        );
        let mut invalid = control;
        invalid.payload.push(0);
        assert!(
            session_consensus_work_class(&invalid).is_err(),
            "noncanonical tail cannot select a protected listener"
        );
    }
    #[test]
    fn native_class_metadata_cannot_promote_an_ordinary_mutation() {
        for class in [
            ScopeWorkClass::SafetyControl,
            ScopeWorkClass::Emergency,
            ScopeWorkClass::EmergencyClassification,
        ] {
            assert!(session_consensus_work_class(&wire(
                SessionMutationIntent::AdvanceLogicalTime,
                ForwardWorkClass::Declared(class)
            ))
            .is_err());
        }
        let mut missing = wire(
            SessionMutationIntent::AdvanceLogicalTime,
            ForwardWorkClass::Inferred,
        );
        missing.payload.pop();
        assert!(session_consensus_work_class(&missing).is_err());
    }
    #[test]
    fn every_own_batch_class_preserves_the_native_command_bytes_and_id() {
        use crate::scope_batch::{ScopeBatchCommand, ScopeBatchRequest, ScopeCounterMutation};
        let state = crate::scope_authority::tests::admitted();
        let request = ScopeBatchRequest::new(
            state.view.stamp().unwrap(),
            [7; 16],
            0,
            vec![],
            vec![ScopeCounterMutation::new(0, 0, 1).unwrap()],
        )
        .unwrap();
        let command = SessionMutationIntent::ScopeBatch(Box::new(ScopeBatchCommand { request }));
        let original = encode_bounded(&command).unwrap();
        for class in [
            ScopeWorkClass::Emergency,
            ScopeWorkClass::EmergencyClassification,
            ScopeWorkClass::Normal,
            ScopeWorkClass::Maintenance,
        ] {
            let value = wire(command.clone(), ForwardWorkClass::Declared(class));
            assert_eq!(session_consensus_work_class(&value), Ok(class));
            let decoded: ForwardRequest = decode_bounded(&value.payload).unwrap();
            let ForwardRequest::Mutation(decoded) = decoded else {
                panic!("native forwarding command")
            };
            assert_eq!(encode_bounded(&decoded.intent).unwrap(), original);
            assert_eq!(
                decoded.request_id,
                SessionConsensusRequestId::from_bytes([1; 16])
            );
        }
        assert!(session_consensus_work_class(&wire(
            command,
            ForwardWorkClass::Declared(ScopeWorkClass::SafetyControl)
        ))
        .is_err());
    }
}
