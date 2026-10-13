//! Schema-only authorization state shared by data work and independent control.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use opc_config_model::TrustedPrincipal;
use opc_mgmt_authz::{
    AuthorizationGate, AuthorizedReadSelection, PolicySource, ReadAction, ReadAuthorizer, ReadNode,
    ResolvedPolicy,
};
use opc_mgmt_schema::SchemaRegistry;

use crate::{GnmiError, ReadSelectionEntry};

pub(crate) struct StreamAuthorization {
    registry: &'static dyn SchemaRegistry,
    source: Arc<dyn PolicySource>,
    principal: TrustedPrincipal,
    requested: Vec<ReadNode<'static>>,
    gate: AuthorizationGate,
    state: Mutex<State>,
}

struct State {
    previously_permitted: BTreeSet<String>,
    allowed_requested: BTreeSet<String>,
    initial: Option<(u64, ResolvedPolicy)>,
}

enum RecordOutcome {
    Recorded,
    RevisionMoved,
    Revoked,
}

impl std::fmt::Debug for StreamAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamAuthorization")
            .finish_non_exhaustive()
    }
}

pub(crate) fn authorization_failure() -> GnmiError {
    GnmiError::unavailable("gNMI subscription authorization context changed")
}

impl StreamAuthorization {
    pub(crate) fn new(
        registry: &'static dyn SchemaRegistry,
        source: Arc<dyn PolicySource>,
        principal: TrustedPrincipal,
        selected: &[ReadSelectionEntry],
        initial: ResolvedPolicy,
        revision: u64,
        gate: AuthorizationGate,
    ) -> Result<Self, GnmiError> {
        let requested = selected
            .iter()
            .map(|entry| crate::get::read_node(registry, entry.schema_path()))
            .collect::<Vec<_>>();
        let authz =
            ReadAuthorizer::new(registry, source.as_ref()).map_err(|_| authorization_failure())?;
        let selection = authz.authorize_selection_resolved(
            &initial,
            ReadAction::Subscribe,
            &requested,
            &BTreeSet::new(),
        );
        let allowed_requested = allowed_nodes(&selection);
        Ok(Self {
            registry,
            source,
            principal,
            requested,
            gate,
            state: Mutex::new(State {
                previously_permitted: selection.permitted_paths,
                allowed_requested,
                initial: Some((revision, initial)),
            }),
        })
    }

    pub(crate) fn snapshot(
        &self,
        requested: &[ReadNode<'_>],
    ) -> Result<AuthorizedReadSelection, GnmiError> {
        loop {
            let revision = self.gate.revision().map_err(|_| authorization_failure())?;
            let (previous, initial) = {
                let mut state = self.state.lock().map_err(|_| authorization_failure())?;
                (state.previously_permitted.clone(), state.initial.take())
            };
            let resolved = match initial {
                Some((initial_revision, initial)) if revision == initial_revision => initial,
                _ => match self
                    .source
                    .active_policy_context_for_principal(&self.principal)
                {
                    Ok(resolved) => resolved,
                    Err(_) if self.gate.reevaluation_pending() == Ok(true) => {
                        // Output is already gated by the activated revision.
                        // Independent control owns refresh failure and termination.
                        return Ok(AuthorizedReadSelection::default());
                    }
                    Err(_) => return Err(authorization_failure()),
                },
            };
            let selection = self.evaluate(&resolved, requested, &previous)?;
            match self.record(revision, &selection)? {
                RecordOutcome::Recorded => return Ok(selection),
                RecordOutcome::RevisionMoved => continue,
                RecordOutcome::Revoked if self.gate.reevaluation_pending() == Ok(true) => {
                    // The control notification owns revocation. Config events
                    // cannot accelerate termination while delivery is pending.
                    return Ok(AuthorizedReadSelection::default());
                }
                RecordOutcome::Revoked => {
                    self.gate.terminate();
                    return Err(authorization_failure());
                }
            }
        }
    }

    /// Hidden events make one authorization decision, then stop. In particular,
    /// a denied event does not examine revocation state or perform audit work.
    pub(crate) fn event(&self, node: &'static str) -> Result<bool, GnmiError> {
        let mut requested = self.requested.clone();
        requested.push(crate::get::read_node(self.registry, node));
        loop {
            let revision = self.gate.revision().map_err(|_| authorization_failure())?;
            let previous = self
                .state
                .lock()
                .map_err(|_| authorization_failure())?
                .previously_permitted
                .clone();
            let resolved = match self
                .source
                .active_policy_context_for_principal(&self.principal)
            {
                Ok(resolved) => resolved,
                Err(_) if self.gate.reevaluation_pending().unwrap_or(false) => {
                    // Output is already gated by the activated revision. Its
                    // independent control notification owns refresh failure and
                    // termination; an unprovably authorized event is only dropped.
                    return Ok(false);
                }
                Err(_) => return Err(authorization_failure()),
            };
            let authz = ReadAuthorizer::new(self.registry, self.source.as_ref())
                .map_err(|_| authorization_failure())?;
            let selection =
                authz.authorize_event_selection_resolved(&resolved, &requested, &previous);
            if selection
                .decisions
                .last()
                .is_none_or(|decision| !decision.allowed)
            {
                return Ok(false);
            }
            match self.record(revision, &selection)? {
                RecordOutcome::Recorded => return Ok(true),
                RecordOutcome::RevisionMoved => continue,
                RecordOutcome::Revoked if self.gate.reevaluation_pending() == Ok(true) => {
                    return Ok(false);
                }
                RecordOutcome::Revoked => {
                    self.gate.terminate();
                    return Err(authorization_failure());
                }
            }
        }
    }

    /// One fresh context covers requested nodes, aggregate descendants, keys,
    /// and every schema permission previously allowed by this stream.
    pub(crate) fn reevaluate(&self) -> Result<(), GnmiError> {
        let revision = self.gate.revision().map_err(|_| authorization_failure())?;
        let previous = {
            let mut state = self.state.lock().map_err(|_| authorization_failure())?;
            state.initial = None;
            state.previously_permitted.clone()
        };
        let resolved = self
            .source
            .active_policy_context_for_principal(&self.principal)
            .map_err(|_| authorization_failure())?;
        let selection = self.evaluate(&resolved, &self.requested, &previous)?;
        match self.record(revision, &selection)? {
            RecordOutcome::Recorded => Ok(()),
            RecordOutcome::RevisionMoved | RecordOutcome::Revoked => Err(authorization_failure()),
        }
    }

    /// Prunes a provider subscription from the most recent complete batch. This
    /// does not load another policy or inspect any stored row or key value.
    pub(crate) fn permits_request(&self, schema_path: &str) -> bool {
        self.state
            .lock()
            .is_ok_and(|state| state.allowed_requested.contains(schema_path))
    }

    fn evaluate(
        &self,
        resolved: &ResolvedPolicy,
        requested: &[ReadNode<'_>],
        previous: &BTreeSet<String>,
    ) -> Result<AuthorizedReadSelection, GnmiError> {
        let authz = ReadAuthorizer::new(self.registry, self.source.as_ref())
            .map_err(|_| authorization_failure())?;
        Ok(
            authz.authorize_selection_resolved(
                resolved,
                ReadAction::Subscribe,
                requested,
                previous,
            ),
        )
    }

    fn record(
        &self,
        revision: u64,
        selection: &AuthorizedReadSelection,
    ) -> Result<RecordOutcome, GnmiError> {
        match self.gate.at_revision(revision, || {
            let mut state = self.state.lock().map_err(|_| authorization_failure())?;
            if !state
                .previously_permitted
                .is_subset(&selection.permitted_paths)
            {
                return Ok(RecordOutcome::Revoked);
            }
            state
                .previously_permitted
                .extend(selection.permitted_paths.iter().cloned());
            state.allowed_requested = allowed_nodes(selection);
            Ok(RecordOutcome::Recorded)
        }) {
            Ok(result) => result,
            Err(_) => {
                // Distinguish a healthy activation race from a failed gate.
                self.gate.revision().map_err(|_| authorization_failure())?;
                Ok(RecordOutcome::RevisionMoved)
            }
        }
    }
}

fn allowed_nodes(selection: &AuthorizedReadSelection) -> BTreeSet<String> {
    selection
        .decisions
        .iter()
        .filter(|decision| decision.allowed)
        .map(|decision| decision.path.clone())
        .collect()
}
