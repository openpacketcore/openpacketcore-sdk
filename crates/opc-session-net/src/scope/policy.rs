//! Live principal/slot/operation routing policy, before body and proof allocation.
use super::wire::*;
use opc_types::SpiffeId;
use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex},
};

/// Scope roles come from trusted local configuration, never wire claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeRole {
    /// A worker configured for an explicit set of stable scopes.
    Worker,
    /// An authorized scope controller; mutations are deferred in this profile.
    Controller,
    /// An authorized read-only observer.
    Observer,
}
/// Configuration or live authorization failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// Ambiguous or malformed principal configuration.
    #[error("invalid scope principal policy")]
    Invalid,
    /// This principal/scope/operation/class tuple is not authorized.
    #[error("scope operation unauthorized")]
    Unauthorized,
    /// Live policy changed after this attempt was routed.
    #[error("scope authorization changed")]
    Changed,
}
/// Explicit trusted enrollment of one principal and its permitted scopes.
#[derive(Clone)]
pub struct PrincipalGrant {
    principal: SpiffeId,
    role: ScopeRole,
    scopes: BTreeMap<[u8; 32], ScopeBinding>,
}
impl PrincipalGrant {
    /// Enroll one transport principal for a nonempty explicit set of scopes.
    /// Each worker call still proves its own slot-bound ticket and boot key.
    pub fn new(
        principal: SpiffeId,
        role: ScopeRole,
        scopes: Vec<ScopeBinding>,
    ) -> Result<Self, PolicyError> {
        if scopes.is_empty() {
            return Err(PolicyError::Invalid);
        }
        let mut indexed = BTreeMap::new();
        for scope in scopes {
            if indexed.insert(scope.commitment(), scope).is_some() {
                return Err(PolicyError::Invalid);
            }
        }
        Ok(Self {
            principal,
            role,
            scopes: indexed,
        })
    }
}
impl fmt::Debug for PrincipalGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrincipalGrant([redacted])")
    }
}
struct State {
    revision: u64,
    grants: BTreeMap<SpiffeId, PrincipalGrant>,
}
fn index(grants: Vec<PrincipalGrant>) -> Result<BTreeMap<SpiffeId, PrincipalGrant>, PolicyError> {
    let mut result = BTreeMap::new();
    for grant in grants {
        if result.insert(grant.principal.clone(), grant).is_some() {
            return Err(PolicyError::Invalid);
        }
    }
    Ok(result)
}
/// Shared live authorization policy for the scope endpoint.
#[derive(Clone)]
pub struct ScopePolicy(Arc<Mutex<State>>);
impl fmt::Debug for ScopePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopePolicy([redacted])")
    }
}
impl ScopePolicy {
    /// Install explicit grants; an empty list grants nothing.
    pub fn new(grants: Vec<PrincipalGrant>) -> Result<Self, PolicyError> {
        Ok(Self(Arc::new(Mutex::new(State {
            revision: 1,
            grants: index(grants)?,
        }))))
    }
    /// Atomically replace grants and invalidate all previously routed attempts.
    pub fn replace(&self, grants: Vec<PrincipalGrant>) -> Result<(), PolicyError> {
        let grants = index(grants)?;
        let mut state = self.0.lock().map_err(|_| PolicyError::Changed)?;
        let revision = state.revision.checked_add(1).ok_or(PolicyError::Invalid)?;
        *state = State { revision, grants };
        Ok(())
    }
    pub(super) fn resolve_scope(
        &self,
        principal: &SpiffeId,
        installation: &[u8; 32],
        commitment: &[u8; 32],
    ) -> Result<ScopeBinding, PolicyError> {
        let state = self.0.lock().map_err(|_| PolicyError::Changed)?;
        let scope = state
            .grants
            .get(principal)
            .and_then(|grant| grant.scopes.get(commitment))
            .ok_or(PolicyError::Unauthorized)?;
        if scope.installation() != installation {
            return Err(PolicyError::Unauthorized);
        }
        Ok(scope.clone())
    }
    pub(super) fn authorize(
        &self,
        principal: &SpiffeId,
        scope: &ScopeBinding,
        method: Method,
        class: Class,
    ) -> Result<RoutedCall, PolicyError> {
        let state = self.0.lock().map_err(|_| PolicyError::Changed)?;
        let grant = state
            .grants
            .get(principal)
            .ok_or(PolicyError::Unauthorized)?;
        if grant.scopes.get(&scope.commitment()) != Some(scope) {
            return Err(PolicyError::Unauthorized);
        }
        let allowed = match (grant.role, method) {
            (
                ScopeRole::Worker,
                Method::AdmitInitial
                | Method::SucceedClosed
                | Method::Close
                | Method::Current
                | Method::Outcome,
            ) => class == Class::SafetyControl,
            (
                ScopeRole::Worker,
                Method::ApplyBatch
                | Method::BatchReopen
                | Method::BatchCancel
                | Method::BatchLookup,
            ) => class != Class::SafetyControl,
            (ScopeRole::Controller | ScopeRole::Observer, Method::Current | Method::Outcome) => {
                class == Class::SafetyControl
            }
            (
                ScopeRole::Controller | ScopeRole::Observer,
                Method::BatchReopen | Method::BatchLookup,
            ) => matches!(
                class,
                Class::Normal | Class::Maintenance | Class::EmergencyClassification
            ),
            _ => false,
        };
        if !allowed {
            return Err(PolicyError::Unauthorized);
        }
        Ok(RoutedCall {
            policy: self.clone(),
            revision: state.revision,
            role: grant.role,
            scope: scope.clone(),
            principal: principal.clone(),
            method,
            class,
        })
    }
    pub(super) fn authorize_startup(
        &self,
        principal: &SpiffeId,
        issuer: &SpiffeId,
        scope: &ScopeBinding,
        method: Method,
        class: Class,
    ) -> Result<RoutedCall, PolicyError> {
        if principal != issuer || !method.is_startup() || class != Class::SafetyControl {
            return Err(PolicyError::Unauthorized);
        }
        let mut routed = self.authorize(principal, scope, Method::Current, class)?;
        if routed.role != ScopeRole::Controller {
            return Err(PolicyError::Unauthorized);
        }
        routed.method = method;
        Ok(routed)
    }
}
/// Routing permission only; it cannot create a verified boot or committed authority.
pub(super) struct RoutedCall {
    policy: ScopePolicy,
    revision: u64,
    pub(super) role: ScopeRole,
    pub(super) scope: ScopeBinding,
    pub(super) principal: SpiffeId,
    pub(super) method: Method,
    pub(super) class: Class,
}
impl RoutedCall {
    pub(super) fn requires_worker_proof(&self) -> bool {
        self.role == ScopeRole::Worker
    }
    pub(super) fn revalidate(&self) -> Result<(), PolicyError> {
        let state = self.policy.0.lock().map_err(|_| PolicyError::Changed)?;
        if state.revision != self.revision {
            return Err(PolicyError::Changed);
        }
        Ok(())
    }
}
