use super::{policy::*, wire::*};
use opc_types::{NetworkFunctionKind, SpiffeId, TenantId};

fn scope(slot: u8) -> ScopeBinding {
    ScopeBinding::new(
        [1; 32],
        TenantId::new("example").unwrap(),
        NetworkFunctionKind::new("worker").unwrap(),
        [slot; 32],
    )
    .unwrap()
}
fn identity(name: &str) -> SpiffeId {
    SpiffeId::new(format!(
        "spiffe://example.test/tenant/example/ns/example/sa/{name}/nf/smf/instance/{name}-0"
    ))
    .unwrap()
}
fn policy() -> ScopePolicy {
    ScopePolicy::new(vec![
        PrincipalGrant::new(identity("worker"), ScopeRole::Worker, vec![scope(1)]).unwrap(),
        PrincipalGrant::new(
            identity("controller"),
            ScopeRole::Controller,
            vec![scope(1), scope(2)],
        )
        .unwrap(),
        PrincipalGrant::new(identity("observer"), ScopeRole::Observer, vec![scope(1)]).unwrap(),
    ])
    .unwrap()
}

#[test]
fn controller_and_observer_are_read_only_before_body_or_challenge_admission() {
    let policy = policy();
    for role in ["controller", "observer"] {
        for method in [Method::Current, Method::Outcome] {
            let permit = policy
                .authorize(&identity(role), &scope(1), method, Class::SafetyControl)
                .unwrap();
            assert!(!permit.requires_worker_proof());
        }
        for method in [
            Method::AdmitInitial,
            Method::SucceedClosed,
            Method::Close,
            Method::ApplyBatch,
            Method::Liveness,
            Method::Candidate,
        ] {
            assert!(policy
                .authorize(&identity(role), &scope(1), method, Class::SafetyControl)
                .is_err());
        }
    }
}

#[test]
fn worker_scope_grants_and_typed_classification_are_checked_before_reserving_a_proof() {
    let policy = policy();
    for method in [
        Method::AdmitInitial,
        Method::SucceedClosed,
        Method::Close,
        Method::Current,
        Method::Outcome,
    ] {
        let permit = policy
            .authorize(&identity("worker"), &scope(1), method, Class::SafetyControl)
            .unwrap();
        assert!(permit.requires_worker_proof());
        assert!(policy
            .authorize(&identity("worker"), &scope(2), method, Class::SafetyControl)
            .is_err());
        assert!(policy
            .authorize(&identity("worker"), &scope(1), method, Class::Normal)
            .is_err());
    }
    assert!(policy
        .authorize(
            &identity("worker"),
            &scope(1),
            Method::ApplyBatch,
            Class::SafetyControl
        )
        .is_err());
    for class in [
        Class::Emergency,
        Class::EmergencyClassification,
        Class::Normal,
        Class::Maintenance,
    ] {
        assert!(policy
            .authorize(&identity("worker"), &scope(1), Method::ApplyBatch, class)
            .is_ok());
    }
    assert!(policy
        .authorize(
            &identity("stranger"),
            &scope(1),
            Method::Current,
            Class::SafetyControl
        )
        .is_err());
}

#[test]
fn a_live_policy_replacement_invalidates_an_already_routed_call() {
    let policy = policy();
    let routed = policy
        .authorize(
            &identity("worker"),
            &scope(1),
            Method::Close,
            Class::SafetyControl,
        )
        .unwrap();
    routed.revalidate().unwrap();
    policy.replace(vec![]).unwrap();
    assert_eq!(routed.revalidate().unwrap_err(), PolicyError::Changed);
    assert!(policy
        .authorize(
            &identity("worker"),
            &scope(1),
            Method::Close,
            Class::SafetyControl
        )
        .is_err());
}

#[test]
fn one_worker_identity_routes_each_explicit_slot_and_requires_its_own_proof() {
    let policy = ScopePolicy::new(vec![PrincipalGrant::new(
        identity("worker"),
        ScopeRole::Worker,
        vec![scope(1), scope(2)],
    )
    .expect("one transport identity may hold several explicit slot grants")])
    .unwrap();
    for binding in [scope(1), scope(2)] {
        assert_eq!(
            policy
                .resolve_scope(
                    &identity("worker"),
                    binding.installation(),
                    &binding.commitment()
                )
                .unwrap(),
            binding
        );
        for method in [
            Method::AdmitInitial,
            Method::SucceedClosed,
            Method::Close,
            Method::Current,
            Method::Outcome,
        ] {
            let route = policy
                .authorize(&identity("worker"), &binding, method, Class::SafetyControl)
                .unwrap();
            assert!(
                route.requires_worker_proof(),
                "a slot grant alone never admits a worker"
            );
            route.revalidate().unwrap();
        }
    }
    assert!(policy
        .resolve_scope(
            &identity("worker"),
            scope(3).installation(),
            &scope(3).commitment()
        )
        .is_err());
    assert!(policy
        .resolve_scope(&identity("worker"), &[9; 32], &scope(1).commitment())
        .is_err());
    assert!(policy
        .authorize(
            &identity("worker"),
            &scope(3),
            Method::Close,
            Class::SafetyControl
        )
        .is_err());
}

#[test]
fn worker_grants_reject_empty_duplicate_scopes_and_ambiguous_roles() {
    assert!(PrincipalGrant::new(identity("worker"), ScopeRole::Worker, vec![]).is_err());
    assert!(PrincipalGrant::new(
        identity("worker"),
        ScopeRole::Worker,
        vec![scope(1), scope(1)]
    )
    .is_err());
    assert!(ScopePolicy::new(vec![
        PrincipalGrant::new(identity("worker"), ScopeRole::Worker, vec![scope(1)]).unwrap(),
        PrincipalGrant::new(identity("worker"), ScopeRole::Controller, vec![scope(1)]).unwrap(),
    ])
    .is_err());
}
