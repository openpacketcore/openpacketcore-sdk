use super::super::{ScopeBatchError, ScopeChildKey, ScopeChildRevision, ScopeClaimKey};
use super::*;

fn child(n: u8) -> ScopeChildKey {
    ScopeChildKey::new([n; 32]).unwrap()
}

fn claim(n: u8) -> ScopeClaimKey {
    ScopeClaimKey::new([n; 32]).unwrap()
}

// Matching only the key or generation lets delete/recreate recycle a read.
#[test]
fn child_condition_requires_the_exact_live_key_birth_and_generation() {
    let version = ScopeChildRevision::new(5, 6).unwrap();
    let condition = ScopeChildCondition::new(child(1), version).unwrap();
    assert!(condition.matches(child(1), Some(version)));
    assert!(!condition.matches(child(2), Some(version)));
    assert!(!condition.matches(child(1), None));
    assert!(!condition.matches(child(1), Some(ScopeChildRevision::new(5, 7).unwrap())));
    assert!(!condition.matches(child(1), Some(ScopeChildRevision::new(6, 6).unwrap())));
}

// A release or ownership cycle can repeat the owner, but never the revision.
#[test]
fn claim_condition_requires_revision_and_exact_owner_birth() {
    let owner = ScopeClaimOwner::new(child(1), 5).unwrap();
    let condition = ScopeClaimCondition::new(claim(3), 9, Some(owner)).unwrap();
    assert!(condition.matches(claim(3), Some(9), Some(owner)));
    assert!(!condition.matches(claim(4), Some(9), Some(owner)));
    assert!(!condition.matches(claim(3), Some(10), Some(owner)));
    assert!(!condition.matches(claim(3), Some(9), None));
    assert!(!condition.matches(
        claim(3),
        Some(9),
        Some(ScopeClaimOwner::new(child(1), 6).unwrap())
    ));
    assert!(!condition.matches(
        claim(3),
        Some(9),
        Some(ScopeClaimOwner::new(child(2), 5).unwrap())
    ));
}

// Treating an absent claim as Released removes the versioned absence fence.
#[test]
fn released_claim_condition_does_not_match_missing_or_recreated_rows() {
    let condition = ScopeClaimCondition::new(claim(1), 7, None).unwrap();
    assert!(condition.matches(claim(1), Some(7), None));
    assert!(!condition.matches(claim(1), None, None));
    assert!(!condition.matches(claim(1), Some(8), None));
    assert!(!condition.matches(
        claim(1),
        Some(7),
        Some(ScopeClaimOwner::new(child(2), 3).unwrap())
    ));
}

// Derived serde fields can bypass checked key/version constructors.
#[test]
fn condition_validation_refuses_forged_zero_keys_and_nonpositive_floors() {
    let zero_child: ScopeChildKey =
        serde_json::from_value(serde_json::json!(vec![0u8; 32])).unwrap();
    let zero_claim: ScopeClaimKey =
        serde_json::from_value(serde_json::json!(vec![0u8; 32])).unwrap();
    let zero_birth: ScopeChildRevision = serde_json::from_value(serde_json::json!({
        "birth": 0, "generation": 1
    }))
    .unwrap();
    assert_eq!(
        ScopeChildCondition::new(zero_child, ScopeChildRevision::new(1, 1).unwrap()),
        Err(ScopeBatchError::InvalidRequest)
    );
    assert_eq!(
        ScopeChildCondition::new(child(1), zero_birth),
        Err(ScopeBatchError::InvalidRequest)
    );
    assert_eq!(
        ScopeClaimOwner::new(zero_child, 1),
        Err(ScopeBatchError::InvalidRequest)
    );
    assert_eq!(
        ScopeClaimOwner::new(child(1), 0),
        Err(ScopeBatchError::InvalidRequest)
    );
    assert_eq!(
        ScopeClaimOwner::new(child(1), u64::MAX),
        Err(ScopeBatchError::InvalidRequest)
    );
    for revision in [0, u64::MAX] {
        assert_eq!(
            ScopeClaimCondition::new(claim(1), revision, None),
            Err(ScopeBatchError::InvalidRequest)
        );
    }
    assert_eq!(
        ScopeClaimCondition::new(zero_claim, 1, None),
        Err(ScopeBatchError::InvalidRequest)
    );
}

// Changing any comparison must change canonical request bytes downstream.
#[test]
fn predicates_round_trip_exactly_and_serialize_every_compared_field() {
    let a = ScopeChildCondition::new(child(1), ScopeChildRevision::new(2, 3).unwrap()).unwrap();
    let b = ScopeChildCondition::new(child(1), ScopeChildRevision::new(2, 4).unwrap()).unwrap();
    let a_bytes = postcard::to_allocvec(&a).unwrap();
    assert_eq!(
        postcard::from_bytes::<ScopeChildCondition>(&a_bytes).unwrap(),
        a
    );
    assert_ne!(a_bytes, postcard::to_allocvec(&b).unwrap());
    let owner = ScopeClaimOwner::new(child(1), 2).unwrap();
    let held = ScopeClaimCondition::new(claim(3), 4, Some(owner)).unwrap();
    let released = ScopeClaimCondition::new(claim(3), 4, None).unwrap();
    let changed = ScopeClaimCondition::new(claim(3), 5, Some(owner)).unwrap();
    let bytes = postcard::to_allocvec(&held).unwrap();
    assert_eq!(
        postcard::from_bytes::<ScopeClaimCondition>(&bytes).unwrap(),
        held
    );
    assert_ne!(bytes, postcard::to_allocvec(&released).unwrap());
    assert_ne!(bytes, postcard::to_allocvec(&changed).unwrap());
}

#[test]
fn deserialized_invalid_conditions_are_refused_before_comparison() {
    let forged: ScopeChildCondition = serde_json::from_value(serde_json::json!({
        "key": vec![1u8; 32], "expected": {"birth": 0, "generation": 1}
    }))
    .unwrap();
    assert_eq!(forged.validate(), Err(ScopeBatchError::InvalidRequest));
    let forged: ScopeClaimCondition = serde_json::from_value(serde_json::json!({
        "key": vec![1u8; 32], "revision": 1, "owner": {"child": vec![2u8; 32], "birth": 0}
    }))
    .unwrap();
    assert_eq!(forged.validate(), Err(ScopeBatchError::InvalidRequest));
}
