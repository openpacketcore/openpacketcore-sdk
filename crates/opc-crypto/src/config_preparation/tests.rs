use super::*;

#[test]
fn shared_lifetime_owner_preserves_destination_identity_until_final_lease() {
    let owner = Arc::new(());
    let alive = Arc::downgrade(&owner);
    let destination = ConfigPreparationPool::bounded_v1_with_owner(owner.clone());
    let other = ConfigPreparationPool::bounded_v1_with_owner(owner);
    let reservation = destination.try_reserve().expect("destination reservation");
    assert!(destination.owns(&reservation));
    assert!(
        !other.owns(&reservation),
        "sharing a lifetime owner cannot authorize a foreign reservation"
    );
    drop(destination);
    drop(other);
    assert!(
        alive.upgrade().is_some(),
        "last reservation owns the lifetime"
    );
    drop(reservation);
    assert!(alive.upgrade().is_none(), "no cycle retains the owner");
}
