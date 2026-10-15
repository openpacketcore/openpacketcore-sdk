//! Independent non-testkit-capable initiator composition vector.
//! @spec IETF RFC7296 2.14, 2.15, 2.16
//! @req REQ-IETF-RFC7296-SA-INIT-INITIATOR-COMPOSITION-001

#[path = "sa_init_initiator/composition.rs"]
mod composition;

#[test]
fn independent_vector_covers_dh_keys_both_auth_directions_and_eap_msk() {
    composition::run();
}
