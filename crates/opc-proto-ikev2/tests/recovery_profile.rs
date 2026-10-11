//! Public recovery composition, checked by an independent packet-driven peer.

#[path = "recovery_profile/admission.rs"]
mod admission;
#[path = "recovery_profile/authority.rs"]
mod authority;
#[path = "support/canonical.rs"]
mod canonical_fixtures;
#[path = "recovery_profile/cbc.rs"]
mod cbc;
#[path = "recovery_profile/codec.rs"]
mod codec;
#[path = "recovery_profile/codec_tests.rs"]
mod codec_tests;
#[path = "recovery_profile/crash.rs"]
mod crash;
#[path = "recovery_profile/driver.rs"]
mod driver;
#[path = "recovery_profile/envelope.rs"]
mod envelope;
#[path = "recovery_profile/foundation.rs"]
mod foundation;
#[path = "recovery_profile/initial_contact.rs"]
mod initial_contact;
#[path = "recovery_profile/inputs.rs"]
mod inputs;
#[path = "recovery_profile/ke.rs"]
mod ke;
#[path = "recovery_profile/lifecycle.rs"]
mod lifecycle;
#[path = "recovery_profile/module.rs"]
mod module;
#[path = "recovery_profile/peer.rs"]
mod peer;
#[path = "recovery_profile/records.rs"]
mod records;
#[path = "recovery_profile/row.rs"]
mod row;
#[path = "recovery_profile/shapes.rs"]
mod shapes;
#[path = "recovery_profile/store.rs"]
mod store;
mod support {
    pub fn ensure_ike_crypto() {
        crate::module::install();
    }
}
#[path = "recovery_profile/wire.rs"]
mod wire;

#[path = "recovery_profile/auth.rs"]
mod auth;

#[path = "recovery_profile/auth_process.rs"]
mod auth_process;

#[path = "recovery_profile/checkpoint_tests.rs"]
mod checkpoint_tests;

#[path = "recovery_profile/peer_ke_tests.rs"]
mod peer_ke_tests;

#[path = "recovery_profile/effects.rs"]
mod effects;

#[path = "recovery_profile/effect_tests.rs"]
mod effect_tests;

#[path = "recovery_profile/iv_process.rs"]
mod iv_process;

#[path = "recovery_profile/peer_epochs.rs"]
mod peer_epochs;

#[path = "recovery_profile/handoff.rs"]
mod handoff;

#[path = "recovery_profile/handoff_tests.rs"]
mod handoff_tests;

#[path = "recovery_profile/child_owners.rs"]
mod child_owners;

#[path = "recovery_profile/crossed_tests.rs"]
mod crossed_tests;

#[path = "recovery_profile/handoff_process.rs"]
mod handoff_process;

#[path = "recovery_profile/sync_driver.rs"]
mod sync_driver;

#[path = "recovery_profile/sync_tests.rs"]
mod sync_tests;

#[path = "recovery_profile/sync_process.rs"]
mod sync_process;

#[path = "recovery_profile/remedy.rs"]
mod remedy;

#[path = "recovery_profile/remedy_tests.rs"]
mod remedy_tests;

#[path = "recovery_profile/endpoint.rs"]
mod endpoint;

#[path = "recovery_profile/endpoint_tests.rs"]
mod endpoint_tests;

#[path = "recovery_profile/contact.rs"]
mod contact;

#[path = "recovery_profile/contact_tests.rs"]
mod contact_tests;

#[path = "recovery_profile/terminal_process.rs"]
mod terminal_process;
