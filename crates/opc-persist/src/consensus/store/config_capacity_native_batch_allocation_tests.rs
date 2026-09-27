//! Native codec allocation observation with genuine encrypted record proofs.
//! This does not establish retained reopen or multi-node qualification.

use super::*;

#[test]
fn capacity_native_small_record_batch_has_proportional_envelope_allocations() {
    let source = entry(EntryPayload::Normal(command(1024)));
    let encoded = serde_json::to_vec(&source).unwrap();
    let mut decoded = Vec::with_capacity(64);
    for _ in 0..64 {
        let value = engine::native_entry(PROFILE, &encoded).unwrap();
        assert_eq!(serde_json::to_vec(&value).unwrap(), encoded);
        let EntryPayload::Normal(command) = &value.payload else {
            unreachable!()
        };
        command
            .intent
            .validate_capacity(identity(), &key(), PROFILE)
            .unwrap();
        decoded.push(value);
    }
    let mut initialized = 0usize;
    let mut allocated = 0usize;
    for value in &decoded {
        let EntryPayload::Normal(command) = &value.payload else {
            unreachable!()
        };
        let ConfigMutationIntent::BoundedAppend { commit, .. } = &command.intent else {
            unreachable!()
        };
        initialized += commit.record.encrypted_blob.len();
        allocated += commit.record.encrypted_blob.capacity();
        assert_eq!(commit.audit.capacity(), 0);
    }
    eprintln!(
        "config capacity native decoder: records=64 initialized_envelope_bytes={initialized} allocated_envelope_bytes={allocated}"
    );
    assert!(initialized < 256 * 1024, "small genuine native records");
    assert!(
        allocated <= initialized + 64 * 4095,
        "live native decoding must not reserve a maximum envelope for each small record"
    );
    std::hint::black_box(decoded);
}
