use super::*;

fn n3(group: &GtpuSessionGroup, qfi: u8) -> GtpuSessionGroup {
    GtpuSessionGroup::new(
        group.id(),
        group.device_id(),
        group
            .entries()
            .iter()
            .cloned()
            .map(|entry| entry.restore_n3_qfi(qfi).unwrap())
            .collect(),
    )
    .unwrap()
}

#[test]
fn n3_desired_descriptor_binds_qfi_without_changing_selector_atoms() {
    let legacy = group(1, 2, 10, Some(40));
    let old = canonical_desired_bytes(&legacy);
    assert_eq!(old[0], 1);
    assert_eq!(decode_canonical_desired(&old).unwrap(), legacy);
    for qfi in 0..64 {
        let candidate = n3(&legacy, qfi);
        let encoded = canonical_desired_bytes(&candidate);
        assert_eq!(encoded[0], 2);
        assert_eq!(encoded.last(), Some(&qfi));
        assert_eq!(decode_canonical_desired(&encoded).unwrap(), candidate);
        let key = [0x4e; 32]; // Synthetic namespace key, never an operator secret.
        let a = CanonicalClaim::from_group(&legacy).with_key(&key).unwrap();
        let b = CanonicalClaim::from_group(&candidate)
            .with_key(&key)
            .unwrap();
        assert_eq!(a.atoms, b.atoms);
        assert_ne!(a.desired_fingerprint, b.desired_fingerprint);
        assert_ne!(
            b.desired_fingerprint,
            CanonicalClaim::from_group(&n3(&legacy, (qfi + 1) % 64))
                .with_key(&key)
                .unwrap()
                .desired_fingerprint
        );
        for bad in 64..=255 {
            let mut mutation = encoded.clone();
            *mutation.last_mut().unwrap() = bad;
            assert!(decode_canonical_desired(&mutation).is_none());
        }
        let mut no_version = encoded;
        no_version[0] = 1;
        assert!(decode_canonical_desired(&no_version).is_none());
    }
}

#[test]
fn teid_only_transition_cannot_change_n3_profile_or_qfi() {
    let original = group(1, 2, 10, Some(40));
    let replacement = group_with_paa(
        2,
        2,
        20,
        original.entries()[0].context().ms_address,
        Some(40),
    );
    assert!(single_bearer_reattach_is_exact(&original, &replacement));
    assert!(single_bearer_reattach_is_exact(
        &n3(&original, 9),
        &n3(&replacement, 9)
    ));
    assert!(!single_bearer_reattach_is_exact(
        &original,
        &n3(&replacement, 9)
    ));
    assert!(!single_bearer_reattach_is_exact(
        &n3(&original, 9),
        &replacement
    ));
    assert!(!single_bearer_reattach_is_exact(
        &n3(&original, 9),
        &n3(&replacement, 10)
    ));
}
