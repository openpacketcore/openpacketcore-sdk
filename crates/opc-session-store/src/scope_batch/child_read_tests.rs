use super::*;

#[test]
fn child_read_request_preserves_order_and_exact_wire_bytes() {
    let state = State::new();
    let stamp = state.authority.view.stamp().unwrap();
    for count in [1, 17, 32] {
        let keys: Vec<_> = (1..=count).rev().map(key).collect();
        let request = ScopeChildReadRequest::new(stamp, keys.clone()).unwrap();
        let stamp_bytes = stamp.encode_canonical().unwrap();
        let mut expected = (stamp_bytes.len() as u16).to_be_bytes().to_vec();
        expected.extend_from_slice(&stamp_bytes);
        expected.push(count);
        for child in &keys {
            expected.extend_from_slice(child.as_bytes());
        }
        assert_eq!(request.encode_canonical().unwrap(), expected);
        let restored = ScopeChildReadRequest::decode_canonical(&expected).unwrap();
        assert_eq!(restored.stamp(), stamp);
        assert_eq!(restored.keys(), keys);
    }
}

#[test]
fn child_read_rejects_invalid_sets_from_constructors_and_raw_peers() {
    let state = State::new();
    let stamp = state.authority.view.stamp().unwrap();
    for keys in [
        vec![],
        vec![key(1), key(1)],
        vec![ScopeChildKey([0; 32])],
        (1..=33).map(key).collect(),
    ] {
        assert_eq!(
            ScopeChildReadRequest::new(stamp, keys.clone()).err(),
            Some(ScopeBatchError::InvalidRequest)
        );
        let stamp_bytes = stamp.encode_canonical().unwrap();
        let mut raw = (stamp_bytes.len() as u16).to_be_bytes().to_vec();
        raw.extend_from_slice(&stamp_bytes);
        raw.push(keys.len() as u8);
        for child in keys {
            raw.extend_from_slice(child.as_bytes());
        }
        assert_eq!(
            ScopeChildReadRequest::decode_canonical(&raw).err(),
            Some(ScopeBatchError::InvalidRequest)
        );
    }
    let bytes = ScopeChildReadRequest::new(stamp, vec![key(1)])
        .unwrap()
        .encode_canonical()
        .unwrap();
    for end in 0..bytes.len() {
        assert!(ScopeChildReadRequest::decode_canonical(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(ScopeChildReadRequest::decode_canonical(&trailing).is_err());
    let mut oversized = bytes;
    oversized[..2].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(ScopeChildReadRequest::decode_canonical(&oversized).is_err());
}

#[test]
fn child_read_record_canonical_bytes_include_every_metadata_field() {
    let mut state = State::new();
    let outcome = state
        .apply(&state.command(1, vec![create(1, &[2, 3])]))
        .unwrap();
    let row = state.child(1).unwrap();
    assert_eq!(row.batch_revision(), outcome.revision());
    let bytes = row.encode_canonical().unwrap();
    assert_eq!(bytes, postcard::to_allocvec(row).unwrap());
    let decoded = ScopeChildRecord::decode_canonical(&bytes).unwrap();
    assert!(decoded == *row);
    assert_eq!(decoded.namespace(), outcome_namespace(&state));
    assert_eq!(decoded.key(), key(1));
    assert_eq!(decoded.revision(), outcome.rows()[0]);
    assert_eq!(decoded.claims(), &[claim(2), claim(3)]);
    assert_eq!(decoded.value(), Some(&value(1)));
}

fn outcome_namespace(state: &State) -> &crate::scope_authority::ScopeNamespace {
    state.authority.view.stamp().unwrap().namespace()
}

#[test]
fn child_read_record_rejects_noncanonical_invalid_and_deleted_records() {
    let mut state = State::new();
    state
        .apply(&state.command(1, vec![create(1, &[2])]))
        .unwrap();
    let row = state.child(1).unwrap();
    for field in 0..9 {
        let mut invalid = row.clone();
        match field {
            0 => invalid.revision.birth = 0,
            1 => invalid.revision.generation = 0,
            2 => invalid.batch_revision = 0,
            3 => invalid.batch_revision = u64::MAX,
            4 => invalid.claims = vec![claim(2), claim(2)],
            5 => invalid.claims = (1..=9).map(claim).collect(),
            6 => invalid.claims = vec![ScopeClaimKey([0; 32])],
            7 => invalid.value = None,
            _ => invalid.value = Some(ScopeSealedValue(vec![0; 8])),
        }
        assert!(invalid.encode_canonical().is_err(), "field {field}");
        let raw = postcard::to_allocvec(&invalid).unwrap();
        assert!(
            ScopeChildRecord::decode_canonical(&raw).is_err(),
            "raw field {field}"
        );
    }
    let mut bytes = row.encode_canonical().unwrap();
    bytes.push(0);
    assert!(ScopeChildRecord::decode_canonical(&bytes).is_err());
    assert!(
        ScopeChildRecord::decode_canonical(&vec![0; MAX_SCOPE_CHILD_VALUE_BYTES + 8193]).is_err()
    );
}

#[test]
fn child_read_transport_mismatch_never_has_a_canonical_store_error_tag() {
    let mismatch = ScopeBatchError::TransportRevisionMismatch;
    assert_eq!(
        mismatch.encode_canonical(),
        Err(ScopeBatchError::InvalidRequest)
    );
    assert!(postcard::to_allocvec(&mismatch).is_err());
    assert!(serde_json::to_vec(&mismatch).is_err());
}
