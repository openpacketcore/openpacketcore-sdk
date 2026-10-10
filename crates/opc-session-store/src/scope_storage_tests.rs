use super::*;
use crate::scope_authority::ScopeIncarnation;
use opc_consensus::{derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch};
use opc_types::{NetworkFunctionKind, TenantId};

#[test]
fn scope_scan_prefix_classification_reads_only_the_bounded_namespace_header() {
    use crate::scope_batch::{tests::key, ScopeChildRevision, ScopeSealedValue};
    let namespace = ScopeNamespace::new(
        crate::scope_authority::tests::scope(),
        ScopeIncarnation::new(1).unwrap(),
    )
    .unwrap();
    let small = crate::scope_batch::tests::value(1);
    let mut envelope = opc_crypto::CryptoEnvelopeV1::decode(small.envelope()).unwrap();
    let overhead = small.envelope().len() - envelope.ciphertext_and_tag.len();
    envelope
        .ciphertext_and_tag
        .resize(MAX_SCOPE_CHILD_VALUE_BYTES - overhead, 1);
    let records = [
        ScopeRow::Child(ScopeChildRecord {
            namespace: namespace.clone(),
            key: key(1),
            revision: ScopeChildRevision::new(1, 1).unwrap(),
            batch_revision: 1,
            value: Some(ScopeSealedValue::new(envelope.encode().unwrap()).unwrap()),
            claims: vec![],
        })
        .to_record()
        .unwrap(),
        ScopeRow::Claim(ClaimRow {
            namespace,
            key: crate::scope_batch::tests::claim(1),
            revision: 1,
            owner: None,
        })
        .to_record()
        .unwrap(),
    ];
    for record in records {
        let stable = record.key.stable_id.as_ref();
        let mut damaged = stable.to_vec();
        damaged[0] ^= 1;
        let allocation = allocation_counter::measure(|| {
            assert!(!scope_scan_prefix_mismatch(
                stable,
                record.payload.as_bytes()
            ));
            assert!(scope_scan_prefix_mismatch(
                &damaged,
                record.payload.as_bytes()
            ));
            assert!(scope_scan_prefix_mismatch(
                &damaged[..48],
                record.payload.as_bytes()
            ));
        });
        assert!(
            allocation.bytes_total < 16 * 1024,
            "header-only decoding: {allocation:?}"
        );
        for payload in [
            b"".as_slice(),
            b"OPSC\x03\x01",
            b"OPSC\x04\x01",
            b"OPSC\x04\x00",
        ] {
            assert!(!scope_scan_prefix_mismatch(&damaged, payload));
        }
        assert!(!scope_scan_prefix_mismatch(
            &damaged[..31],
            record.payload.as_bytes()
        ));
    }
}

#[test]
fn namespace_keys_retain_frozen_a64_vectors() {
    // Synthetic RFC026-shaped scope. Expected bytes are independently frozen,
    // not recomputed with a second implementation of the storage hash.
    let cluster = ConsensusClusterId::from_bytes([0x11; 32]);
    let epoch = ConsensusConfigurationEpoch::new(1).unwrap();
    let scope = ScopeId::new(
        crate::SessionConsensusIdentity::new(
            cluster,
            derive_configuration_id(cluster, epoch, &[[1; 32]]),
            epoch,
        ),
        TenantId::new("example").unwrap(),
        NetworkFunctionKind::new("worker").unwrap(),
        [0x22; 32],
    )
    .unwrap();
    for (incarnation, expected_prefix) in [
        (
            1,
            "989227163b8dbc3a1611baa0ba43afda55e740420ed8c95be6ee1127060fe401",
        ),
        (
            2,
            "a032025ad8dcfbb67028e39b67d2f51093835b424c115b17045c0d2e105b625e",
        ),
        (
            128,
            "500d355356dc9e18bba2c9e8e7f2177077ff94c0a1aa33b6fbf24721382756f4",
        ),
    ] {
        let namespace =
            ScopeNamespace::new(scope.clone(), ScopeIncarnation::new(incarnation).unwrap())
                .unwrap();
        let expected_prefix = hex::decode(expected_prefix).unwrap();
        assert_eq!(
            namespace_prefix(&namespace).unwrap().as_slice(),
            expected_prefix
        );
        let child = child_key(&namespace, ScopeChildKey::new([0x55; 32]).unwrap()).unwrap();
        let claim = claim_key(&namespace, ScopeClaimKey::new([0x55; 32]).unwrap()).unwrap();
        for key in [&child, &claim] {
            assert_eq!(key.tenant, *scope.tenant());
            assert_eq!(key.nf_kind, *scope.nf_kind());
            assert_eq!(key.stable_id.as_bytes().len(), 64);
            assert_eq!(&key.stable_id.as_bytes()[..32], expected_prefix);
            assert_eq!(&key.stable_id.as_bytes()[32..], [0x55; 32]);
        }
        assert_eq!(child.key_type.as_str(), "opc-scope-child");
        assert_eq!(claim.key_type.as_str(), "opc-scope-claim");
        assert_ne!(child, claim);
    }
}
