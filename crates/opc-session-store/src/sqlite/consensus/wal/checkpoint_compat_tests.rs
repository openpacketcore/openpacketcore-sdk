use super::*;

fn anchor_fixture(mode: SessionPersistenceMode) -> (Binding, Anchor) {
    let binding = Binding {
        identity: SessionConsensusIdentity::new(
            crate::consensus::SessionConsensusClusterId::new("checkpoint-format-contract").unwrap(),
            crate::consensus::SessionConsensusConfigurationId::from_bytes([0x61; 32]),
            crate::consensus::SessionConsensusConfigurationEpoch::new(1).unwrap(),
        ),
        generation: [0x62; 32],
        basis: [0x63; 32],
        native: true,
        persistence: mode,
        async_closed_format: mode == SessionPersistenceMode::Async,
        async_recovery_format: mode == SessionPersistenceMode::Async,
    };
    let position = if mode == SessionPersistenceMode::Async {
        CutPosition::initial()
    } else {
        CutPosition {
            segment: 3,
            offset: SEGMENT_HEADER as u64 + 128,
            sequence: 19,
            chain: [0x64; 32],
        }
    };
    let anchor = Anchor {
        root: binding.digest().unwrap(),
        epoch: 100,
        basis: [0x65; 32],
        basis_bytes: 64 * 1024,
        position,
        cut: if mode == SessionPersistenceMode::Async {
            0
        } else {
            9
        },
        cut_chain: if mode == SessionPersistenceMode::Async {
            [0; 32]
        } else {
            [0x66; 32]
        },
        prefix: [0x67; 32],
        applied: None,
        marker: None,
        cuts: [(
            position.sequence,
            DurableCut {
                chain: position.chain,
                committed: None,
                installed: None,
            },
        )]
        .into(),
        native: true,
        native_generation: Some(NativeGeneration {
            file_epoch: 7,
            block_bytes: 64 * 1024,
            frontiers: [0x68; 32],
        }),
        native_snapshots: None,
        async_cut: (mode == SessionPersistenceMode::Async).then_some(AsyncCut {
            generation: 12,
            sequence: 29,
            committed: None,
            applied: None,
        }),
    };
    anchor.validate(binding, Limits::default()).unwrap();
    (binding, anchor)
}

#[test]
fn native_selector_reselects_the_same_logical_cut_in_a_new_file_at_a_higher_epoch() {
    for mode in [
        SessionPersistenceMode::Durable,
        SessionPersistenceMode::Async,
    ] {
        let (binding, original) = anchor_fixture(mode);
        let directory = tempfile::tempdir().unwrap();
        select(directory.path(), &original, &IoControl::default()).unwrap();
        assert_eq!(
            read(directory.path(), binding, Limits::default()).unwrap(),
            Some(original.clone())
        );
        let mut next = original.clone();
        next.epoch += 1;
        next.native_generation.as_mut().unwrap().file_epoch += 1;
        next.basis = [0x69; 32];
        next.validate(binding, Limits::default()).unwrap();
        assert_eq!(next.position, original.position);
        assert_eq!(next.async_cut, original.async_cut);
        assert_eq!(next.native_sequence(), original.native_sequence());
        assert_ne!(
            next.native_cut_binding().unwrap(),
            original.native_cut_binding().unwrap()
        );
        select(directory.path(), &next, &IoControl::default()).unwrap();
        assert_eq!(
            read(directory.path(), binding, Limits::default()).unwrap(),
            Some(next.clone())
        );
        next.native_generation.as_mut().unwrap().file_epoch = next.epoch + 1;
        assert_eq!(
            next.validate(binding, Limits::default())
                .unwrap_err()
                .to_string(),
            "native generation selector lineage differs"
        );
    }
}

#[test]
fn native_checkpoint_namespace_reclaims_one_next_and_two_previous_files_in_any_order() {
    let (_, anchor) = anchor_fixture(SessionPersistenceMode::Durable);
    let names = [
        "basis-00000000000000000005.native",
        "basis-00000000000000000006.native",
        "basis-00000000000000000007.native",
        "basis-00000000000000000008.preparing",
    ];
    for first in 0..4 {
        for second in 0..4 {
            if second == first {
                continue;
            }
            for third in 0..4 {
                if third == first || third == second {
                    continue;
                }
                let fourth = (0..4)
                    .find(|n| *n != first && *n != second && *n != third)
                    .unwrap();
                let directory = tempfile::tempdir().unwrap();
                for name in names {
                    std::fs::write(directory.path().join(name), [1]).unwrap();
                }
                let mut namespace = Namespace::default();
                let mut retired = Vec::new();
                for i in [first, second, third, fourth] {
                    assert!(namespace
                        .visit(
                            names[i],
                            directory.path().join(names[i]),
                            1,
                            Some(&anchor),
                            &mut retired
                        )
                        .unwrap());
                }
                assert_eq!(retired.len(), 3);
                assert!(!retired.contains(&directory.path().join(names[2])));
                reclaim(directory.path(), &retired, &IoControl::default()).unwrap();
                for (i, name) in names.into_iter().enumerate() {
                    assert_eq!(directory.path().join(name).exists(), i == 2);
                }
            }
        }
    }
}

#[test]
fn native_checkpoint_namespace_refuses_a_third_previous_or_second_next_file() {
    let (_, anchor) = anchor_fixture(SessionPersistenceMode::Durable);
    for extra in [
        "basis-00000000000000000004.native",
        "basis-00000000000000000008.native",
    ] {
        let mut namespace = Namespace::default();
        let mut retired = Vec::new();
        for name in [
            "basis-00000000000000000005.native",
            "basis-00000000000000000006.native",
            "basis-00000000000000000007.native",
            "basis-00000000000000000008.preparing",
        ] {
            namespace
                .visit(name, PathBuf::from(name), 1, Some(&anchor), &mut retired)
                .unwrap();
        }
        assert_eq!(
            namespace
                .visit(extra, PathBuf::from(extra), 1, Some(&anchor), &mut retired)
                .unwrap_err()
                .to_string(),
            "private WAL basis namespace exceeds file bounds"
        );
    }
}
