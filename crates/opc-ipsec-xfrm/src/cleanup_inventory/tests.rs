use super::{
    codec::{decode_record, encode_record},
    CandidateImage, CleanupImage, CoverageMember, CoverageRecord, InventoryRecord, ObjectPhase,
    ObjectRecord, RecordLink, TransactionFamily, CANDIDATES_PER_OBJECT, COVERAGE_MEMBERS,
    POLICY_TEMPLATES,
};
use super::{
    index::{Location, LocatorIndex, LocatorKind},
    node::{open_node, seal_node, InventoryKey, NodeContext, NodeKind},
    InventoryError,
};
use crate::{
    IpAddress, PolicyParameters, SaRelocationIdentity, SaRelocationSelector, UdpEncap, XfrmAction,
    XfrmDirection, XfrmId, XfrmLookupMark, XfrmMark, XfrmMode, XfrmRequestId, XfrmSelector,
    XfrmTemplate,
};

const MEASUREMENT_RECORD_LIMIT: usize = 4096;

fn maximum_sa() -> SaRelocationIdentity {
    SaRelocationIdentity {
        selector: SaRelocationSelector {
            source: IpAddress::Ipv6([0x21; 16]),
            destination: IpAddress::Ipv6([0x22; 16]),
            source_port: 5060,
            source_port_mask: 0xfffe,
            destination_port: 5061,
            destination_port_mask: 0xfffc,
            protocol: 17,
            source_prefix_len: 128,
            destination_prefix_len: 127,
            ifindex: 7,
            user_id: 1000,
        },
        id: XfrmId {
            destination: IpAddress::Ipv6([0x23; 16]),
            spi: 0x1234_5678,
            protocol: 50,
        },
        source_address: IpAddress::Ipv6([0x24; 16]),
        request_id: XfrmRequestId::new(7),
        mode: XfrmMode::Tunnel,
        encap: Some(UdpEncap::esp_in_udp(4500, 4501)),
        mark: Some(XfrmLookupMark::full(17)),
        if_id: Some(19),
        output_mark: Some(XfrmMark {
            value: 23,
            mask: 31,
        }),
    }
}

pub(super) fn maximum_policy() -> PolicyParameters {
    let sa = maximum_sa();
    PolicyParameters {
        selector: XfrmSelector {
            source: sa.selector.source,
            destination: sa.selector.destination,
            source_port: 5060,
            destination_port: 5061,
            protocol: 17,
            source_prefix_len: 128,
            destination_prefix_len: 127,
        },
        direction: XfrmDirection::Out,
        action: XfrmAction::Allow,
        priority: 100,
        templates: vec![
            XfrmTemplate {
                id: sa.id,
                source_address: sa.source_address,
                request_id: sa.request_id,
                mode: sa.mode,
            };
            POLICY_TEMPLATES
        ],
        mark: sa.mark,
        if_id: sa.if_id,
    }
}

pub(super) fn object_record(image: CleanupImage) -> InventoryRecord {
    InventoryRecord::Object(ObjectRecord {
        serial: 1,
        generation: 1,
        phase: ObjectPhase::Indeterminate,
        reserved_images: u8::try_from(CANDIDATES_PER_OBJECT).unwrap(),
        candidates: vec![
            CandidateImage {
                image,
                pre_effect_absence: [0x31; 32],
            };
            CANDIDATES_PER_OBJECT
        ],
        coverage: Some(RecordLink {
            position: 1,
            serial: 2,
        }),
    })
}

fn maximum_coverage() -> InventoryRecord {
    InventoryRecord::Coverage(CoverageRecord {
        serial: 2,
        inventory_generation: 1,
        family: TransactionFamily::Roster,
        store_incarnation: [0x32; 16],
        correlation: [0x33; 16],
        operation_generation: 1,
        request_fingerprint: [0x34; 32],
        members: (0..COVERAGE_MEMBERS)
            .map(|index| CoverageMember {
                object: RecordLink {
                    position: u32::try_from(index).unwrap(),
                    serial: u64::try_from(index + 1).unwrap(),
                },
                absence: Some([0x35; 32]),
            })
            .collect(),
        settlement: Some([0x36; 32]),
    })
}

#[test]
fn record_codec_preserves_maximum_key_free_images_and_coverage() {
    let records = [
        object_record(CleanupImage::Sa {
            identity: maximum_sa(),
            immutable_fingerprint: [0x37; 32],
        }),
        object_record(CleanupImage::Policy(maximum_policy())),
        maximum_coverage(),
    ];
    for (name, record) in ["sa", "policy", "coverage"].into_iter().zip(records) {
        let encoded = encode_record(&record, MEASUREMENT_RECORD_LIMIT).unwrap();
        assert_eq!(
            decode_record(&encoded, MEASUREMENT_RECORD_LIMIT).unwrap(),
            record
        );
        assert_eq!(format!("{record:?}"), "InventoryRecord(<redacted>)");
        println!("record_bytes {name} {}", encoded.len());
    }
}

#[test]
fn record_parser_refuses_every_truncation_and_excess_record_budget() {
    let record = object_record(CleanupImage::Policy(maximum_policy()));
    let encoded = encode_record(&record, MEASUREMENT_RECORD_LIMIT).unwrap();
    for length in 0..encoded.len() {
        assert!(decode_record(&encoded[..length], MEASUREMENT_RECORD_LIMIT).is_err());
    }
    assert!(matches!(
        encode_record(&record, encoded.len() - 1),
        Err(InventoryError::Capacity)
    ));
    assert!(matches!(
        decode_record(&encoded, encoded.len() - 1),
        Err(InventoryError::Capacity)
    ));
    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert!(decode_record(&trailing, MEASUREMENT_RECORD_LIMIT).is_err());
    let mut unknown_version = encoded.to_vec();
    unknown_version[0] = 1;
    assert!(decode_record(&unknown_version, MEASUREMENT_RECORD_LIMIT).is_err());
    let mut unknown_kind = encoded.to_vec();
    unknown_kind[1] = u8::MAX;
    assert!(decode_record(&unknown_kind, MEASUREMENT_RECORD_LIMIT).is_err());
}

#[test]
fn one_lifecycle_cannot_mix_sa_and_policy_candidates() {
    let mut record = object_record(CleanupImage::Policy(maximum_policy()));
    if let InventoryRecord::Object(object) = &mut record {
        object.candidates[1].image = CleanupImage::Sa {
            identity: maximum_sa(),
            immutable_fingerprint: [0x37; 32],
        };
    }
    assert!(matches!(
        encode_record(&record, MEASUREMENT_RECORD_LIMIT),
        Err(InventoryError::Malformed)
    ));
}

#[test]
fn every_supported_variable_field_fits_the_derived_wire_bounds() {
    // Each scalar/enum has a fixed width. IPv6, present optional fields, two
    // candidates, six policy templates, and eight members maximize the only
    // variable-width productions in this experimental grammar.
    const OBJECT_HEADER: usize = 2 + 8 + 8 + 1 + 1 + 1 + 12 + 1;
    const SELECTOR: usize = 2 * 17 + 2 * 2 + 3;
    const ID: usize = 17 + 4 + 1;
    const TEMPLATE: usize = ID + 17 + 4 + 1;
    const SA_IMAGE: usize = SELECTOR + 4 + 4 + 4 + ID + 17 + 4 + 1 + 7 + 9 + 5 + 9 + 32;
    const POLICY_IMAGE: usize = SELECTOR + 1 + 1 + 4 + 1 + 6 * TEMPLATE + 9 + 5;
    const MAX_SA: usize = OBJECT_HEADER + 2 * (32 + 1 + SA_IMAGE);
    const MAX_POLICY: usize = OBJECT_HEADER + 2 * (32 + 1 + POLICY_IMAGE);
    const MAX_COVERAGE: usize = 2 + 8 + 8 + 1 + 16 + 16 + 8 + 32 + 33 + 1 + 8 * (12 + 33);
    assert_eq!((MAX_SA, MAX_POLICY, MAX_COVERAGE), (418, 752, 485));

    for ipv6 in [false, true] {
        for options in 0_u8..16 {
            for mode in [XfrmMode::Transport, XfrmMode::Tunnel, XfrmMode::Beet] {
                let mut identity = maximum_sa();
                if !ipv6 {
                    identity.selector.source = IpAddress::Ipv4([1; 4]);
                    identity.selector.destination = IpAddress::Ipv4([2; 4]);
                    identity.selector.source_prefix_len = 32;
                    identity.selector.destination_prefix_len = 31;
                    identity.id.destination = IpAddress::Ipv4([3; 4]);
                    identity.source_address = IpAddress::Ipv4([4; 4]);
                }
                identity.id.spi = u32::MAX;
                identity.selector.ifindex = i32::MIN;
                identity.selector.user_id = u32::MAX;
                identity.mode = mode;
                identity.encap =
                    (options & 1 != 0).then_some(UdpEncap::esp_in_udp(u16::MAX, u16::MAX));
                identity.mark = (options & 2 != 0).then_some(XfrmLookupMark::full(u32::MAX));
                identity.if_id = (options & 4 != 0).then_some(u32::MAX);
                identity.output_mark = (options & 8 != 0).then_some(XfrmMark {
                    value: u32::MAX,
                    mask: u32::MAX,
                });
                let record = object_record(CleanupImage::Sa {
                    identity,
                    immutable_fingerprint: [0xff; 32],
                });
                let bytes = encode_record(&record, MAX_SA).unwrap();
                assert!(bytes.len() <= MAX_SA);
                assert_eq!(decode_record(&bytes, MAX_SA).unwrap(), record);
            }
        }
    }
    for count in 0..=POLICY_TEMPLATES {
        for direction in [
            XfrmDirection::In,
            XfrmDirection::Out,
            XfrmDirection::Forward,
        ] {
            for action in [XfrmAction::Allow, XfrmAction::Block] {
                let mut policy = maximum_policy();
                policy.templates.truncate(count);
                policy.direction = direction;
                policy.action = action;
                policy.priority = u32::MAX;
                let record = object_record(CleanupImage::Policy(policy));
                if count == 0 && action == XfrmAction::Allow {
                    assert!(encode_record(&record, MAX_POLICY).is_err());
                    continue;
                }
                let bytes = encode_record(&record, MAX_POLICY).unwrap();
                assert_eq!(decode_record(&bytes, MAX_POLICY).unwrap(), record);
            }
        }
    }
    let record = maximum_coverage();
    assert_eq!(
        encode_record(&record, MAX_COVERAGE).unwrap().len(),
        MAX_COVERAGE
    );
    println!(
        "derived_maximum_record_bytes sa {MAX_SA} policy {MAX_POLICY} coverage {MAX_COVERAGE}"
    );
    println!(
        "native_type_bytes record {} object {} candidate {} policy_template {} coverage_member {} leaf {} child_reference {} root {}",
        std::mem::size_of::<InventoryRecord>(),
        std::mem::size_of::<ObjectRecord>(),
        std::mem::size_of::<CandidateImage>(),
        std::mem::size_of::<XfrmTemplate>(),
        std::mem::size_of::<CoverageMember>(),
        std::mem::size_of::<super::tree::LeafPage>(),
        std::mem::size_of::<super::tree::ChildReference>(),
        std::mem::size_of::<super::tree::RootPage>()
    );
}

fn node_context() -> NodeContext {
    NodeContext {
        namespace: [0x41; 40],
        incarnation: [0x42; 16],
        device: 1,
        inode: 2,
        generation: 3,
        revision: 4,
        kind: NodeKind::Leaf,
        position: 5,
        slot: 1,
    }
}

#[test]
fn node_authentication_binds_whole_context_and_rejects_torn_frames() {
    let key = InventoryKey::new([0x51; 32]);
    let context = node_context();
    let payload = encode_record(&maximum_coverage(), MEASUREMENT_RECORD_LIMIT).unwrap();
    let frame = seal_node(&key, context, &payload, 16 * 1024).unwrap();
    assert_eq!(
        &*open_node(&key, context, &frame, 16 * 1024).unwrap(),
        &*payload
    );
    assert!(!frame.windows(32).any(|window| window == [0x34; 32]));
    assert!(open_node(&InventoryKey::new([0x52; 32]), context, &frame, 16 * 1024).is_err());
    let mut alternatives = vec![context; 10];
    alternatives[0].namespace[0] ^= 1;
    alternatives[1].incarnation[0] ^= 1;
    alternatives[2].device += 1;
    alternatives[3].inode += 1;
    alternatives[4].generation += 1;
    alternatives[5].revision += 1;
    alternatives[6].kind = NodeKind::Branch;
    alternatives[7].position += 1;
    alternatives[8].slot = 0;
    alternatives[9].kind = NodeKind::Root;
    for alternative in alternatives {
        assert!(open_node(&key, alternative, &frame, 16 * 1024).is_err());
    }
    for length in 0..frame.len() {
        assert!(open_node(&key, context, &frame[..length], 16 * 1024).is_err());
    }
    for index in 0..frame.len() {
        let mut damaged = frame.clone();
        damaged[index] ^= 1;
        assert!(open_node(&key, context, &damaged, 16 * 1024).is_err());
    }
    let mut appended = frame.clone();
    appended.push(0);
    assert!(open_node(&key, context, &appended, 16 * 1024).is_err());
    let repeated = seal_node(&key, context, &payload, 16 * 1024).unwrap();
    assert_ne!(frame, repeated);
    println!("node_envelope_bytes {}", frame.len() - payload.len());
}

#[test]
fn locator_index_keeps_collisions_reachable_after_removal_and_reuse() {
    let mut index = LocatorIndex::new(4).unwrap();
    let mut keys = [[0_u8; 32]; 5];
    for (ordinal, key) in keys.iter_mut().enumerate() {
        key[31] = u8::try_from(ordinal).unwrap();
    }
    let locations = std::array::from_fn::<_, 5, _>(|ordinal| Location {
        position: u32::try_from(ordinal).unwrap(),
        kind: if ordinal % 2 == 0 {
            LocatorKind::Object
        } else {
            LocatorKind::Coverage
        },
    });
    for ordinal in 0..4 {
        index.insert(keys[ordinal], locations[ordinal]).unwrap();
    }
    let allocation = index.allocation();
    assert_eq!(allocation.0, 8);
    assert_eq!(allocation.2, allocation.0 * allocation.1);
    assert!(matches!(
        index.insert(keys[4], locations[4]),
        Err(InventoryError::Capacity)
    ));
    index.remove(&keys[1], locations[1]).unwrap();
    for ordinal in [0, 2, 3] {
        assert_eq!(index.lookup(&keys[ordinal]).0, Some(locations[ordinal]));
        assert!(index.lookup(&keys[ordinal]).1 <= allocation.0);
    }
    assert_eq!(index.lookup(&keys[1]).0, None);
    index.insert(keys[4], locations[4]).unwrap();
    assert_eq!(index.lookup(&keys[4]).0, Some(locations[4]));
    assert_eq!(index.allocation(), allocation);
    assert!(matches!(
        index.insert(keys[0], locations[4]),
        Err(InventoryError::Duplicate)
    ));
    index.insert(keys[0], locations[0]).unwrap();
    println!(
        "index_slots {} index_slot_bytes {} index_allocation_bytes {}",
        allocation.0, allocation.1, allocation.2
    );
}

pub(super) fn proposed_format() -> super::tree::FormatBudget {
    super::tree::FormatBudget {
        record_bytes: 1024,
        manifest_bytes: 16 * 1024,
        root_bytes: 20 * 1024,
    }
}

#[test]
fn snapshot_codecs_measure_full_leaf_and_manifests_without_addressspace_allocation() {
    use super::tree::{
        decode_children, decode_leaf, decode_root, encode_children, encode_leaf, encode_root,
        ChildReference, Counts, InventoryLimits, LeafPage, RootPage, ADDRESS_SLOTS, FANOUT,
    };
    let format = proposed_format();
    let mut leaf = LeafPage::empty();
    for (position, slot) in leaf.records.iter_mut().enumerate() {
        let mut record = object_record(CleanupImage::Policy(maximum_policy()));
        if let InventoryRecord::Object(object) = &mut record {
            object.serial = u64::try_from(position + 1).unwrap();
        }
        *slot = Some(record);
    }
    let leaf_bytes = encode_leaf(&leaf, format).unwrap();
    assert!(decode_leaf(&leaf_bytes, format).unwrap() == leaf);
    let children = [ChildReference {
        present: true,
        slot: 1,
        generation: 1,
        revision: 2,
        counts: Counts {
            objects: 64,
            images: 128,
            coverage: 0,
        },
        digest: [0x61; 32],
    }; FANOUT];
    let branch_bytes = encode_children(&children, format.manifest_bytes).unwrap();
    assert!(decode_children(&branch_bytes, format.manifest_bytes).unwrap() == children);
    let root = RootPage {
        completion: [0; 4096],
        next_serial: u64::from(ADDRESS_SLOTS) + 1,
        limits: InventoryLimits {
            objects: ADDRESS_SLOTS,
            images: 2 * ADDRESS_SLOTS,
            coverage: 0,
            batch_records: 9,
            storage_bytes: u64::MAX,
            index_bytes: u64::MAX,
            working_bytes: u64::MAX,
        },
        stores: [Some([0x62; 16]), Some([0x63; 16]), Some([0x64; 16])],
        children: [ChildReference {
            counts: Counts {
                objects: 16384,
                images: 32768,
                coverage: 0,
            },
            ..children[0]
        }; FANOUT],
    };
    let root_bytes = encode_root(&root, format.root_bytes).unwrap();
    assert!(decode_root(&root_bytes, format.root_bytes).unwrap() == root);
    assert_eq!(root_bytes.len(), 20067);
    let envelope = super::node::ENVELOPE_BYTES;
    assert!(branch_bytes.len() + envelope <= format.manifest_bytes);
    assert!(root_bytes.len() + envelope <= format.root_bytes);
    println!(
        "snapshot_payload_bytes leaf {} branch {} root {} framed_single_path_bytes {}",
        leaf_bytes.len(),
        branch_bytes.len(),
        root_bytes.len(),
        leaf_bytes.len() + branch_bytes.len() + root_bytes.len() + 3 * envelope
    );
}

#[test]
fn root_completion_reservation_has_a_closed_version_and_refuses_unknown_bytes() {
    use super::tree::{decode_root, encode_root, ChildReference, InventoryLimits, RootPage};
    let format = proposed_format();
    let mut root = RootPage {
        completion: [0; 4096],
        next_serial: 1,
        limits: InventoryLimits {
            objects: 1,
            images: 2,
            coverage: 1,
            batch_records: 2,
            storage_bytes: u64::MAX,
            index_bytes: u64::MAX,
            working_bytes: u64::MAX,
        },
        stores: [None; 3],
        children: [ChildReference::EMPTY; 256],
    };
    let encoded = encode_root(&root, format.root_bytes).unwrap();
    // Metadata is 51 bytes with all three optional stores absent, followed by
    // the fixed completion region and 256 one-byte empty child references.
    assert_eq!(encoded.len(), 51 + 4096 + 256);
    assert!(decode_root(&encoded, format.root_bytes).unwrap() == root);
    for offset in [0, 1, 2048, 4095] {
        root.completion[offset] = 1;
        assert!(encode_root(&root, format.root_bytes).is_err());
        root.completion[offset] = 0;
        let mut corrupt = encoded.to_vec();
        corrupt[51 + offset] = 1;
        assert!(decode_root(&corrupt, format.root_bytes).is_err());
    }
}

#[test]
fn cleanup_descriptor_refuses_an_sa_with_zero_protocol() {
    let mut identity = maximum_sa();
    identity.id.protocol = 0;
    let record = object_record(CleanupImage::Sa {
        identity,
        immutable_fingerprint: [0x37; 32],
    });
    assert!(encode_record(&record, MEASUREMENT_RECORD_LIMIT).is_err());
    let mut bytes = encode_record(
        &object_record(CleanupImage::Sa {
            identity: maximum_sa(),
            immutable_fingerprint: [0x37; 32],
        }),
        MEASUREMENT_RECORD_LIMIT,
    )
    .unwrap();
    assert_eq!(bytes[141], 50);
    bytes[141] = 0;
    assert!(decode_record(&bytes, MEASUREMENT_RECORD_LIMIT).is_err());
}

#[test]
fn cleanup_descriptor_refuses_allow_without_a_template() {
    let mut policy = maximum_policy();
    policy.templates.clear();
    assert!(encode_record(
        &object_record(CleanupImage::Policy(policy.clone())),
        MEASUREMENT_RECORD_LIMIT
    )
    .is_err());
    policy.action = XfrmAction::Block;
    let mut bytes = encode_record(
        &object_record(CleanupImage::Policy(policy)),
        MEASUREMENT_RECORD_LIMIT,
    )
    .unwrap();
    assert_eq!(bytes[109], 1);
    bytes[109] = 0;
    assert!(decode_record(&bytes, MEASUREMENT_RECORD_LIMIT).is_err());
}

#[test]
fn cleanup_descriptor_refuses_unidentified_or_zero_protocol_templates() {
    for zero_protocol in [false, true] {
        let mut policy = maximum_policy();
        if zero_protocol {
            policy.templates[0].id.protocol = 0;
        } else {
            policy.templates[0].id.spi = 0;
            policy.templates[0].request_id = None;
        }
        assert!(encode_record(
            &object_record(CleanupImage::Policy(policy)),
            MEASUREMENT_RECORD_LIMIT
        )
        .is_err());
    }
    let mut bytes = encode_record(
        &object_record(CleanupImage::Policy(maximum_policy())),
        MEASUREMENT_RECORD_LIMIT,
    )
    .unwrap();
    assert_eq!(bytes[136], 50);
    bytes[136] = 0;
    assert!(decode_record(&bytes, MEASUREMENT_RECORD_LIMIT).is_err());
}
