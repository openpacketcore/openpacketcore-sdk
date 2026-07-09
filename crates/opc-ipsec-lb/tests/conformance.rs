use opc_ipsec_lb::{
    classify_swu_packet, measure_disruption, AntiReplayResume, ClusterNode, CookieKey, CookieSlot,
    EspFragmentPosture, FixedEntropy, ForwardingProof, IkeCookieGate, IpAddress, IpFragment,
    IpsecLbError, IvResumeDecision, MockOwnershipFencer, MockRePinAuditSink, MockSteeringBackend,
    MockSteeringOperation, RePinAuditEventKind, RePinCoordinator, RePinRequest, RekeyRequest,
    RendezvousSelector, ResumeKeySource, SaId, SameSpiResume, SelectionKey, SendIvCounter, ShardId,
    ShardSet, SpiAllocationRequest, SpiAllocator, SpiKind, SteerKey, SteeringRule,
    SwuClassification, SwuClassifierConfig, SwuPacket, TaggedSpiAllocator, TaggedSpiLayout,
};

const IKE_HEADER_LEN: usize = 28;

fn shards(count: u16) -> ShardSet {
    ShardSet::new((0..count).map(ShardId::new).collect()).unwrap()
}

fn ike_header(initiator_spi: u64, responder_spi: u64, exchange_type: u8) -> Vec<u8> {
    let mut bytes = vec![0u8; IKE_HEADER_LEN];
    bytes[0..8].copy_from_slice(&initiator_spi.to_be_bytes());
    bytes[8..16].copy_from_slice(&responder_spi.to_be_bytes());
    bytes[17] = 0x20;
    bytes[18] = exchange_type;
    bytes[24..28].copy_from_slice(&(IKE_HEADER_LEN as u32).to_be_bytes());
    bytes
}

#[test]
fn spi_allocator_rejects_unsatisfiable_normative_entropy_floor() {
    assert!(TaggedSpiLayout::new(SpiKind::Ikev2Responder, 8, 64).is_err());
    assert!(TaggedSpiLayout::new(SpiKind::ChildEsp, 8, 64).is_err());
}

#[test]
fn spi_allocator_decodes_owner_and_keeps_rekey_tag_stable() {
    let layout = TaggedSpiLayout::new(SpiKind::ChildEsp, 8, 24).unwrap();
    let allocator =
        TaggedSpiAllocator::new(layout, shards(4), FixedEntropy::new((0..64).collect()));
    let first = allocator
        .allocate(SpiAllocationRequest {
            kind: SpiKind::ChildEsp,
            shard: ShardId::new(3),
        })
        .unwrap();
    let decoded = allocator.decode(SpiKind::ChildEsp, first.value).unwrap();
    assert_eq!(decoded.shard, ShardId::new(3));
    let rekey = allocator
        .allocate_rekey(RekeyRequest { replaces: first })
        .unwrap();
    assert_eq!(rekey.tag, first.tag);
    assert_eq!(rekey.shard, first.shard);
    assert_ne!(rekey.value, first.value);
}

#[test]
fn classifier_demuxes_500_4500_ike_esp_and_mobike() {
    let shard_set = shards(3);
    let config = SwuClassifierConfig {
        shards: &shard_set,
        esp_fragment_posture: EspFragmentPosture::PreventIpFragmentation,
    };
    let source = IpAddress::V4([198, 51, 100, 7]);
    let ike_init = ike_header(0x0102, 0, 34);
    assert_eq!(
        classify_swu_packet(
            SwuPacket {
                udp_destination_port: 500,
                source_ip: source,
                datagram: &ike_init,
                fragment: None,
            },
            config,
        )
        .code(),
        "ike_sa_init_bootstrap"
    );

    let mut natt_ike = vec![0, 0, 0, 0];
    natt_ike.extend_from_slice(&ike_header(0x0102, 0x9000, 35));
    assert_eq!(
        classify_swu_packet(
            SwuPacket {
                udp_destination_port: 4500,
                source_ip: source,
                datagram: &natt_ike,
                fragment: None,
            },
            config,
        )
        .code(),
        "ike_responder_spi"
    );

    let esp = [0x99, 0xaa, 0xbb, 0xcc, 0, 0, 0, 1];
    assert!(matches!(
        classify_swu_packet(
            SwuPacket {
                udp_destination_port: 4500,
                source_ip: source,
                datagram: &esp,
                fragment: None,
            },
            config,
        ),
        SwuClassification::Steer {
            key: SteerKey::EspSpi(0x99aa_bbcc),
            bootstrap_shard: None,
            ..
        }
    ));

    let mobike = ike_header(0x0102, 0x9000, 37);
    let before = classify_swu_packet(
        SwuPacket {
            udp_destination_port: 500,
            source_ip: IpAddress::V4([198, 51, 100, 7]),
            datagram: &mobike,
            fragment: None,
        },
        config,
    );
    let after = classify_swu_packet(
        SwuPacket {
            udp_destination_port: 500,
            source_ip: IpAddress::V4([203, 0, 113, 55]),
            datagram: &mobike,
            fragment: None,
        },
        config,
    );
    assert_eq!(before, after);
}

#[test]
fn classifier_reports_non_first_fragments_explicitly() {
    let shard_set = shards(2);
    let packet = SwuPacket {
        udp_destination_port: 4500,
        source_ip: IpAddress::V4([198, 51, 100, 7]),
        datagram: &[],
        fragment: Some(IpFragment {
            offset: 10,
            more_fragments: true,
        }),
    };
    assert_eq!(
        classify_swu_packet(
            packet,
            SwuClassifierConfig {
                shards: &shard_set,
                esp_fragment_posture: EspFragmentPosture::PreventIpFragmentation,
            },
        )
        .code(),
        "unexpected_non_first_ip_fragment"
    );
    assert_eq!(
        classify_swu_packet(
            packet,
            SwuClassifierConfig {
                shards: &shard_set,
                esp_fragment_posture: EspFragmentPosture::ReassembleBeforeSteer,
            },
        ),
        SwuClassification::NeedsReassembly
    );
}

#[test]
fn rendezvous_selection_is_stable_and_measured_for_disruption() {
    let selector = RendezvousSelector;
    let before = shards(5);
    let after = shards(6);
    let key = SelectionKey::Tag(12345);
    assert_eq!(
        selector.select(&before, &key).unwrap(),
        selector.select(&before, &key).unwrap()
    );
    let keys: Vec<_> = (0..65_536).map(SelectionKey::Tag).collect();
    let disruption = measure_disruption(&before, &after, &keys).unwrap();
    assert!(disruption.moved_keys <= keys.len().div_ceil(5));
}

#[test]
fn cookie_is_stateless_and_tamper_bound() {
    let gate = IkeCookieGate::new(CookieKey::new([0x7b; 32]));
    let src = IpAddress::V4([198, 51, 100, 7]);
    let dst = IpAddress::V4([203, 0, 113, 8]);
    let cookie = gate
        .generate(0x1234, src, dst, CookieSlot::new(88))
        .unwrap();
    gate.verify(cookie, 0x1234, src, dst, CookieSlot::new(88))
        .unwrap();
    assert!(gate
        .verify(
            cookie,
            0x1234,
            IpAddress::V4([198, 51, 100, 8]),
            dst,
            CookieSlot::new(88),
        )
        .is_err());
}

#[test]
fn failover_guards_reject_iv_and_replay_rollback() {
    assert_eq!(
        SendIvCounter::resume_after(7).unwrap(),
        IvResumeDecision::Resume(SendIvCounter::new(8))
    );
    assert!(SendIvCounter::validate_restored_next(6, 7).is_err());
    assert!(AntiReplayResume {
        previous_highest_accepted: 101,
        restored_highest_accepted: 100,
    }
    .validate()
    .is_err());
}

#[tokio::test]
async fn repin_requires_audit_fence_and_injected_forwarding_proof() {
    let steering = MockSteeringBackend::new();
    let fencer = MockOwnershipFencer::new();
    let audit = MockRePinAuditSink::new();
    let coordinator = RePinCoordinator::new(steering.clone(), fencer.clone(), audit.clone());

    let sa = SaId::Esp { spi: 0x1122_3344 };
    let previous_owner = ClusterNode::new("worker-a");
    let new_owner = ClusterNode::new("worker-b");
    fencer.set_owner(sa, previous_owner.clone());

    let rule = SteeringRule {
        shard: ShardId::new(1),
        owner: ShardId::new(2),
        key: SteerKey::EspSpi(0x1122_3344),
    };
    let outcome = coordinator
        .repin(RePinRequest {
            sa,
            previous_owner: previous_owner.clone(),
            new_owner: new_owner.clone(),
            rule,
            resume: SameSpiResume {
                previous_sa: sa,
                resumed_sa: sa,
                previous_send_iv_next: 41,
                restored_send_iv_next: 42,
                anti_replay: AntiReplayResume {
                    previous_highest_accepted: 100,
                    restored_highest_accepted: 101,
                },
                key_source: ResumeKeySource::LiveMirrored,
            },
        })
        .await
        .unwrap();

    assert_eq!(
        steering.operations(),
        vec![MockSteeringOperation::Install(rule)]
    );
    assert_eq!(fencer.owner(sa).unwrap().as_str(), "worker-b");
    assert!(!outcome.forwarding_proven());

    let events = audit.events();
    assert_eq!(events[0].kind, RePinAuditEventKind::Attempt);
    assert_eq!(events[1].kind, RePinAuditEventKind::Fenced);
    assert_eq!(events[2].kind, RePinAuditEventKind::SteeringInstalled);
    assert!(!events.iter().any(|event| event.forwarding_proven));

    let proof = ForwardingProof::new(sa, outcome.fence(), 3).unwrap();
    let proven = outcome.with_forwarding_proof(proof).unwrap();
    assert!(proven.forwarding_proven());
}

#[tokio::test]
async fn repin_fails_closed_when_audit_or_resume_is_unsafe() {
    let steering = MockSteeringBackend::new();
    let fencer = MockOwnershipFencer::new();
    let audit = MockRePinAuditSink::new();
    let coordinator = RePinCoordinator::new(steering.clone(), fencer.clone(), audit.clone());

    let sa = SaId::Esp { spi: 7 };
    let previous_owner = ClusterNode::new("worker-a");
    let new_owner = ClusterNode::new("worker-b");
    fencer.set_owner(sa, previous_owner.clone());
    audit.set_failure(IpsecLbError::Unsupported);

    let rule = SteeringRule {
        shard: ShardId::new(1),
        owner: ShardId::new(2),
        key: SteerKey::EspSpi(7),
    };
    let request = RePinRequest {
        sa,
        previous_owner: previous_owner.clone(),
        new_owner: new_owner.clone(),
        rule,
        resume: SameSpiResume {
            previous_sa: sa,
            resumed_sa: sa,
            previous_send_iv_next: 10,
            restored_send_iv_next: 11,
            anti_replay: AntiReplayResume {
                previous_highest_accepted: 5,
                restored_highest_accepted: 5,
            },
            key_source: ResumeKeySource::LiveMirrored,
        },
    };
    assert_eq!(
        coordinator.repin(request.clone()).await.unwrap_err(),
        IpsecLbError::Unsupported
    );
    assert!(steering.operations().is_empty());
    assert_eq!(fencer.owner(sa).unwrap().as_str(), "worker-a");

    audit.clear_failure();
    let unsafe_request = RePinRequest {
        resume: SameSpiResume {
            previous_sa: sa,
            resumed_sa: SaId::Esp { spi: 8 },
            previous_send_iv_next: 10,
            restored_send_iv_next: 11,
            anti_replay: AntiReplayResume {
                previous_highest_accepted: 5,
                restored_highest_accepted: 5,
            },
            key_source: ResumeKeySource::PersistedKeyMaterial,
        },
        ..request
    };
    assert!(matches!(
        coordinator.repin(unsafe_request).await.unwrap_err(),
        IpsecLbError::UnsafeResume { .. }
    ));
    assert!(steering.operations().is_empty());
    assert_eq!(fencer.owner(sa).unwrap().as_str(), "worker-a");
}
