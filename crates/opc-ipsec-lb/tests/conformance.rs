use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use opc_route_steering::{IpPrefix, MockOperation, MockRouteSteeringBackend, RouteRequest};
use opc_session_store::{
    CompareAndSet, CompareAndSetResult, EncryptedSessionPayload, FakeSessionBackend, Generation,
    OwnerId, SessionBackend, SessionLeaseManager, SessionStore, StateClass, StateType,
    StoredSessionRecord,
};
use opc_types::{NetworkFunctionKind, TenantId};

use opc_ipsec_lb::{
    classify_swu_packet, measure_disruption, AntiReplayResume, BgpRouteVipAdvertiser,
    BgpRouteVipAdvertiserConfig, ClusterNode, CookieKey, CookieSlot, EspFragmentPosture,
    ExternalLbVipAdvertiser, FixedEntropy, ForwardingProof, IkeCookie, IkeCookieDecision,
    IkeCookieGate, IkeCookiePolicy, IkeCookieRequest, IpAddress, IpFragment, IpsecLbError,
    IvResumeDecision, LeadershipFence, MockOwnershipFencer, MockOwnershipSource,
    MockRePinAuditSink, MockSteeringBackend, MockSteeringOperation, MockVipAdvertiser,
    MockVipOperation, NicOffloadSecurityPosture, OwnershipFenceGrant, OwnershipFenceRequest,
    OwnershipFencer, OwnershipRetryProof, OwnershipSource, OwnershipTransitionFingerprint,
    OwnershipTransitionId, RePinAuditEvent, RePinAuditEventKind, RePinAuditSink, RePinCoordinator,
    RePinError, RePinRequest, RePinRetryStage, RekeyRequest, RendezvousSelector, ResumeKeySource,
    SaId, SameSpiOutboundIvResume, SameSpiResume, SelectionKey, SendIvCounter, SendIvCounterMode,
    SendIvForwardJump, SessionOwnershipKeyResolver, SessionOwnershipKeyspace,
    SessionStoreOwnershipSource, ShardId, ShardSet, SpiAllocationRequest, SpiAllocator, SpiKind,
    SteerKey, SteeringBackend, SteeringBackendKind, SteeringProbe, SteeringRule, SwuClassification,
    SwuClassifierConfig, SwuPacket, TaggedSpiAllocator, TaggedSpiLayout, VipAdvertisement,
    VipAdvertiser, VipAdvertiserKind, VipOwnershipCoordinator, VipOwnershipIntent,
    MAX_ESP_SEND_IV_FORWARD_JUMP, MIN_SEND_IV_FORWARD_JUMP,
};

const IKE_HEADER_LEN: usize = 28;

#[test]
fn vip_delivered_probe_distinguishes_converged_production_from_mock_steering() {
    let probe = SteeringProbe::vip_delivered();

    assert_eq!(probe.kind, SteeringBackendKind::VipDelivered);
    assert_ne!(probe.kind, SteeringBackendKind::Mock);
    assert!(probe.platform_supported && probe.mutation_ready);
    assert!(probe.key_material_free);
    assert!(probe
        .details
        .is_some_and(|details| { details.contains("floating VIP") && details.contains("no-ops") }));
}

fn management_vip() -> VipAdvertisement {
    VipAdvertisement {
        vip: IpAddress::V4([192, 0, 2, 40]),
        node: ClusterNode::new("control-a"),
    }
}

fn owner_intent(fence: u64) -> VipOwnershipIntent {
    VipOwnershipIntent {
        leader: true,
        quorum_available: true,
        healthy: true,
        fence: Some(LeadershipFence::new(fence).unwrap()),
    }
}

#[tokio::test]
async fn vip_ownership_follows_every_external_signal_idempotently() {
    let advertiser = MockVipAdvertiser::new();
    let advertisement = management_vip();
    let mut coordinator = VipOwnershipCoordinator::new(advertisement.clone(), advertiser.clone());

    coordinator
        .reconcile(VipOwnershipIntent::default())
        .await
        .unwrap();
    assert!(!coordinator.is_advertised());
    assert!(advertiser.operations().is_empty());

    for (fence, loss) in [
        (
            1,
            VipOwnershipIntent {
                leader: false,
                ..owner_intent(1)
            },
        ),
        (
            2,
            VipOwnershipIntent {
                quorum_available: false,
                ..owner_intent(2)
            },
        ),
        (
            3,
            VipOwnershipIntent {
                healthy: false,
                ..owner_intent(3)
            },
        ),
    ] {
        let active = owner_intent(fence);
        coordinator.reconcile(active).await.unwrap();
        coordinator.reconcile(active).await.unwrap();
        assert!(coordinator.is_advertised());

        coordinator.reconcile(loss).await.unwrap();
        coordinator.reconcile(loss).await.unwrap();
        assert!(!coordinator.is_advertised());
    }

    assert_eq!(
        advertiser.operations(),
        vec![
            MockVipOperation::Advertise(advertisement.clone()),
            MockVipOperation::Withdraw(advertisement.clone()),
            MockVipOperation::Advertise(advertisement.clone()),
            MockVipOperation::Withdraw(advertisement.clone()),
            MockVipOperation::Advertise(advertisement.clone()),
            MockVipOperation::Withdraw(advertisement),
        ]
    );
}

#[tokio::test]
async fn stale_missing_and_aba_fences_never_readvertise() {
    let advertiser = MockVipAdvertiser::new();
    let advertisement = management_vip();
    let mut coordinator = VipOwnershipCoordinator::new(advertisement.clone(), advertiser.clone());

    coordinator.reconcile(owner_intent(10)).await.unwrap();
    coordinator.reconcile(owner_intent(9)).await.unwrap();
    assert!(!coordinator.is_advertised());

    coordinator.reconcile(owner_intent(9)).await.unwrap();
    coordinator.reconcile(owner_intent(10)).await.unwrap();
    coordinator
        .reconcile(VipOwnershipIntent {
            leader: true,
            quorum_available: true,
            healthy: true,
            fence: None,
        })
        .await
        .unwrap();
    assert!(!coordinator.is_advertised());

    coordinator.reconcile(owner_intent(11)).await.unwrap();
    assert!(coordinator.is_advertised());
    coordinator
        .reconcile(VipOwnershipIntent {
            healthy: false,
            ..owner_intent(11)
        })
        .await
        .unwrap();
    assert!(!coordinator.is_advertised());

    // An ABA return to this same node cannot reuse the prior epoch.
    coordinator.reconcile(owner_intent(11)).await.unwrap();
    assert!(!coordinator.is_advertised());
    coordinator.reconcile(owner_intent(12)).await.unwrap();
    assert!(coordinator.is_advertised());
    assert_eq!(
        coordinator.highest_observed_fence(),
        Some(LeadershipFence::new(12).unwrap())
    );

    coordinator
        .reconcile(VipOwnershipIntent {
            leader: true,
            quorum_available: true,
            healthy: true,
            fence: None,
        })
        .await
        .unwrap();
    assert!(!coordinator.is_advertised());

    assert_eq!(
        advertiser.operations(),
        vec![
            MockVipOperation::Advertise(advertisement.clone()),
            MockVipOperation::Withdraw(advertisement.clone()),
            MockVipOperation::Advertise(advertisement.clone()),
            MockVipOperation::Withdraw(advertisement.clone()),
            MockVipOperation::Advertise(advertisement),
            MockVipOperation::Withdraw(management_vip()),
        ]
    );
}

#[tokio::test]
async fn external_lb_provider_tracks_fenced_cycles_without_route_mutation() {
    let advertiser = ExternalLbVipAdvertiser::new();
    let probe = advertiser.probe().await.unwrap();
    assert_eq!(probe.kind, VipAdvertiserKind::ExternalLb);
    assert!(probe.platform_supported && probe.mutation_ready);

    let mut coordinator = VipOwnershipCoordinator::new(management_vip(), advertiser);
    coordinator.reconcile(owner_intent(40)).await.unwrap();
    assert!(coordinator.is_advertised());
    assert_eq!(
        coordinator.advertised_fence(),
        Some(LeadershipFence::new(40).unwrap())
    );

    coordinator
        .reconcile(VipOwnershipIntent {
            leader: false,
            ..owner_intent(40)
        })
        .await
        .unwrap();
    assert!(!coordinator.is_advertised());

    coordinator.reconcile(owner_intent(40)).await.unwrap();
    assert!(!coordinator.is_advertised());
    coordinator.reconcile(owner_intent(41)).await.unwrap();
    assert!(coordinator.is_advertised());

    // The provider is a zero-state adapter with no route backend to mutate.
    assert_eq!(std::mem::size_of::<ExternalLbVipAdvertiser>(), 0);
}

fn shards(count: u16) -> ShardSet {
    ShardSet::new((0..count).map(ShardId::new).collect()).unwrap()
}

fn valid_repin_request(sa: SaId, key: SteerKey) -> RePinRequest {
    let counter_mode = match sa {
        SaId::Esp { .. } => SendIvCounterMode::EspExtendedSequenceNumbers {
            max_peer_sequence_lag: 0,
        },
        SaId::Ike { .. } => SendIvCounterMode::IkeAeadExplicitIv64,
    };
    RePinRequest {
        sa,
        transition_id: OwnershipTransitionId::new(1).unwrap(),
        previous_fence: opc_ipsec_lb::OwnershipFence::new(1).unwrap(),
        previous_owner: ClusterNode::new("worker-a"),
        new_owner: ClusterNode::new("worker-b"),
        rule: SteeringRule {
            shard: ShardId::new(1),
            owner: ShardId::new(2),
            key,
        },
        resume: SameSpiResume {
            previous_sa: sa,
            resumed_sa: sa,
            outbound_iv: SameSpiOutboundIvResume::CounterBased {
                checkpointed_send_iv_next: 10,
                restored_send_iv_next: 10 + MIN_SEND_IV_FORWARD_JUMP,
                forward_jump: Some(SendIvForwardJump {
                    forward_jump: MIN_SEND_IV_FORWARD_JUMP,
                    counter_mode,
                }),
            },
            anti_replay: AntiReplayResume::ExactWindowRestore {
                checkpoint_highest_accepted: 5,
                restored_highest_accepted: 5,
            },
            key_source: ResumeKeySource::LiveMirrored,
        },
    }
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
        bootstrap_tag_bits: 8,
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
                bootstrap_tag_bits: 8,
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
                bootstrap_tag_bits: 8,
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
    let ni = [0x33u8; 16];
    let cookie = gate
        .generate(0x1234, src, dst, CookieSlot::new(88), &ni)
        .unwrap();
    gate.verify(cookie, 0x1234, src, dst, CookieSlot::new(88), &ni)
        .unwrap();
    assert!(gate
        .verify(
            cookie,
            0x1234,
            IpAddress::V4([198, 51, 100, 8]),
            dst,
            CookieSlot::new(88),
            &ni,
        )
        .is_err());
}

#[test]
fn cookie_gate_challenges_cookieless_init_before_state_allocation() {
    let gate = IkeCookieGate::new(CookieKey::new([0x81; 32]));
    let src = IpAddress::V4([198, 51, 100, 9]);
    let dst = IpAddress::V4([203, 0, 113, 1]);
    let ni = [0x33u8; 16];
    let request = IkeCookieRequest {
        initiator_spi: 0xfeed_beef,
        source_ip: src,
        destination_ip: dst,
        initiator_nonce: &ni,
        echoed_cookie: None,
        slot: CookieSlot::new(42),
    };

    let cookie = match gate
        .evaluate(request, IkeCookiePolicy::require_cookie())
        .unwrap()
    {
        IkeCookieDecision::Challenge { cookie } => cookie,
        IkeCookieDecision::Allow => panic!("cookieless IKE_SA_INIT must be challenged"),
    };

    let echoed = IkeCookieRequest {
        echoed_cookie: Some(cookie),
        ..request
    };
    assert_eq!(
        gate.evaluate(echoed, IkeCookiePolicy::require_cookie())
            .unwrap(),
        IkeCookieDecision::Allow
    );

    let mut tampered = cookie.as_bytes();
    tampered[0] ^= 0xff;
    assert_eq!(
        gate.evaluate(
            IkeCookieRequest {
                echoed_cookie: Some(IkeCookie::from_bytes(tampered)),
                ..request
            },
            IkeCookiePolicy::require_cookie(),
        )
        .unwrap_err(),
        IpsecLbError::CookieRejected
    );

    assert_eq!(
        gate.evaluate(
            IkeCookieRequest {
                source_ip: IpAddress::V4([198, 51, 100, 10]),
                echoed_cookie: Some(cookie),
                ..request
            },
            IkeCookiePolicy::require_cookie(),
        )
        .unwrap_err(),
        IpsecLbError::CookieRejected
    );
    assert_eq!(
        gate.evaluate(request, IkeCookiePolicy::allow_without_cookie())
            .unwrap(),
        IkeCookieDecision::Allow
    );
}

#[test]
fn failover_guards_reject_iv_and_replay_rollback() {
    assert_eq!(MIN_SEND_IV_FORWARD_JUMP, 1_u64 << 30);
    assert_eq!(MAX_ESP_SEND_IV_FORWARD_JUMP, (1_u64 << 31) - 1);
    assert_eq!(
        SendIvCounter::resume_after(7).unwrap(),
        IvResumeDecision::Resume(SendIvCounter::new(8))
    );
    assert!(SendIvCounter::validate_restored_next(6, 7).is_err());

    let checkpoint_next = 9;
    let peer_last_at_checkpoint = checkpoint_next - 1;
    assert_eq!(
        checkpoint_next + MAX_ESP_SEND_IV_FORWARD_JUMP - peer_last_at_checkpoint,
        1_u64 << 31
    );
    SendIvForwardJump {
        forward_jump: MAX_ESP_SEND_IV_FORWARD_JUMP,
        counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
            max_peer_sequence_lag: 0,
        },
    }
    .validate_restored_next(
        SaId::Esp { spi: 1 },
        checkpoint_next,
        checkpoint_next + MAX_ESP_SEND_IV_FORWARD_JUMP,
    )
    .unwrap();
    SendIvForwardJump {
        forward_jump: MAX_ESP_SEND_IV_FORWARD_JUMP - 1,
        counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
            max_peer_sequence_lag: 1,
        },
    }
    .validate_restored_next(
        SaId::Esp { spi: 1 },
        checkpoint_next,
        checkpoint_next + MAX_ESP_SEND_IV_FORWARD_JUMP - 1,
    )
    .unwrap();
    assert!(SendIvForwardJump {
        forward_jump: MAX_ESP_SEND_IV_FORWARD_JUMP,
        counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
            max_peer_sequence_lag: 1,
        },
    }
    .validate_restored_next(
        SaId::Esp { spi: 1 },
        checkpoint_next,
        checkpoint_next + MAX_ESP_SEND_IV_FORWARD_JUMP,
    )
    .is_err());
    assert_eq!(
        checkpoint_next + MAX_ESP_SEND_IV_FORWARD_JUMP + 1 - peer_last_at_checkpoint,
        (1_u64 << 31) + 1
    );
    assert!(SendIvForwardJump {
        forward_jump: MAX_ESP_SEND_IV_FORWARD_JUMP + 1,
        counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
            max_peer_sequence_lag: 0,
        },
    }
    .validate_restored_next(
        SaId::Esp { spi: 1 },
        checkpoint_next,
        checkpoint_next + MAX_ESP_SEND_IV_FORWARD_JUMP + 1,
    )
    .is_err());
    SendIvForwardJump {
        forward_jump: MAX_ESP_SEND_IV_FORWARD_JUMP + 1,
        counter_mode: SendIvCounterMode::IkeAeadExplicitIv64,
    }
    .validate_restored_next(
        SaId::Ike { responder_spi: 1 },
        checkpoint_next,
        checkpoint_next + MAX_ESP_SEND_IV_FORWARD_JUMP + 1,
    )
    .unwrap();
    assert!(SendIvForwardJump {
        forward_jump: MIN_SEND_IV_FORWARD_JUMP,
        counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
            max_peer_sequence_lag: 0,
        },
    }
    .validate_restored_next(SaId::Esp { spi: 1 }, 0, MIN_SEND_IV_FORWARD_JUMP,)
    .is_err());
    assert!(SendIvForwardJump {
        forward_jump: MIN_SEND_IV_FORWARD_JUMP,
        counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
            max_peer_sequence_lag: 0,
        },
    }
    .validate_restored_next(SaId::Esp { spi: 0 }, 1, 1 + MIN_SEND_IV_FORWARD_JUMP,)
    .is_err());
    SendIvForwardJump {
        forward_jump: MIN_SEND_IV_FORWARD_JUMP,
        counter_mode: SendIvCounterMode::IkeAeadExplicitIv64,
    }
    .validate_restored_next(SaId::Ike { responder_spi: 1 }, 0, MIN_SEND_IV_FORWARD_JUMP)
    .unwrap();

    assert!(AntiReplayResume::ExactWindowRestore {
        checkpoint_highest_accepted: 101,
        restored_highest_accepted: 100,
    }
    .validate()
    .is_err());
}

#[test]
fn inline_nic_crypto_offload_requires_key_custody_documentation() {
    assert!(NicOffloadSecurityPosture::steering_only()
        .validate()
        .is_ok());
    assert!(matches!(
        NicOffloadSecurityPosture::inline_ipsec_crypto(false, true)
            .validate()
            .unwrap_err(),
        IpsecLbError::InvalidConfig {
            field: "nic_offload_security",
            ..
        }
    ));
    assert!(matches!(
        NicOffloadSecurityPosture::inline_ipsec_crypto(true, false)
            .validate()
            .unwrap_err(),
        IpsecLbError::InvalidConfig {
            field: "nic_offload_security",
            ..
        }
    ));
    NicOffloadSecurityPosture::inline_ipsec_crypto(true, true)
        .validate()
        .unwrap();
}

#[tokio::test]
async fn bgp_vip_advertiser_programs_host_route_for_export() {
    let route_backend = MockRouteSteeringBackend::new();
    let advertiser = BgpRouteVipAdvertiser::with_backend(
        route_backend.clone(),
        BgpRouteVipAdvertiserConfig {
            route_table: 100,
            oif_ifindex: 42,
            priority: Some(10),
        },
    )
    .unwrap();

    advertiser
        .advertise(VipAdvertisement {
            vip: IpAddress::V4([203, 0, 113, 10]),
            node: ClusterNode::new("worker-a"),
        })
        .await
        .unwrap();

    assert_eq!(
        route_backend.operations(),
        vec![MockOperation::InstallRoute(RouteRequest {
            destination: IpPrefix::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 32),
            oif_ifindex: 42,
            table: 100,
            priority: Some(10),
        })]
    );
}

#[tokio::test]
async fn session_store_ownership_source_reads_authoritative_sa_owner() {
    let store = SessionStore::new(FakeSessionBackend::new());
    let keyspace = SessionOwnershipKeyspace::new(
        TenantId::new("tenant-a").unwrap(),
        NetworkFunctionKind::new("epdg").unwrap(),
    );
    let sa = SaId::Esp { spi: 0x5566_7788 };
    let key = keyspace.sa_key(sa).unwrap();
    let owner = OwnerId::new("worker-a").unwrap();
    let lease = store
        .acquire(&key, owner.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    let record = StoredSessionRecord {
        key: key.clone(),
        generation: Generation::new(1),
        owner,
        fence: lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("ipsec-lb-ownership"),
        expires_at: None,
        payload: EncryptedSessionPayload::new([]),
    };
    assert_eq!(
        store
            .compare_and_set(CompareAndSet {
                key,
                lease,
                expected_generation: None,
                new_record: record,
            })
            .await
            .unwrap(),
        CompareAndSetResult::Success
    );

    let source = SessionStoreOwnershipSource::new(store, keyspace);
    assert_eq!(
        source.sa_owner(sa).await.unwrap().unwrap().as_str(),
        "worker-a"
    );
}

#[tokio::test]
async fn persisted_resume_repins_only_after_forward_jump_and_external_forwarding_proof() {
    let steering = MockSteeringBackend::new();
    let fencer = MockOwnershipFencer::new();
    let ownership = MockOwnershipSource::default();
    let audit = MockRePinAuditSink::new();
    let coordinator = RePinCoordinator::new(
        steering.clone(),
        fencer.clone(),
        ownership.clone(),
        audit.clone(),
    );

    let sa = SaId::Esp { spi: 0x1122_3344 };
    let previous_owner = ClusterNode::new("worker-a");
    let new_owner = ClusterNode::new("worker-b");
    fencer.set_owner(sa, previous_owner.clone());
    ownership.set_shard_owner(ShardId::new(2), new_owner.clone());

    let rule = SteeringRule {
        shard: ShardId::new(1),
        owner: ShardId::new(2),
        key: SteerKey::EspSpi(0x1122_3344),
    };
    let outcome = coordinator
        .repin(RePinRequest {
            sa,
            transition_id: OwnershipTransitionId::new(1).unwrap(),
            previous_fence: opc_ipsec_lb::OwnershipFence::new(1).unwrap(),
            previous_owner: previous_owner.clone(),
            new_owner: new_owner.clone(),
            rule,
            resume: SameSpiResume {
                previous_sa: sa,
                resumed_sa: sa,
                outbound_iv: SameSpiOutboundIvResume::CounterBased {
                    checkpointed_send_iv_next: 41,
                    restored_send_iv_next: 41 + MIN_SEND_IV_FORWARD_JUMP,
                    forward_jump: Some(SendIvForwardJump {
                        forward_jump: MIN_SEND_IV_FORWARD_JUMP,
                        counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
                            max_peer_sequence_lag: 40,
                        },
                    }),
                },
                anti_replay: AntiReplayResume::BoundedReopening {
                    checkpoint_highest_accepted: 100,
                    restored_highest_accepted: 100,
                    max_reopened_packets: 64,
                },
                key_source: ResumeKeySource::PersistedKeyMaterial,
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
    let ownership = MockOwnershipSource::default();
    let audit = MockRePinAuditSink::new();
    let coordinator = RePinCoordinator::new(
        steering.clone(),
        fencer.clone(),
        ownership.clone(),
        audit.clone(),
    );

    let sa = SaId::Esp { spi: 7 };
    let previous_owner = ClusterNode::new("worker-a");
    let new_owner = ClusterNode::new("worker-b");
    fencer.set_owner(sa, previous_owner.clone());
    ownership.set_shard_owner(ShardId::new(2), new_owner.clone());
    audit.set_failure(IpsecLbError::Unsupported);

    let rule = SteeringRule {
        shard: ShardId::new(1),
        owner: ShardId::new(2),
        key: SteerKey::EspSpi(7),
    };
    let request = RePinRequest {
        sa,
        transition_id: OwnershipTransitionId::new(1).unwrap(),
        previous_fence: opc_ipsec_lb::OwnershipFence::new(1).unwrap(),
        previous_owner: previous_owner.clone(),
        new_owner: new_owner.clone(),
        rule,
        resume: SameSpiResume {
            previous_sa: sa,
            resumed_sa: sa,
            outbound_iv: SameSpiOutboundIvResume::CounterBased {
                checkpointed_send_iv_next: 10,
                restored_send_iv_next: 10 + MIN_SEND_IV_FORWARD_JUMP,
                forward_jump: Some(SendIvForwardJump {
                    forward_jump: MIN_SEND_IV_FORWARD_JUMP,
                    counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
                        max_peer_sequence_lag: 0,
                    },
                }),
            },
            anti_replay: AntiReplayResume::ExactWindowRestore {
                checkpoint_highest_accepted: 5,
                restored_highest_accepted: 5,
            },
            key_source: ResumeKeySource::LiveMirrored,
        },
    };
    assert_eq!(
        coordinator.repin(request.clone()).await.unwrap_err(),
        RePinError::BeforeOwnershipCommit(IpsecLbError::Unsupported)
    );
    assert!(steering.operations().is_empty());
    assert_eq!(fencer.owner(sa).unwrap().as_str(), "worker-a");

    audit.clear_failure();
    let unsafe_request = RePinRequest {
        resume: SameSpiResume {
            previous_sa: sa,
            resumed_sa: SaId::Esp { spi: 8 },
            outbound_iv: SameSpiOutboundIvResume::CounterBased {
                checkpointed_send_iv_next: 10,
                restored_send_iv_next: 10 + MIN_SEND_IV_FORWARD_JUMP,
                forward_jump: Some(SendIvForwardJump {
                    forward_jump: MIN_SEND_IV_FORWARD_JUMP,
                    counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
                        max_peer_sequence_lag: 0,
                    },
                }),
            },
            anti_replay: AntiReplayResume::ExactWindowRestore {
                checkpoint_highest_accepted: 5,
                restored_highest_accepted: 5,
            },
            key_source: ResumeKeySource::PersistedKeyMaterial,
        },
        ..request
    };
    assert!(matches!(
        coordinator.repin(unsafe_request).await.unwrap_err(),
        RePinError::BeforeOwnershipCommit(IpsecLbError::UnsafeResume { .. })
    ));
    assert!(steering.operations().is_empty());
    assert_eq!(fencer.owner(sa).unwrap().as_str(), "worker-a");
}

#[tokio::test]
async fn repin_rejects_zero_sa_identifiers_before_any_side_effect() {
    for (sa, key) in [
        (SaId::Esp { spi: 0 }, SteerKey::EspSpi(0)),
        (SaId::Ike { responder_spi: 0 }, SteerKey::IkeResponderSpi(0)),
    ] {
        let steering = MockSteeringBackend::new();
        let fencer = MockOwnershipFencer::new();
        let ownership = MockOwnershipSource::default();
        let audit = MockRePinAuditSink::new();
        let coordinator = RePinCoordinator::new(
            steering.clone(),
            fencer.clone(),
            ownership.clone(),
            audit.clone(),
        );
        let request = valid_repin_request(sa, key);
        fencer.set_owner(sa, request.previous_owner.clone());
        ownership.set_shard_owner(request.rule.owner, request.new_owner.clone());

        assert!(matches!(
            coordinator.repin(request).await.unwrap_err(),
            RePinError::BeforeOwnershipCommit(IpsecLbError::InvalidConfig { .. })
        ));
        assert!(audit.events().is_empty());
        assert!(fencer.operations().is_empty());
        assert!(steering.operations().is_empty());
        assert_eq!(fencer.owner(sa).unwrap().as_str(), "worker-a");
    }
}

#[tokio::test]
async fn repin_requires_target_shard_to_resolve_to_the_new_owner_without_side_effects() {
    let steering = MockSteeringBackend::new();
    let fencer = MockOwnershipFencer::new();
    let ownership = MockOwnershipSource::default();
    let audit = MockRePinAuditSink::new();
    let coordinator = RePinCoordinator::new(
        steering.clone(),
        fencer.clone(),
        ownership.clone(),
        audit.clone(),
    );
    let sa = SaId::Esp { spi: 0x1020_3040 };
    let request = valid_repin_request(sa, SteerKey::EspSpi(0x1020_3040));
    fencer.set_owner(sa, request.previous_owner.clone());

    assert!(matches!(
        coordinator.repin(request.clone()).await.unwrap_err(),
        RePinError::BeforeOwnershipCommit(IpsecLbError::OwnershipConflict { .. })
    ));
    ownership.set_shard_owner(request.rule.owner, ClusterNode::new("worker-c"));
    assert!(matches!(
        coordinator.repin(request).await.unwrap_err(),
        RePinError::BeforeOwnershipCommit(IpsecLbError::OwnershipConflict { .. })
    ));

    assert!(audit.events().is_empty());
    assert!(fencer.operations().is_empty());
    assert!(steering.operations().is_empty());
    assert_eq!(fencer.owner(sa).unwrap().as_str(), "worker-a");
}

#[tokio::test]
async fn repin_rechecks_target_owner_after_the_sa_fence_before_steering() {
    #[derive(Debug, Clone)]
    struct ShardChangingFencer {
        inner: MockOwnershipFencer,
        ownership: MockOwnershipSource,
        shard: ShardId,
        replacement: ClusterNode,
    }

    #[async_trait::async_trait]
    impl OwnershipFencer for ShardChangingFencer {
        async fn recover_fence_grant(
            &self,
            request: &OwnershipFenceRequest,
        ) -> Result<Option<OwnershipFenceGrant>, IpsecLbError> {
            self.inner.recover_fence_grant(request).await
        }

        async fn fence_sa_owner(
            &self,
            request: OwnershipFenceRequest,
        ) -> Result<OwnershipFenceGrant, IpsecLbError> {
            let grant = self.inner.fence_sa_owner(request).await?;
            self.ownership
                .set_shard_owner(self.shard, self.replacement.clone());
            Ok(grant)
        }

        async fn validate_retry_proof(
            &self,
            proof: &OwnershipRetryProof,
        ) -> Result<(), IpsecLbError> {
            self.inner.validate_retry_proof(proof).await
        }
    }

    let steering = MockSteeringBackend::new();
    let inner_fencer = MockOwnershipFencer::new();
    let ownership = MockOwnershipSource::default();
    let audit = MockRePinAuditSink::new();
    let sa = SaId::Esp { spi: 0x2030_4050 };
    let request = valid_repin_request(sa, SteerKey::EspSpi(0x2030_4050));
    inner_fencer.set_owner(sa, request.previous_owner.clone());
    ownership.set_shard_owner(request.rule.owner, request.new_owner.clone());
    let fencer = ShardChangingFencer {
        inner: inner_fencer,
        ownership: ownership.clone(),
        shard: request.rule.owner,
        replacement: ClusterNode::new("worker-c"),
    };
    let coordinator =
        RePinCoordinator::new(steering.clone(), fencer, ownership.clone(), audit.clone());

    let partial = coordinator
        .repin(request.clone())
        .await
        .unwrap_err()
        .into_partial()
        .expect("the SA fence committed before the target changed");
    assert_eq!(partial.resume_at(), RePinRetryStage::SteeringInstall);
    assert!(matches!(
        partial.cause(),
        IpsecLbError::OwnershipConflict { .. }
    ));
    assert!(steering.operations().is_empty());
    assert_eq!(
        audit
            .events()
            .iter()
            .map(|event| event.kind)
            .collect::<Vec<_>>(),
        vec![RePinAuditEventKind::Attempt, RePinAuditEventKind::Fenced,]
    );

    ownership.set_shard_owner(request.rule.owner, request.new_owner);
    coordinator.retry(partial).await.unwrap();
    assert_eq!(
        steering.operations(),
        vec![MockSteeringOperation::Install(request.rule)]
    );
}

#[tokio::test]
async fn post_commit_proof_read_failure_preserves_a_retryable_single_use_partial() {
    #[derive(Debug, Clone)]
    struct ValidationFailOnceFencer {
        inner: MockOwnershipFencer,
        fail_once: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait::async_trait]
    impl OwnershipFencer for ValidationFailOnceFencer {
        async fn recover_fence_grant(
            &self,
            request: &OwnershipFenceRequest,
        ) -> Result<Option<OwnershipFenceGrant>, IpsecLbError> {
            self.inner.recover_fence_grant(request).await
        }

        async fn fence_sa_owner(
            &self,
            request: OwnershipFenceRequest,
        ) -> Result<OwnershipFenceGrant, IpsecLbError> {
            self.inner.fence_sa_owner(request).await
        }

        async fn validate_retry_proof(
            &self,
            proof: &OwnershipRetryProof,
        ) -> Result<(), IpsecLbError> {
            if self
                .fail_once
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(IpsecLbError::io(
                    "ownership_retry_validation",
                    std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "injected transient read failure",
                    ),
                ));
            }
            self.inner.validate_retry_proof(proof).await
        }
    }

    let steering = MockSteeringBackend::new();
    let inner_fencer = MockOwnershipFencer::new();
    let ownership = MockOwnershipSource::default();
    let audit = MockRePinAuditSink::new();
    let sa = SaId::Esp { spi: 0x3040_5060 };
    let request = valid_repin_request(sa, SteerKey::EspSpi(0x3040_5060));
    inner_fencer.set_owner(sa, request.previous_owner.clone());
    ownership.set_shard_owner(request.rule.owner, request.new_owner.clone());
    let fencer = ValidationFailOnceFencer {
        inner: inner_fencer.clone(),
        fail_once: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
    };
    let coordinator = RePinCoordinator::new(steering.clone(), fencer, ownership, audit.clone());

    let partial = coordinator
        .repin(request.clone())
        .await
        .unwrap_err()
        .into_partial()
        .expect("a successful fencer grant is post-commit state");
    assert_eq!(partial.resume_at(), RePinRetryStage::FencedAudit);
    assert!(matches!(partial.cause(), IpsecLbError::Io { .. }));
    assert_eq!(inner_fencer.owner(sa).unwrap().as_str(), "worker-b");
    assert_eq!(
        audit
            .events()
            .iter()
            .map(|event| event.kind)
            .collect::<Vec<_>>(),
        vec![RePinAuditEventKind::Attempt]
    );
    assert!(steering.operations().is_empty());

    coordinator.retry(partial).await.unwrap();
    assert_eq!(
        steering.operations(),
        vec![MockSteeringOperation::Install(request.rule)]
    );
    assert_eq!(
        audit
            .events()
            .iter()
            .map(|event| event.kind)
            .collect::<Vec<_>>(),
        vec![
            RePinAuditEventKind::Attempt,
            RePinAuditEventKind::Fenced,
            RePinAuditEventKind::SteeringInstalled,
        ]
    );
}

#[tokio::test]
async fn replaying_the_same_request_recovers_the_committed_fence_without_refencing() {
    let steering = MockSteeringBackend::new();
    steering
        .fail_install_on_call(1, IpsecLbError::Unsupported)
        .unwrap();
    let fencer = MockOwnershipFencer::new();
    let ownership = MockOwnershipSource::default();
    let audit = MockRePinAuditSink::new();
    let coordinator = RePinCoordinator::new(
        steering.clone(),
        fencer.clone(),
        ownership.clone(),
        audit.clone(),
    );
    let sa = SaId::Esp { spi: 0x4050_6070 };
    let request = valid_repin_request(sa, SteerKey::EspSpi(0x4050_6070));
    fencer.set_owner(sa, request.previous_owner.clone());
    ownership.set_shard_owner(request.rule.owner, request.new_owner.clone());

    let partial = coordinator
        .repin(request.clone())
        .await
        .unwrap_err()
        .into_partial()
        .unwrap();
    assert_eq!(partial.resume_at(), RePinRetryStage::SteeringInstall);
    let committed_fence = partial.fence();
    drop(partial);

    let altered_resume = RePinRequest {
        resume: SameSpiResume {
            outbound_iv: SameSpiOutboundIvResume::CounterBased {
                checkpointed_send_iv_next: 11,
                restored_send_iv_next: 11 + MIN_SEND_IV_FORWARD_JUMP,
                forward_jump: Some(SendIvForwardJump {
                    forward_jump: MIN_SEND_IV_FORWARD_JUMP,
                    counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
                        max_peer_sequence_lag: 0,
                    },
                }),
            },
            ..request.resume
        },
        ..request.clone()
    };
    assert!(matches!(
        coordinator.repin(altered_resume).await.unwrap_err(),
        RePinError::BeforeOwnershipCommit(IpsecLbError::OwnershipConflict { .. })
    ));
    let altered_rule = RePinRequest {
        rule: SteeringRule {
            shard: ShardId::new(9),
            ..request.rule
        },
        ..request.clone()
    };
    assert!(matches!(
        coordinator.repin(altered_rule).await.unwrap_err(),
        RePinError::BeforeOwnershipCommit(IpsecLbError::OwnershipConflict { .. })
    ));
    assert!(steering.operations().is_empty());

    let outcome = coordinator.repin(request.clone()).await.unwrap();
    assert_eq!(outcome.fence(), committed_fence);
    assert_eq!(fencer.operations().len(), 1);
    assert_eq!(fencer.recovery_attempts(), 4);
    assert_eq!(steering.install_attempts(), 2);
    assert_eq!(
        steering.operations(),
        vec![MockSteeringOperation::Install(request.rule)]
    );
    let kinds = audit
        .events()
        .into_iter()
        .map(|event| event.kind)
        .collect::<Vec<_>>();
    assert_eq!(
        kinds,
        vec![
            RePinAuditEventKind::Attempt,
            RePinAuditEventKind::Fenced,
            RePinAuditEventKind::SteeringInstalled,
        ]
    );
}

#[tokio::test]
async fn stale_transition_cannot_recover_or_refence_after_a_full_aba_owner_cycle() {
    let fencer = MockOwnershipFencer::new();
    let sa = SaId::Esp { spi: 0x4151_6171 };
    fencer.set_owner(sa, ClusterNode::new("worker-a"));
    let old = OwnershipFenceRequest {
        sa,
        transition_id: OwnershipTransitionId::new(1).unwrap(),
        fingerprint: OwnershipTransitionFingerprint::from_bytes([1; 32]),
        previous_fence: opc_ipsec_lb::OwnershipFence::new(1).unwrap(),
        previous_owner: ClusterNode::new("worker-a"),
        new_owner: ClusterNode::new("worker-b"),
    };
    let first = fencer.fence_sa_owner(old.clone()).await.unwrap();
    let second = fencer
        .fence_sa_owner(OwnershipFenceRequest {
            sa,
            transition_id: OwnershipTransitionId::new(2).unwrap(),
            fingerprint: OwnershipTransitionFingerprint::from_bytes([2; 32]),
            previous_fence: first.fence,
            previous_owner: ClusterNode::new("worker-b"),
            new_owner: ClusterNode::new("worker-c"),
        })
        .await
        .unwrap();
    fencer
        .fence_sa_owner(OwnershipFenceRequest {
            sa,
            transition_id: OwnershipTransitionId::new(3).unwrap(),
            fingerprint: OwnershipTransitionFingerprint::from_bytes([3; 32]),
            previous_fence: second.fence,
            previous_owner: ClusterNode::new("worker-c"),
            new_owner: ClusterNode::new("worker-a"),
        })
        .await
        .unwrap();

    assert!(matches!(
        fencer.recover_fence_grant(&old).await.unwrap_err(),
        IpsecLbError::OwnershipConflict { .. }
    ));
    assert!(matches!(
        fencer.fence_sa_owner(old).await.unwrap_err(),
        IpsecLbError::OwnershipConflict { .. }
    ));
    assert_eq!(fencer.operations().len(), 3);
}

#[tokio::test]
async fn retry_converges_after_steering_applied_but_acknowledgement_failed() {
    #[derive(Debug, Clone)]
    struct ApplyThenErrorSteering {
        inner: MockSteeringBackend,
        fail_once: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait::async_trait]
    impl SteeringBackend for ApplyThenErrorSteering {
        async fn install_rule(&self, rule: SteeringRule) -> Result<(), IpsecLbError> {
            self.inner.install_rule(rule).await?;
            if self
                .fail_once
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(IpsecLbError::Unsupported);
            }
            Ok(())
        }

        async fn remove_rule(&self, rule: SteeringRule) -> Result<(), IpsecLbError> {
            self.inner.remove_rule(rule).await
        }

        async fn probe(&self) -> Result<SteeringProbe, IpsecLbError> {
            self.inner.probe().await
        }
    }

    let installed = MockSteeringBackend::new();
    let steering = ApplyThenErrorSteering {
        inner: installed.clone(),
        fail_once: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
    };
    let fencer = MockOwnershipFencer::new();
    let ownership = MockOwnershipSource::default();
    let audit = MockRePinAuditSink::new();
    let coordinator = RePinCoordinator::new(steering, fencer.clone(), ownership.clone(), audit);
    let sa = SaId::Esp { spi: 0x5060_7080 };
    let request = valid_repin_request(sa, SteerKey::EspSpi(0x5060_7080));
    fencer.set_owner(sa, request.previous_owner.clone());
    ownership.set_shard_owner(request.rule.owner, request.new_owner.clone());

    let partial = coordinator
        .repin(request.clone())
        .await
        .unwrap_err()
        .into_partial()
        .unwrap();
    assert_eq!(partial.resume_at(), RePinRetryStage::SteeringInstall);
    coordinator.retry(partial).await.unwrap();

    assert_eq!(installed.install_attempts(), 2);
    assert_eq!(
        installed.operations(),
        vec![MockSteeringOperation::Install(request.rule)]
    );
}

#[tokio::test]
async fn retry_deduplicates_an_audit_event_applied_before_acknowledgement_failed() {
    #[derive(Debug, Clone)]
    struct ApplyThenErrorAudit {
        inner: MockRePinAuditSink,
        fail_once: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait::async_trait]
    impl RePinAuditSink for ApplyThenErrorAudit {
        async fn record_repin(&self, event: RePinAuditEvent) -> Result<(), IpsecLbError> {
            let fail_this_event = event.kind == RePinAuditEventKind::SteeringInstalled
                && self.fail_once.load(std::sync::atomic::Ordering::SeqCst);
            self.inner.record_repin(event).await?;
            if fail_this_event
                && self
                    .fail_once
                    .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(IpsecLbError::Unsupported);
            }
            Ok(())
        }
    }

    let steering = MockSteeringBackend::new();
    let fencer = MockOwnershipFencer::new();
    let ownership = MockOwnershipSource::default();
    let recorded = MockRePinAuditSink::new();
    let audit = ApplyThenErrorAudit {
        inner: recorded.clone(),
        fail_once: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
    };
    let coordinator =
        RePinCoordinator::new(steering.clone(), fencer.clone(), ownership.clone(), audit);
    let sa = SaId::Esp { spi: 0x6070_8090 };
    let request = valid_repin_request(sa, SteerKey::EspSpi(0x6070_8090));
    fencer.set_owner(sa, request.previous_owner.clone());
    ownership.set_shard_owner(request.rule.owner, request.new_owner.clone());

    let partial = coordinator
        .repin(request)
        .await
        .unwrap_err()
        .into_partial()
        .unwrap();
    assert_eq!(partial.resume_at(), RePinRetryStage::SteeringAudit);
    coordinator.retry(partial).await.unwrap();

    assert_eq!(steering.install_attempts(), 1);
    assert_eq!(
        recorded
            .events()
            .iter()
            .filter(|event| event.kind == RePinAuditEventKind::SteeringInstalled)
            .count(),
        1
    );
}

#[tokio::test]
async fn post_commit_failures_retry_from_the_first_incomplete_stage() {
    #[derive(Clone, Copy)]
    enum FailurePoint {
        FencedAudit,
        SteeringInstall,
        SteeringAudit,
    }

    for (failure_point, expected_stage, expected_install_attempts) in [
        (FailurePoint::FencedAudit, RePinRetryStage::FencedAudit, 1),
        (
            FailurePoint::SteeringInstall,
            RePinRetryStage::SteeringInstall,
            2,
        ),
        (
            FailurePoint::SteeringAudit,
            RePinRetryStage::SteeringAudit,
            1,
        ),
    ] {
        let steering = MockSteeringBackend::new();
        let fencer = MockOwnershipFencer::new();
        let ownership = MockOwnershipSource::default();
        let audit = MockRePinAuditSink::new();
        let coordinator = RePinCoordinator::new(
            steering.clone(),
            fencer.clone(),
            ownership.clone(),
            audit.clone(),
        );
        let sa = SaId::Esp { spi: 0x3344_5566 };
        let request = valid_repin_request(sa, SteerKey::EspSpi(0x3344_5566));
        fencer.set_owner(sa, request.previous_owner.clone());
        ownership.set_shard_owner(request.rule.owner, request.new_owner.clone());

        match failure_point {
            FailurePoint::FencedAudit => audit.fail_on_call(2, IpsecLbError::Unsupported).unwrap(),
            FailurePoint::SteeringInstall => steering
                .fail_install_on_call(1, IpsecLbError::Unsupported)
                .unwrap(),
            FailurePoint::SteeringAudit => {
                audit.fail_on_call(3, IpsecLbError::Unsupported).unwrap()
            }
        }

        let partial = coordinator
            .repin(request.clone())
            .await
            .unwrap_err()
            .into_partial()
            .unwrap();
        assert_eq!(partial.resume_at(), expected_stage);
        assert_eq!(partial.cause(), &IpsecLbError::Unsupported);
        assert_eq!(partial.fence().get(), 2);
        assert_eq!(fencer.owner(sa).unwrap().as_str(), "worker-b");

        let outcome = coordinator.retry(partial).await.unwrap();
        assert_eq!(outcome.fence().get(), 2);
        assert_eq!(fencer.operations().len(), 1);
        assert_eq!(fencer.retry_validation_attempts(), 3);
        assert_eq!(steering.install_attempts(), expected_install_attempts);
        assert_eq!(
            steering.operations(),
            vec![MockSteeringOperation::Install(request.rule)]
        );

        let kinds = audit
            .events()
            .into_iter()
            .map(|event| event.kind)
            .collect::<Vec<_>>();
        assert_eq!(
            kinds
                .iter()
                .filter(|kind| **kind == RePinAuditEventKind::Attempt)
                .count(),
            1
        );
        assert_eq!(
            kinds
                .iter()
                .filter(|kind| **kind == RePinAuditEventKind::Fenced)
                .count(),
            1
        );
        assert_eq!(
            kinds
                .iter()
                .filter(|kind| **kind == RePinAuditEventKind::SteeringInstalled)
                .count(),
            1
        );
        assert_eq!(
            kinds
                .iter()
                .filter(|kind| **kind == RePinAuditEventKind::Failed)
                .count(),
            0
        );

        assert_eq!(fencer.operations().len(), 1);
        assert_eq!(steering.operations().len(), 1);
    }
}

#[tokio::test]
async fn retry_rejects_a_superseded_fence_before_audit_or_steering() {
    let steering = MockSteeringBackend::new();
    steering
        .fail_install_on_call(1, IpsecLbError::Unsupported)
        .unwrap();
    let fencer = MockOwnershipFencer::new();
    let ownership = MockOwnershipSource::default();
    let audit = MockRePinAuditSink::new();
    let coordinator = RePinCoordinator::new(
        steering.clone(),
        fencer.clone(),
        ownership.clone(),
        audit.clone(),
    );
    let sa = SaId::Esp { spi: 0x4455_6677 };
    let request = valid_repin_request(sa, SteerKey::EspSpi(0x4455_6677));
    fencer.set_owner(sa, request.previous_owner.clone());
    ownership.set_shard_owner(request.rule.owner, request.new_owner.clone());

    let partial = coordinator
        .repin(request.clone())
        .await
        .unwrap_err()
        .into_partial()
        .unwrap();
    fencer
        .fence_sa_owner(OwnershipFenceRequest {
            sa,
            transition_id: OwnershipTransitionId::new(2).unwrap(),
            fingerprint: OwnershipTransitionFingerprint::from_bytes([2; 32]),
            previous_fence: opc_ipsec_lb::OwnershipFence::new(2).unwrap(),
            previous_owner: request.new_owner,
            new_owner: ClusterNode::new("worker-c"),
        })
        .await
        .unwrap();
    let events_before_retry = audit.events();

    let error = coordinator.retry(partial).await.unwrap_err();
    assert!(matches!(
        error,
        RePinError::AfterOwnershipCommit(partial)
            if matches!(partial.cause(), IpsecLbError::OwnershipConflict { .. })
    ));
    assert_eq!(fencer.retry_validation_attempts(), 3);
    assert_eq!(audit.events(), events_before_retry);
    assert_eq!(steering.install_attempts(), 1);
    assert!(steering.operations().is_empty());
}
