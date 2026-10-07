use opc_proto_ikev2::{
    Ikev2AesGcmIvAllocator as Allocator, Ikev2AesGcmIvDomain as Domain,
    Ikev2AesGcmIvLimits as Limits, Ikev2AesGcmIvPurpose as Purpose, Ikev2AesGcmIvRecord as Record,
    Ikev2AesGcmIvReservationError as Error, Ikev2DhGroup, Ikev2EncryptionAlgorithm as Encryption,
    Ikev2IntegrityAlgorithm, Ikev2PrfAlgorithm, Ikev2ProtectedPayloadCryptoError,
    Ikev2ProtectedPayloadDirection as Direction, Ikev2SaInitCryptoProfile as Profile,
    Ikev2SaInitKeyMaterial as Keys, PayloadType, ProtectedPayloadKind as Kind,
    ProtectedPayloadSealContext as Context, IKEV2_AES_GCM_MAX_RESERVED_ALLOCATIONS,
    IKEV2_AES_GCM_NORMAL_IV_END,
};

mod support;

const INITIATOR_SPI: u64 = 0x0102_0304_0506_0708;
const RESPONDER_SPI: u64 = 0x1112_1314_1516_1718;
const DIRECTIONS: [Direction; 2] = [
    Direction::InitiatorToResponder,
    Direction::ResponderToInitiator,
];
const ALGORITHMS: [Encryption; 3] = [
    Encryption::AesGcm16_128,
    Encryption::AesGcm16_192,
    Encryption::AesGcm16_256,
];

fn profile(encryption: Encryption) -> Profile {
    Profile::new_aead(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2DhGroup::Ecp256,
        encryption,
    )
    .unwrap()
}

fn keys(profile: Profile, key_change: u8, salt_change: u8) -> Keys {
    let len = profile.encryption().key_material_len();
    let mut ei = vec![0x41; len];
    let mut er = vec![0x62; len];
    ei[0] ^= key_change;
    er[0] ^= key_change;
    ei[len - 1] ^= salt_change;
    er[len - 1] ^= salt_change;
    Keys::from_established_keys(
        profile,
        false,
        &[0x11; 32],
        &[],
        &[],
        &ei,
        &er,
        &[0x22; 32],
        &[0x33; 32],
    )
    .unwrap()
}

fn domain(profile: Profile, keys: &Keys, direction: Direction) -> Domain {
    support::iv_domain(INITIATOR_SPI, RESPONDER_SPI, direction, profile, keys).unwrap()
}

fn inputs<'a>(
    profile: Profile,
    keys: &'a Keys,
    domain: &Domain,
) -> opc_proto_ikev2::Ikev2AesGcmEpochInputs<'a> {
    support::epoch_inputs(
        domain.initiator_spi(),
        domain.responder_spi(),
        domain.direction(),
        profile,
        keys,
    )
}

fn fixture() -> (Profile, Keys, Domain, Limits) {
    let profile = profile(Encryption::AesGcm16_128);
    let keys = keys(profile, 0, 0);
    let domain = domain(profile, &keys, DIRECTIONS[0]);
    (profile, keys, domain, Limits::new(32, 2, 1, 2).unwrap())
}

fn prefix(direction: Direction, kind: Kind) -> Vec<u8> {
    let fragmented = kind == Kind::EncryptedFragment;
    let mut prefix = vec![0; 32];
    prefix[..8].copy_from_slice(&INITIATOR_SPI.to_be_bytes());
    prefix[8..16].copy_from_slice(&RESPONDER_SPI.to_be_bytes());
    prefix[16] = if fragmented {
        PayloadType::EncryptedFragment
    } else {
        PayloadType::Encrypted
    }
    .as_u8();
    prefix[17] = 0x20;
    prefix[18] = 37;
    prefix[19] = if direction == DIRECTIONS[0] { 8 } else { 0 };
    prefix[20..24].copy_from_slice(&1_u32.to_be_bytes());
    prefix[24..28].copy_from_slice(&(if fragmented { 61_u32 } else { 57 }).to_be_bytes());
    prefix[30..32].copy_from_slice(&(if fragmented { 33_u16 } else { 29 }).to_be_bytes());
    if fragmented {
        prefix.extend_from_slice(&[0, 1, 0, 2]);
    }
    prefix
}

fn commit(allocator: &mut Allocator, count: u64, purpose: Purpose) -> Record {
    let prepared = allocator.prepare(count, purpose).unwrap();
    let durable = prepared.record().clone();
    prepared.activate_after_commit(&durable).unwrap();
    durable
}

fn seal_next(
    allocator: &mut Allocator,
    profile: Profile,
    keys: &Keys,
    direction: Direction,
    purpose: Purpose,
) -> u64 {
    support::ensure_ike_crypto();
    let prefix = prefix(direction, Kind::Encrypted);
    let body = allocator
        .allocate(purpose)
        .unwrap()
        .seal(
            profile,
            keys,
            Context {
                kind: Kind::Encrypted,
                message_prefix: &prefix,
            },
            &[],
            0,
        )
        .unwrap();
    u64::from_be_bytes(body[..8].try_into().unwrap())
}

#[test]
fn reservation_must_commit_before_allocation_and_cannot_replace_an_active_block() {
    let (profile, keys, domain, limits) = fixture();
    let mut allocator = Allocator::fresh(inputs(profile, &keys, &domain), limits).unwrap();
    assert_eq!(
        allocator.allocate(Purpose::Ordinary).unwrap_err(),
        Error::ReservationRequired
    );
    {
        let prepared = allocator.prepare(3, Purpose::Ordinary).unwrap();
        assert_eq!(prepared.record().exclusive_end(), 3);
        // Cancellation, including a storage error, never activates the block.
    }
    assert_eq!(
        allocator.allocate(Purpose::Ordinary).unwrap_err(),
        Error::ReservationRequired
    );
    let record = commit(&mut allocator, 3, Purpose::Ordinary);
    assert_eq!(record.exclusive_end(), 6);
    assert_eq!(record.limits(), limits);
    assert_eq!(
        seal_next(
            &mut allocator,
            profile,
            &keys,
            DIRECTIONS[0],
            Purpose::Ordinary
        ),
        3
    );
    assert_eq!(
        allocator.prepare(1, Purpose::Ordinary).unwrap_err(),
        Error::ActiveReservation
    );
    for value in [4, 5] {
        assert_eq!(
            seal_next(
                &mut allocator,
                profile,
                &keys,
                DIRECTIONS[0],
                Purpose::Ordinary
            ),
            value
        );
    }
    assert_eq!(
        allocator.allocate(Purpose::Ordinary).unwrap_err(),
        Error::ReservationRequired
    );
}

#[test]
fn failed_uncertain_and_mismatched_commits_never_release_the_proposed_ivs() {
    for storage_outcome in ["failed", "uncertain", "mismatched"] {
        let (profile, keys, domain, limits) = fixture();
        let mut allocator = Allocator::fresh(inputs(profile, &keys, &domain), limits).unwrap();
        let prepared = allocator.prepare(4, Purpose::Ordinary).unwrap();
        let proposed = prepared.record().clone();
        if storage_outcome == "mismatched" {
            let old = Record::from_persisted(inputs(profile, &keys, &domain), limits, 0, Some(1))
                .unwrap();
            assert_eq!(
                prepared.activate_after_commit(&old),
                Err(Error::CommitMismatch)
            );
        } else {
            drop(prepared);
        }
        assert_eq!(
            allocator.allocate(Purpose::Ordinary).unwrap_err(),
            Error::ReservationRequired
        );
        if storage_outcome == "uncertain" {
            // A durable write whose acknowledgement was lost is found on restore.
            allocator = Allocator::restore(&domain, &proposed).unwrap();
            assert_eq!(
                allocator.allocate(Purpose::Ordinary).unwrap_err(),
                Error::ReservationRequired
            );
        }
        assert_eq!(
            commit(&mut allocator, 2, Purpose::Ordinary).exclusive_end(),
            6
        );
        assert_eq!(
            seal_next(
                &mut allocator,
                profile,
                &keys,
                DIRECTIONS[0],
                Purpose::Ordinary
            ),
            4
        );
    }
}

#[test]
fn restore_discards_unused_tail_and_repeated_crashes_keep_advancing() {
    let (profile, keys, domain, limits) = fixture();
    let mut allocator = Allocator::fresh(inputs(profile, &keys, &domain), limits).unwrap();
    let mut durable = commit(&mut allocator, 4, Purpose::Ordinary);
    assert_eq!(
        seal_next(
            &mut allocator,
            profile,
            &keys,
            DIRECTIONS[0],
            Purpose::Ordinary
        ),
        0
    );
    for expected in [4, 7, 10] {
        // Rebuild the record from consumer-persisted fields, not an allocator clone.
        let (messages, fragments, attempts) = durable.limits().control_budget();
        let restored_limits = Limits::new(
            durable.limits().hard_ceiling(),
            messages,
            fragments,
            attempts,
        )
        .unwrap();
        durable = Record::from_persisted(
            inputs(profile, &keys, &domain),
            restored_limits,
            durable.exclusive_end(),
            durable.canonical_format(),
        )
        .unwrap();
        allocator = Allocator::restore(&domain, &durable).unwrap();
        assert_eq!(
            allocator.allocate(Purpose::Ordinary).unwrap_err(),
            Error::ReservationRequired
        );
        durable = commit(&mut allocator, 3, Purpose::Ordinary);
        assert_eq!(
            seal_next(
                &mut allocator,
                profile,
                &keys,
                DIRECTIONS[0],
                Purpose::Ordinary
            ),
            expected
        );
    }
    assert_eq!(durable.exclusive_end(), 13);
}

#[test]
fn checked_control_budget_preserves_rekey_delete_headroom_until_hard_exhaustion() {
    assert_eq!(IKEV2_AES_GCM_NORMAL_IV_END, 0xffff_ffff_0000_0000);
    assert_eq!(IKEV2_AES_GCM_MAX_RESERVED_ALLOCATIONS, 1_u64 << 32);
    let (profile, keys, domain, _) = fixture();
    let limits = Limits::new(20, 2, 1, 2).unwrap();
    assert_eq!(limits.hard_ceiling(), 20);
    assert_eq!(limits.control_reserve(), 4);
    assert_eq!(limits.soft_threshold(), 16);
    let mut allocator = Allocator::fresh(inputs(profile, &keys, &domain), limits).unwrap();
    assert_eq!(
        allocator.prepare(17, Purpose::Ordinary).unwrap_err(),
        Error::RekeyRequired
    );
    commit(&mut allocator, 16, Purpose::Ordinary);
    for value in 0..16 {
        assert_eq!(
            seal_next(
                &mut allocator,
                profile,
                &keys,
                DIRECTIONS[0],
                Purpose::Ordinary
            ),
            value
        );
    }
    assert_eq!(
        allocator.allocate(Purpose::Ordinary).unwrap_err(),
        Error::RekeyRequired
    );
    assert_eq!(
        allocator.prepare(1, Purpose::Ordinary).unwrap_err(),
        Error::RekeyRequired
    );
    let durable = commit(&mut allocator, 4, Purpose::Control);
    assert_eq!(
        allocator.allocate(Purpose::Ordinary).unwrap_err(),
        Error::RekeyRequired
    );
    for value in 16..20 {
        assert_eq!(
            seal_next(
                &mut allocator,
                profile,
                &keys,
                DIRECTIONS[0],
                Purpose::Control
            ),
            value
        );
    }
    for purpose in [Purpose::Ordinary, Purpose::Control] {
        assert_eq!(allocator.allocate(purpose).unwrap_err(), Error::Exhausted);
        assert_eq!(allocator.prepare(1, purpose).unwrap_err(), Error::Exhausted);
        assert_eq!(
            Allocator::restore(&domain, &durable)
                .unwrap()
                .allocate(purpose)
                .unwrap_err(),
            Error::Exhausted
        );
    }
}

#[test]
fn invalid_budgets_counts_and_persisted_bounds_are_rejected_without_wraparound() {
    for (hard, messages, fragments, attempts) in [
        (0, 2, 1, 1),
        (2, 2, 1, 1),
        (10, 1, 1, 1),
        (10, 2, 0, 1),
        (10, 2, 1, 0),
        (u64::MAX, 2, 1, 1),
        ((1_u64 << 32) + 1, 2, 1, 1),
        (1_u64 << 32, u32::MAX, u32::MAX, u32::MAX),
    ] {
        assert_eq!(
            Limits::new(hard, messages, fragments, attempts),
            Err(Error::InvalidLimits)
        );
    }
    let (profile, keys, domain, limits) = fixture();
    assert!(Limits::new(1_u64 << 32, 2, 1, 1).is_ok());
    let mut allocator = Allocator::fresh(inputs(profile, &keys, &domain), limits).unwrap();
    assert_eq!(
        allocator.prepare(0, Purpose::Ordinary).unwrap_err(),
        Error::InvalidCount
    );
    commit(&mut allocator, 2, Purpose::Ordinary);
    let record =
        Record::from_persisted(inputs(profile, &keys, &domain), limits, 10, Some(1)).unwrap();
    let mut allocator = Allocator::restore(&domain, &record).unwrap();
    assert_eq!(
        allocator.prepare(u64::MAX, Purpose::Control).unwrap_err(),
        Error::Exhausted
    );
    assert_eq!(
        commit(&mut allocator, 1, Purpose::Ordinary).exclusive_end(),
        11
    );
    for end in [
        limits.hard_ceiling() + 1,
        IKEV2_AES_GCM_NORMAL_IV_END,
        u64::MAX,
    ] {
        assert_eq!(
            Record::from_persisted(inputs(profile, &keys, &domain), limits, end, Some(1)),
            Err(Error::InvalidRecord)
        );
    }
}

#[test]
fn restore_and_commit_bind_exact_key_salt_direction_algorithm_and_spis() {
    for algorithm in ALGORITHMS {
        let profile = profile(algorithm);
        let keys = keys(profile, 0, 0);
        for direction in DIRECTIONS {
            let domain = domain(profile, &keys, direction);
            let limits = Limits::new(12, 2, 1, 1).unwrap();
            let record =
                Record::from_persisted(inputs(profile, &keys, &domain), limits, 4, Some(1))
                    .unwrap();
            assert!(Allocator::restore(&domain, &record).is_ok());
            let changed_profile = different_profile(algorithm);
            let make_record = |i, r, d, p, k: &Keys| {
                Record::from_persisted(support::epoch_inputs(i, r, d, p, k), limits, 4, Some(1))
            };
            let different = [
                make_record(INITIATOR_SPI + 1, RESPONDER_SPI, direction, profile, &keys).unwrap(),
                make_record(INITIATOR_SPI, RESPONDER_SPI + 1, direction, profile, &keys).unwrap(),
                make_record(
                    INITIATOR_SPI,
                    RESPONDER_SPI,
                    if direction == DIRECTIONS[0] {
                        DIRECTIONS[1]
                    } else {
                        DIRECTIONS[0]
                    },
                    profile,
                    &keys,
                )
                .unwrap(),
                make_record(
                    INITIATOR_SPI,
                    RESPONDER_SPI,
                    direction,
                    profile,
                    &self::keys(profile, 1, 0),
                )
                .unwrap(),
                make_record(
                    INITIATOR_SPI,
                    RESPONDER_SPI,
                    direction,
                    profile,
                    &self::keys(profile, 0, 1),
                )
                .unwrap(),
                make_record(
                    INITIATOR_SPI,
                    RESPONDER_SPI,
                    direction,
                    changed_profile,
                    &self::keys(changed_profile, 0, 0),
                )
                .unwrap(),
            ];
            for other in different {
                assert_eq!(
                    Allocator::restore(other.domain(), &record).unwrap_err(),
                    Error::DomainMismatch
                );
                let mut allocator =
                    Allocator::fresh(inputs(profile, &keys, &domain), limits).unwrap();
                let prepared = allocator.prepare(4, Purpose::Ordinary).unwrap();
                let wrong = other;
                assert_eq!(
                    prepared.activate_after_commit(&wrong),
                    Err(Error::CommitMismatch)
                );
                assert_eq!(
                    allocator.allocate(Purpose::Ordinary).unwrap_err(),
                    Error::ReservationRequired
                );
            }
            let mut allocator = Allocator::fresh(inputs(profile, &keys, &domain), limits).unwrap();
            let prepared = allocator.prepare(4, Purpose::Ordinary).unwrap();
            let wrong = Record::from_persisted(
                inputs(profile, &keys, &domain),
                Limits::new(13, 2, 1, 1).unwrap(),
                4,
                Some(1),
            )
            .unwrap();
            assert_eq!(
                prepared.activate_after_commit(&wrong),
                Err(Error::CommitMismatch)
            );
        }
    }
}

fn different_profile(algorithm: Encryption) -> Profile {
    profile(if algorithm == Encryption::AesGcm16_128 {
        Encryption::AesGcm16_256
    } else {
        Encryption::AesGcm16_128
    })
}

#[test]
fn invalid_and_colliding_directional_domains_are_rejected() {
    let (profile, keys, _, _) = fixture();
    for (i, r) in [(0, RESPONDER_SPI), (INITIATOR_SPI, 0)] {
        assert_eq!(
            support::iv_domain(i, r, DIRECTIONS[0], profile, &keys),
            Err(Error::InvalidDomain)
        );
    }
    let cbc = Profile::new_encrypt_then_mac(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2DhGroup::Ecp256,
        Encryption::AesCbc128,
        Ikev2IntegrityAlgorithm::HmacSha2_256_128,
    )
    .unwrap();
    assert_eq!(
        support::iv_domain(INITIATOR_SPI, RESPONDER_SPI, DIRECTIONS[0], cbc, &keys),
        Err(Error::InvalidDomain)
    );
    let equal_keys = Keys::from_established_keys(
        profile,
        false,
        keys.sk_d(),
        &[],
        &[],
        keys.sk_ei(),
        keys.sk_ei(),
        keys.sk_pi(),
        keys.sk_pr(),
    )
    .unwrap();
    assert_eq!(
        support::iv_domain(
            INITIATOR_SPI,
            RESPONDER_SPI,
            DIRECTIONS[0],
            profile,
            &equal_keys
        ),
        Err(Error::InvalidDomain)
    );
}

#[test]
fn allocated_tokens_seal_both_payload_kinds_and_burn_on_failed_sealing() {
    support::ensure_ike_crypto();
    for algorithm in ALGORITHMS {
        let profile = profile(algorithm);
        let keys = keys(profile, 0, 0);
        for direction in DIRECTIONS {
            let domain = domain(profile, &keys, direction);
            let mut allocator = Allocator::fresh(
                inputs(profile, &keys, &domain),
                Limits::new(16, 2, 1, 1).unwrap(),
            )
            .unwrap();
            commit(&mut allocator, 8, Purpose::Ordinary);
            for (value, kind) in [Kind::Encrypted, Kind::EncryptedFragment]
                .into_iter()
                .enumerate()
            {
                let prefix = prefix(direction, kind);
                let body = allocator
                    .allocate(Purpose::Ordinary)
                    .unwrap()
                    .seal(
                        profile,
                        &keys,
                        Context {
                            kind,
                            message_prefix: &prefix,
                        },
                        &[],
                        0,
                    )
                    .unwrap();
                assert_eq!(&body[..8], &(value as u64).to_be_bytes());
            }
            for wrong in [self::keys(profile, 1, 0), self::keys(profile, 0, 1)] {
                let prefix = prefix(direction, Kind::Encrypted);
                assert_eq!(
                    allocator.allocate(Purpose::Ordinary).unwrap().seal(
                        profile,
                        &wrong,
                        Context {
                            kind: Kind::Encrypted,
                            message_prefix: &prefix
                        },
                        &[],
                        0
                    ),
                    Err(Error::DomainMismatch)
                );
            }
            for offset in [0, 8, 19] {
                let mut prefix = prefix(direction, Kind::Encrypted);
                prefix[offset] ^= 8;
                assert_eq!(
                    allocator.allocate(Purpose::Ordinary).unwrap().seal(
                        profile,
                        &keys,
                        Context {
                            kind: Kind::Encrypted,
                            message_prefix: &prefix
                        },
                        &[],
                        0
                    ),
                    Err(Error::DomainMismatch)
                );
            }
            let mut malformed = prefix(direction, Kind::Encrypted);
            malformed[27] = 0;
            assert_eq!(
                allocator.allocate(Purpose::Ordinary).unwrap().seal(
                    profile,
                    &keys,
                    Context {
                        kind: Kind::Encrypted,
                        message_prefix: &malformed
                    },
                    &[],
                    0
                ),
                Err(Error::Crypto(
                    Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData
                ))
            );
            assert_eq!(
                allocator.allocate(Purpose::Ordinary).unwrap_err(),
                Error::ReservationRequired
            );
            commit(&mut allocator, 1, Purpose::Ordinary);
            assert_eq!(
                seal_next(&mut allocator, profile, &keys, direction, Purpose::Ordinary),
                8
            );
        }
    }
}

#[test]
fn descriptor_records_and_tokens_redact_keys_counters_and_ivs() {
    let (profile, keys, domain, limits) = fixture();
    assert_eq!(format!("{domain:?}"), "Ikev2AesGcmIvDomain { .. }");
    let mut allocator = Allocator::fresh(inputs(profile, &keys, &domain), limits).unwrap();
    assert_eq!(format!("{allocator:?}"), "Ikev2AesGcmIvAllocator { .. }");
    let prepared = allocator.prepare(2, Purpose::Ordinary).unwrap();
    assert_eq!(
        format!("{prepared:?}"),
        "Ikev2AesGcmPreparedIvReservation { .. }"
    );
    let durable = prepared.record().clone();
    assert_eq!(format!("{durable:?}"), "Ikev2AesGcmIvRecord { .. }");
    prepared.activate_after_commit(&durable).unwrap();
    assert_eq!(
        format!("{:?}", allocator.allocate(Purpose::Ordinary).unwrap()),
        "Ikev2AesGcmIvAllocation { .. }"
    );
    assert_eq!(
        Error::CommitMismatch.to_string(),
        "IKEv2 IV reservation commit mismatch"
    );
}

#[test]
fn exact_commit_binds_control_budget_even_when_total_headroom_is_equal() {
    let (profile, keys, domain, limits) = fixture();
    let mut allocator = Allocator::fresh(inputs(profile, &keys, &domain), limits).unwrap();
    let prepared = allocator.prepare(2, Purpose::Ordinary).unwrap();
    let changed_budget = Limits::new(32, 2, 2, 1).unwrap();
    assert_eq!(limits.control_reserve(), changed_budget.control_reserve());
    let wrong = Record::from_persisted(inputs(profile, &keys, &domain), changed_budget, 2, Some(1))
        .unwrap();
    assert_eq!(
        prepared.activate_after_commit(&wrong),
        Err(Error::CommitMismatch)
    );
}

#[test]
fn maximum_per_key_ceiling_allocates_its_last_iv_then_stops() {
    let (profile, keys, domain, _) = fixture();
    let hard = IKEV2_AES_GCM_MAX_RESERVED_ALLOCATIONS;
    let limits = Limits::new(hard, 2, 1, 1).unwrap();
    let previous =
        Record::from_persisted(inputs(profile, &keys, &domain), limits, hard - 1, Some(1)).unwrap();
    let mut allocator = Allocator::restore(&domain, &previous).unwrap();
    let last = commit(&mut allocator, 1, Purpose::Control);
    assert_eq!(
        allocator.allocate(Purpose::Ordinary).unwrap_err(),
        Error::RekeyRequired
    );
    assert_eq!(
        seal_next(
            &mut allocator,
            profile,
            &keys,
            DIRECTIONS[0],
            Purpose::Control
        ),
        hard - 1
    );
    assert_eq!(last.exclusive_end(), hard);
    assert_eq!(
        allocator.allocate(Purpose::Control).unwrap_err(),
        Error::Exhausted
    );
}

#[test]
fn persisted_record_at_exact_hard_ceiling_restores_as_exhausted() {
    let (profile, keys, domain, _) = fixture();
    for hard in [32, IKEV2_AES_GCM_MAX_RESERVED_ALLOCATIONS] {
        let limits = Limits::new(hard, 2, 1, 1).unwrap();
        let persisted = Record::from_persisted(
            inputs(profile, &keys, &domain),
            limits,
            limits.hard_ceiling(),
            Some(1),
        )
        .expect("a fully consumed key has a valid persisted record");
        let mut restored = Allocator::restore(&domain, &persisted).unwrap();
        for purpose in [Purpose::Ordinary, Purpose::Control] {
            assert_eq!(restored.allocate(purpose).unwrap_err(), Error::Exhausted);
            assert_eq!(restored.prepare(1, purpose).unwrap_err(), Error::Exhausted);
        }
    }
}
