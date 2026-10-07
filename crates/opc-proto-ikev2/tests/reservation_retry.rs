use opc_proto_ikev2::{
    recovery::{
        Ikev2ReservationRetry as Retry, Ikev2ReservationRetryError as Error,
        Ikev2ReservationRetryPolicy as Policy, Ikev2ReservationRetryRecord as Record,
    },
    Ikev2AesGcmIvAllocator as Allocator, Ikev2AesGcmIvDomain as Domain,
    Ikev2AesGcmIvLimits as Limits, Ikev2AesGcmIvPurpose as Purpose,
    Ikev2AesGcmIvReservationError as IvError, Ikev2DhGroup, Ikev2EncryptionAlgorithm,
    Ikev2PrfAlgorithm, Ikev2ProtectedPayloadDirection, Ikev2SaInitCryptoProfile,
    Ikev2SaInitKeyMaterial,
};

mod support;

fn key_material() -> (Ikev2SaInitCryptoProfile, Ikev2SaInitKeyMaterial) {
    let profile = Ikev2SaInitCryptoProfile::new_aead(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2DhGroup::Ecp256,
        Ikev2EncryptionAlgorithm::AesGcm16_128,
    )
    .unwrap();
    let keys = Ikev2SaInitKeyMaterial::from_established_keys(
        profile,
        false,
        &[0x11; 32],
        &[],
        &[],
        &[0x41; 20],
        &[0x62; 20],
        &[0x22; 32],
        &[0x33; 32],
    )
    .unwrap();
    (profile, keys)
}
fn domain() -> Domain {
    let (profile, keys) = key_material();
    support::iv_domain(
        0x101,
        0x202,
        Ikev2ProtectedPayloadDirection::ResponderToInitiator,
        profile,
        &keys,
    )
    .unwrap()
}
fn policy() -> Policy {
    Policy::new(1_000, 2_000, 3, 100).unwrap()
}
fn allocator(domain: &Domain) -> Allocator {
    let (profile, keys) = key_material();
    Allocator::fresh(
        support::epoch_inputs(
            domain.initiator_spi(),
            domain.responder_spi(),
            domain.direction(),
            profile,
            &keys,
        ),
        Limits::new(128, 2, 1, 2).unwrap(),
    )
    .unwrap()
}
fn initial(domain: &Domain) -> Record {
    Record::initial(domain.clone(), 7, policy())
}
fn restore(domain: &Domain, record: &Record) -> Retry {
    Retry::restore(domain, 7, record).unwrap()
}

#[test]
fn attempt_charge_must_commit_before_any_iv_block_can_be_prepared() {
    let domain = domain();
    let original = initial(&domain);
    let mut retry = restore(&domain, &original);
    let mut allocator = allocator(&domain);
    let charge = retry.prepare_attempt(&allocator, 1_000, false).unwrap();
    assert_eq!(charge.record().attempts(), 1);
    assert_eq!(charge.record().last_attempt_unix_ms(), Some(1_000));
    assert!(matches!(
        charge.commit_after_durable(&original),
        Err(Error::CommitMismatch)
    ));
    assert!(matches!(
        retry.prepare_attempt(&allocator, 1_100, false),
        Err(Error::CommitUncertain)
    ));
    assert_eq!(retry.record(), &original);
    assert_eq!(
        allocator.allocate(Purpose::Ordinary).unwrap_err(),
        IvError::ReservationRequired
    );
    // Failed charge burned no block. Readback proves the old charge record remained.
    retry = restore(&domain, &original);
    let charge = retry.prepare_attempt(&allocator, 1_000, false).unwrap();
    let durable = charge.record().clone();
    let permit = charge.commit_after_durable(&durable).unwrap();
    let block = permit
        .prepare(&mut allocator, 4, Purpose::Ordinary, 1_000, false)
        .unwrap();
    assert_eq!(block.record().exclusive_end(), 4);
    let durable_iv = block.record().clone();
    block
        .activate_after_commit(&durable_iv, 1_000, false)
        .unwrap();
    assert_eq!(retry.record(), &durable);
    assert!(allocator.allocate(Purpose::Ordinary).is_ok());
}

#[test]
fn cancellation_after_charge_commit_consumes_the_attempt_across_repeated_crashes() {
    let domain = domain();
    let mut retry = restore(&domain, &initial(&domain));
    let allocator = allocator(&domain);
    let charge = retry.prepare_attempt(&allocator, 1_000, false).unwrap();
    let durable = charge.record().clone();
    drop(charge.commit_after_durable(&durable).unwrap());
    assert!(matches!(
        retry.prepare_attempt(&allocator, 1_100, false),
        Err(Error::CommitUncertain)
    ));
    for _ in 0..8 {
        retry = restore(&domain, &durable);
        assert_eq!(retry.record().attempts(), 1);
        assert_eq!(retry.record().policy(), policy());
        assert!(matches!(
            retry.prepare_attempt(&allocator, 1_099, false),
            Err(Error::Backoff)
        ));
    }
    let charge = retry.prepare_attempt(&allocator, 1_100, false).unwrap();
    assert_eq!(charge.record().attempts(), 2);
}

#[test]
fn prolonged_uncertain_storage_outage_has_three_backed_off_blocks_and_no_send_authority() {
    let domain = domain();
    let mut durable_charge = initial(&domain);
    let mut allocator = allocator(&domain);
    let mut last_end = 0;
    for attempt in 1..=3 {
        let now = 1_000 + 100 * u64::from(attempt - 1);
        let mut retry = restore(&domain, &durable_charge);
        let charge = retry.prepare_attempt(&allocator, now, false).unwrap();
        durable_charge = charge.record().clone();
        assert_eq!(durable_charge.attempts(), attempt);
        let permit = charge.commit_after_durable(&durable_charge).unwrap();
        let block = permit
            .prepare(&mut allocator, 4, Purpose::Ordinary, now, false)
            .unwrap();
        let uncertain_iv = block.record().clone();
        assert_eq!(uncertain_iv.exclusive_end(), last_end + 4);
        last_end = uncertain_iv.exclusive_end();
        drop(block); // The store may have committed, but its acknowledgement was lost.
        assert_eq!(
            allocator.allocate(Purpose::Ordinary).unwrap_err(),
            IvError::ReservationRequired
        );
        assert!(matches!(
            retry.prepare_attempt(&allocator, now + 100, false),
            Err(Error::CommitUncertain)
        ));
        // No retry until older writes are settled and both latest records are read back.
        allocator = Allocator::restore(&domain, &uncertain_iv).unwrap();
        for _ in 0..4 {
            let mut restarted = restore(&domain, &durable_charge);
            let failure = restarted.prepare_attempt(&allocator, now + 99, false);
            if attempt < 3 {
                assert!(matches!(failure, Err(Error::Backoff)));
            } else {
                assert!(matches!(failure, Err(Error::Closed)));
            }
            assert_eq!(restarted.record().attempts(), attempt);
        }
    }
    let mut retry = restore(&domain, &durable_charge);
    assert!(matches!(
        retry.prepare_attempt(&allocator, 1_500, false),
        Err(Error::Closed)
    ));
    assert_eq!(last_end, 12);
    assert_eq!(durable_charge.policy().deadline_unix_ms(), 2_000);
}

#[test]
fn active_blocks_forbid_reserve_ahead_without_consuming_an_attempt() {
    let domain = domain();
    let mut retry = restore(&domain, &initial(&domain));
    let mut allocator = allocator(&domain);
    let charge = retry.prepare_attempt(&allocator, 1_000, false).unwrap();
    let durable = charge.record().clone();
    let block = charge
        .commit_after_durable(&durable)
        .unwrap()
        .prepare(&mut allocator, 4, Purpose::Ordinary, 1_000, false)
        .unwrap();
    let iv_record = block.record().clone();
    block
        .activate_after_commit(&iv_record, 1_000, false)
        .unwrap();
    for _ in 0..4 {
        assert!(matches!(
            retry.prepare_attempt(&allocator, 1_100, false),
            Err(Error::Iv(IvError::ActiveReservation))
        ));
        assert_eq!(retry.record().attempts(), 1);
        drop(allocator.allocate(Purpose::Ordinary).unwrap());
    }
    let charge = retry.prepare_attempt(&allocator, 1_100, false).unwrap();
    let durable = charge.record().clone();
    let block = charge
        .commit_after_durable(&durable)
        .unwrap()
        .prepare(&mut allocator, 4, Purpose::Ordinary, 1_100, false)
        .unwrap();
    assert_eq!(block.record().exclusive_end(), 8);
    drop(block);
    assert_eq!(
        allocator.allocate(Purpose::Ordinary).unwrap_err(),
        IvError::ReservationRequired
    );
}

#[test]
fn fixed_deadline_and_clock_discontinuity_expire_each_stage_without_releasing_ivs() {
    let domain = domain();
    for (now, stepped) in [
        (999, false),
        (2_000, false),
        (1_001, true),
        (u64::MAX, false),
    ] {
        let mut retry = restore(&domain, &initial(&domain));
        let allocator = allocator(&domain);
        assert!(matches!(
            retry.prepare_attempt(&allocator, now, stepped),
            Err(Error::Closed)
        ));
        assert!(matches!(
            retry.prepare_attempt(&allocator, 1_100, false),
            Err(Error::Closed)
        ));
    }
    for activation in [false, true] {
        for (now, stepped) in [(999, false), (2_000, false), (1_001, true)] {
            let mut retry = restore(&domain, &initial(&domain));
            let mut allocator = allocator(&domain);
            let charge = retry.prepare_attempt(&allocator, 1_000, false).unwrap();
            let durable = charge.record().clone();
            let permit = charge.commit_after_durable(&durable).unwrap();
            if activation {
                let block = permit
                    .prepare(&mut allocator, 4, Purpose::Ordinary, 1_000, false)
                    .unwrap();
                let iv_record = block.record().clone();
                assert!(matches!(
                    block.activate_after_commit(&iv_record, now, stepped),
                    Err(Error::Closed)
                ));
            } else {
                assert!(matches!(
                    permit.prepare(&mut allocator, 4, Purpose::Ordinary, now, stepped),
                    Err(Error::Closed)
                ));
            }
            assert_eq!(
                allocator.allocate(Purpose::Ordinary).unwrap_err(),
                IvError::ReservationRequired
            );
            assert!(matches!(
                retry.prepare_attempt(&allocator, 1_100, false),
                Err(Error::Closed)
            ));
        }
    }
}

#[test]
fn rollback_since_the_previous_attempt_and_checked_backoff_never_extend_the_budget() {
    let domain = domain();
    let mut retry = restore(&domain, &initial(&domain));
    let allocator = allocator(&domain);
    let charge = retry.prepare_attempt(&allocator, 1_500, false).unwrap();
    let durable = charge.record().clone();
    drop(charge.commit_after_durable(&durable).unwrap());
    let mut retry = restore(&domain, &durable);
    assert!(matches!(
        retry.prepare_attempt(&allocator, 1_499, false),
        Err(Error::Closed)
    ));
    let limits = Policy::new(u64::MAX - 20, u64::MAX, 2, 15).unwrap();
    let persisted =
        Record::from_persisted(domain.clone(), 7, limits, 1, Some(u64::MAX - 10)).unwrap();
    let mut retry = restore(&domain, &persisted);
    assert!(matches!(
        retry.prepare_attempt(&allocator, u64::MAX - 1, false),
        Err(Error::Closed)
    ));
}

#[test]
fn retry_records_bind_the_operation_domain_policy_and_exact_attempt_acknowledgement() {
    let domain = domain();
    let original = initial(&domain);
    assert!(matches!(
        Retry::restore(&domain, 8, &original),
        Err(Error::RecordMismatch)
    ));
    let mut retry = restore(&domain, &original);
    let allocator = allocator(&domain);
    let charge = retry.prepare_attempt(&allocator, 1_000, false).unwrap();
    let changed_policy = Policy::new(1_000, 3_000, 3, 100).unwrap();
    let wrong = Record::from_persisted(domain.clone(), 7, changed_policy, 1, Some(1_000)).unwrap();
    assert!(matches!(
        charge.commit_after_durable(&wrong),
        Err(Error::CommitMismatch)
    ));
    assert!(!format!("{retry:?}").contains("1000"));
    for (attempts, last) in [
        (0, Some(1_000)),
        (1, None),
        (4, Some(1_000)),
        (1, Some(999)),
        (1, Some(2_000)),
    ] {
        assert!(Record::from_persisted(domain.clone(), 7, policy(), attempts, last).is_err());
    }
    for (start, deadline, max, backoff) in [
        (1, 1, 3, 1),
        (2, 1, 3, 1),
        (1, 2, 0, 1),
        (1, 2, 4, 1),
        (1, 2, 3, 0),
    ] {
        assert!(Policy::new(start, deadline, max, backoff).is_err());
    }
}

#[test]
fn failed_charge_and_wrong_domain_burn_no_block_and_one_attempt_policy_is_final() {
    let domain = domain();
    let policy = Policy::new(1_000, 2_000, 1, 100).unwrap();
    let record = Record::initial(domain.clone(), 7, policy);
    let mut retry = restore(&domain, &record);
    let mut allocator = allocator(&domain);
    drop(retry.prepare_attempt(&allocator, 1_000, false).unwrap());
    assert_eq!(retry.record().attempts(), 0);
    assert!(matches!(
        retry.prepare_attempt(&allocator, 1_100, false),
        Err(Error::CommitUncertain)
    ));
    retry = restore(&domain, &record); // Readback proves no charge committed.
    let charge = retry.prepare_attempt(&allocator, 1_000, false).unwrap();
    let charged = charge.record().clone();
    let block = charge
        .commit_after_durable(&charged)
        .unwrap()
        .prepare(&mut allocator, 4, Purpose::Ordinary, 1_000, false)
        .unwrap();
    assert_eq!(block.record().exclusive_end(), 4);
    let (iv_profile, iv_keys) = key_material();
    let wrong_iv = opc_proto_ikev2::Ikev2AesGcmIvRecord::from_persisted(
        support::epoch_inputs(
            domain.initiator_spi(),
            domain.responder_spi(),
            domain.direction(),
            iv_profile,
            &iv_keys,
        ),
        Limits::new(128, 2, 1, 2).unwrap(),
        5,
        Some(1),
    )
    .unwrap();
    assert!(matches!(
        block.activate_after_commit(&wrong_iv, 1_000, false),
        Err(Error::Iv(IvError::CommitMismatch))
    ));
    retry = restore(&domain, &charged);
    assert!(matches!(
        retry.prepare_attempt(&allocator, 1_100, false),
        Err(Error::Closed)
    ));
    assert_eq!(
        allocator.allocate(Purpose::Ordinary).unwrap_err(),
        IvError::ReservationRequired
    );

    let profile = Ikev2SaInitCryptoProfile::new_aead(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2DhGroup::Ecp256,
        Ikev2EncryptionAlgorithm::AesGcm16_128,
    )
    .unwrap();
    let keys = Ikev2SaInitKeyMaterial::from_established_keys(
        profile,
        false,
        &[0x11; 32],
        &[],
        &[],
        &[0x41; 20],
        &[0x62; 20],
        &[0x22; 32],
        &[0x33; 32],
    )
    .unwrap();
    let foreign = support::iv_domain(
        0x101,
        0x203,
        Ikev2ProtectedPayloadDirection::ResponderToInitiator,
        profile,
        &keys,
    )
    .unwrap();
    assert!(matches!(
        Retry::restore(&foreign, 7, &record),
        Err(Error::RecordMismatch)
    ));
    let foreign_allocator = Allocator::fresh(
        support::epoch_inputs(
            foreign.initiator_spi(),
            foreign.responder_spi(),
            foreign.direction(),
            profile,
            &keys,
        ),
        Limits::new(128, 2, 1, 2).unwrap(),
    )
    .unwrap();
    retry = restore(&domain, &record);
    assert!(matches!(
        retry.prepare_attempt(&foreign_allocator, 1_000, false),
        Err(Error::Iv(IvError::DomainMismatch))
    ));
    assert_eq!(retry.record().attempts(), 0);
}
