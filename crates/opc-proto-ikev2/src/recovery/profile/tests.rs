#![allow(clippy::unwrap_used)]

use super::*;
use crate::recovery::{
    Ikev2CbcEpochInputs, Ikev2CbcEpochRecord, Ikev2CommittedWindowRecord as Record,
    Ikev2SyncAttemptRecord as Attempt, Ikev2SyncClock as Clock,
    Ikev2SyncDisposition as Disposition, Ikev2SyncRecoveryPolicy as Policy,
    Ikev2SyncRecoveryRecord as Recovery, Ikev2SyncRecoveryStatus as Status,
    Ikev2SyncResponderRecord as SyncRecord,
};
use crate::{
    Ikev2DhGroup, Ikev2IntegrityAlgorithm as Integrity, Ikev2MessageIdSync as Sync,
    Ikev2MessageIdSyncAgreement as Agreement, Ikev2MessageIdSyncPending as Pending,
    Ikev2MessageIdSyncRole as Role, Ikev2MessageIdSyncSa as Sa, Ikev2PrfAlgorithm as Prf,
};

type Cbc = Ikev2CbcRecoveryProfile;

fn domain(direction: Direction) -> Domain<Cbc> {
    let profile = Profile::new_encrypt_then_mac(
        Prf::HmacSha2_256,
        Ikev2DhGroup::Modp2048,
        Ikev2EncryptionAlgorithm::AesCbc128,
        Integrity::HmacSha2_256_128,
    )
    .unwrap();
    let keys = Keys::from_established_keys(
        profile, false, &[1; 32], &[2; 32], &[3; 32], &[4; 16], &[5; 16], &[6; 32], &[7; 32],
    )
    .unwrap();
    let epoch = Ikev2CbcEpochRecord::fresh(Ikev2CbcEpochInputs {
        initiator_spi: 1,
        responder_spi: 2,
        sending_direction: direction,
        profile,
        keys: &keys,
    })
    .unwrap();
    let domain = Domain::from_cbc_epoch(&epoch);
    domain.check(profile, &keys).unwrap();
    domain
}

fn agreement(direction: Direction) -> Agreement {
    let role = if direction == Direction::InitiatorToResponder {
        Role::Initiator
    } else {
        Role::Responder
    };
    Agreement::from_persisted(
        Sa::new(1, 2, role).unwrap(),
        crate::Ikev2MessageIdSyncMode::Negotiated,
    )
}

#[test]
fn cbc_domain_rechecks_sk_d_prf_both_traffic_directions_and_exact_marker() {
    for direction in [
        Direction::InitiatorToResponder,
        Direction::ResponderToInitiator,
    ] {
        let domain = domain(direction);
        let profile = Profile::new_encrypt_then_mac(
            Prf::HmacSha2_256,
            Ikev2DhGroup::Modp2048,
            Ikev2EncryptionAlgorithm::AesCbc128,
            Integrity::HmacSha2_256_128,
        )
        .unwrap();
        for key in 0..5 {
            let mut d = [1; 32];
            let mut ai = [2; 32];
            let mut ar = [3; 32];
            let mut ei = [4; 16];
            let mut er = [5; 16];
            [
                &mut d[..],
                &mut ai[..],
                &mut ar[..],
                &mut ei[..],
                &mut er[..],
            ][key][0] ^= 0x80;
            let keys = Keys::from_established_keys(
                profile, false, &d, &ai, &ar, &ei, &er, &[6; 32], &[7; 32],
            )
            .unwrap();
            assert_eq!(
                domain.check(profile, &keys),
                Err(Error::DomainMismatch),
                "changed key {key}"
            );
        }
        let other_profile = Profile::new_encrypt_then_mac(
            Prf::HmacSha2_512,
            Ikev2DhGroup::Modp2048,
            profile.encryption(),
            profile.integrity().unwrap(),
        )
        .unwrap();
        let other_keys = Keys::from_established_keys(
            other_profile,
            false,
            &[1; 64],
            &[2; 32],
            &[3; 32],
            &[4; 16],
            &[5; 16],
            &[6; 64],
            &[7; 64],
        )
        .unwrap();
        assert_eq!(
            domain.check(other_profile, &other_keys),
            Err(Error::DomainMismatch)
        );
        let keys = Keys::from_established_keys(
            profile, false, &[1; 32], &[2; 32], &[3; 32], &[4; 16], &[5; 16], &[6; 32], &[7; 32],
        )
        .unwrap();
        for marker in [None, Some(0), Some(2), Some(u8::MAX)] {
            let mut inconsistent = domain.clone();
            inconsistent.canonical_format = marker;
            assert_eq!(
                inconsistent.check(profile, &keys),
                Err(Error::DomainMismatch)
            );
        }
    }
}

#[test]
fn cbc_storage_keeps_typed_sync_history_without_iv_evidence() {
    for direction in [
        Direction::InitiatorToResponder,
        Direction::ResponderToInitiator,
    ] {
        let domain = domain(direction);
        let agreement = agreement(direction);
        let state = SyncRecord::<Cbc>::from_persisted_cbc(
            agreement,
            Some(0),
            Some(0),
            None,
            None,
            Disposition::Continue,
        )
        .unwrap();
        assert_eq!(std::mem::size_of_val(&state.packet_evidence), 0);
        let record = Record::initial(domain, 1, 1)
            .with_sync_state(state)
            .unwrap();
        let restored =
            Record::from_persisted(record.domain().clone(), 0, Some(1), Some(1), None, None)
                .unwrap()
                .with_sync_state(state)
                .unwrap();
        assert_eq!(record, restored);
        assert_eq!(record.sync_state().unwrap().agreement(), agreement);
        assert_eq!(record.domain().send.direction(), direction);
        assert_ne!(
            record.domain().send.direction(),
            record.domain().receive.direction()
        );
    }
}

#[test]
fn cbc_storage_sync_validation_keeps_role_floor_and_disposition_checks() {
    let direction = Direction::InitiatorToResponder;
    let domain = domain(direction);
    let agreement = agreement(direction);
    for state in [
        SyncRecord::<Cbc>::from_persisted_cbc(
            agreement,
            Some(1),
            Some(0),
            None,
            None,
            Disposition::Continue,
        )
        .unwrap(),
        SyncRecord::<Cbc>::from_persisted_cbc(
            self::agreement(Direction::ResponderToInitiator),
            Some(0),
            Some(0),
            None,
            None,
            Disposition::Continue,
        )
        .unwrap(),
    ] {
        assert!(Record::initial(domain.clone(), 1, 1)
            .with_sync_state(state)
            .is_err());
    }
    assert!(SyncRecord::<Cbc>::from_persisted_cbc(
        agreement,
        None,
        None,
        None,
        None,
        Disposition::AwaitLocalSync
    )
    .is_err());
    assert!(SyncRecord::<Cbc>::from_persisted_cbc(
        agreement,
        None,
        None,
        Some(u32::MAX),
        None,
        Disposition::Continue
    )
    .is_err());
    assert!(SyncRecord::<Cbc>::from_persisted_cbc(
        agreement,
        None,
        None,
        None,
        Some(u32::MAX),
        Disposition::Continue
    )
    .is_err());
}

#[test]
fn cbc_storage_initiating_history_roundtrips_without_counter_interpretation() {
    let direction = Direction::InitiatorToResponder;
    let agreement = agreement(direction);
    let pending = Pending::from_persisted(agreement.sa(), Sync::new([1, 2, 3, 4], 5, 6)).unwrap();
    // Storage construction deliberately does not authenticate these bytes.
    // Runtime restore must do so before this history can influence a window.
    let attempt = Attempt::<Cbc>::from_persisted_cbc(
        pending,
        100,
        bytes::Bytes::from_static(b"untrusted-storage"),
    )
    .unwrap();
    let policy = Policy::new(1, Clock::new(100, 2), 1000, 3, 10).unwrap();
    let recovery =
        Recovery::<Cbc>::from_persisted_cbc(policy, 100, vec![attempt.clone()], Status::Pending)
            .unwrap();
    let state = SyncRecord::<Cbc>::from_persisted_cbc(
        agreement,
        Some(0),
        Some(0),
        Some(5),
        None,
        Disposition::AwaitLocalSync,
    )
    .unwrap();
    let record = Record::from_persisted(domain(direction), 1, Some(5), Some(6), None, None)
        .unwrap()
        .with_sync_state(state)
        .unwrap()
        .with_sync_recovery(recovery.clone())
        .unwrap();
    assert_eq!(record.sync_recovery(), Some(&recovery));
    assert_eq!(recovery.attempts(), std::slice::from_ref(&attempt));
    assert!(Recovery::<Cbc>::from_persisted_cbc(
        policy,
        100,
        vec![attempt.clone(), attempt],
        Status::Pending
    )
    .is_err());
    assert!(Attempt::<Cbc>::from_persisted_cbc(pending, 100, bytes::Bytes::new()).is_err());
}
