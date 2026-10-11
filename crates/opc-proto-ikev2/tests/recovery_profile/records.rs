//! Mandatory persisted profile metadata; low-level optional construction is insufficient.

use crate::canonical_fixtures::{Fixture, ALGORITHMS, DIRECTIONS};
use opc_proto_ikev2::{
    recovery::{
        Ikev2CommittedWindowRecord as Record, Ikev2PersistedProfileSync as ProfileSync,
        Ikev2SyncDisposition as Disposition, Ikev2SyncResponderRecord as SyncRecord,
    },
    Ikev2MessageIdSyncAgreement as Agreement, Ikev2MessageIdSyncMode as Mode,
    Ikev2MessageIdSyncRole as Role, Ikev2MessageIdSyncSa as Sa,
};

#[test]
fn negotiated_local_sync_requires_the_original_recovery_event() {
    crate::support::ensure_ike_crypto();
    let f = Fixture::new(81_000, ALGORITHMS[0], DIRECTIONS[0]);
    let agreement = Agreement::from_persisted(
        Sa::new(f.spis.0, f.spis.1, Role::Initiator).unwrap(),
        Mode::Negotiated,
    );
    let state = SyncRecord::from_persisted(
        agreement,
        None,
        None,
        Some(1),
        None,
        Disposition::AwaitLocalSync,
        0,
    )
    .unwrap();
    let record = Record::from_profile_persisted(
        f.window.record().domain().clone(),
        1,
        Some(1),
        Some(0),
        None,
        None,
        ProfileSync::Negotiated {
            agreement,
            state,
            recovery: None,
        },
    );
    assert!(
        record.is_err(),
        "a profile restore cannot omit its pending recovery event"
    );
}

fn agreement(
    spis: (u64, u64),
    direction: opc_proto_ikev2::Ikev2ProtectedPayloadDirection,
    mode: Mode,
) -> Agreement {
    let role = if direction == DIRECTIONS[0] {
        Role::Initiator
    } else {
        Role::Responder
    };
    Agreement::from_persisted(Sa::new(spis.0, spis.1, role).unwrap(), mode)
}

// Invoke the same public construction assertions for each sealed profile type.
macro_rules! checked_metadata {
    ($domain:expr, $spis:expr, $direction:expr, $state:expr) => {{
        use opc_proto_ikev2::recovery::Ikev2WindowError as Error;
        let domain = $domain;
        let base = agreement($spis, $direction, Mode::BaseFallback);
        let negotiated = agreement($spis, $direction, Mode::Negotiated);
        let state = $state;
        let rebuild = |synchronization| {
            Record::from_profile_persisted(
                domain.clone(),
                0,
                Some(0),
                Some(0),
                None,
                None,
                synchronization,
            )
        };
        let base_record = rebuild(ProfileSync::Base { agreement: base }).unwrap();
        assert!(base_record.sync_state().is_none());
        assert!(base_record.sync_recovery().is_none());
        let sync = state(negotiated, None, Disposition::Continue);
        let record = rebuild(ProfileSync::Negotiated {
            agreement: negotiated,
            state: sync,
            recovery: None,
        })
        .unwrap();
        assert_eq!(record.sync_state(), Some(&sync));
        assert!(record.sync_recovery().is_none());
        assert_eq!(
            rebuild(ProfileSync::Base {
                agreement: negotiated
            })
            .unwrap_err(),
            Error::InvalidRecord
        );
        assert_eq!(
            rebuild(ProfileSync::Negotiated {
                agreement: base,
                state: state(base, None, Disposition::Continue),
                recovery: None,
            })
            .unwrap_err(),
            Error::InvalidRecord
        );
        assert_eq!(
            rebuild(ProfileSync::Negotiated {
                agreement: negotiated,
                state: state(base, None, Disposition::Continue),
                recovery: None,
            })
            .unwrap_err(),
            Error::InvalidRecord
        );
        for foreign in [
            agreement(($spis.0 ^ 1, $spis.1), $direction, Mode::BaseFallback),
            agreement(($spis.0, $spis.1 ^ 1), $direction, Mode::BaseFallback),
            agreement(
                $spis,
                crate::canonical_fixtures::opposite($direction),
                Mode::BaseFallback,
            ),
        ] {
            assert_eq!(
                rebuild(ProfileSync::Base { agreement: foreign }).unwrap_err(),
                Error::DomainMismatch
            );
            let foreign = Agreement::from_persisted(foreign.sa(), Mode::Negotiated);
            assert_eq!(
                rebuild(ProfileSync::Negotiated {
                    agreement: foreign,
                    state: state(foreign, None, Disposition::Continue),
                    recovery: None,
                })
                .unwrap_err(),
                Error::DomainMismatch
            );
            assert_eq!(
                rebuild(ProfileSync::Negotiated {
                    agreement: negotiated,
                    state: state(foreign, None, Disposition::Continue),
                    recovery: None,
                })
                .unwrap_err(),
                Error::InvalidRecord
            );
        }
        for disposition in [
            Disposition::AwaitLocalSync,
            Disposition::Continue,
            Disposition::CloseIkeSa,
            Disposition::OutcomeUncertain,
        ] {
            assert_eq!(
                Record::from_profile_persisted(
                    domain.clone(),
                    1,
                    Some(1),
                    Some(0),
                    None,
                    None,
                    ProfileSync::Negotiated {
                        agreement: negotiated,
                        state: state(negotiated, Some(1), disposition),
                        recovery: None,
                    }
                )
                .unwrap_err(),
                Error::InvalidRecord,
                "pending, completed and closed event history must all be explicit"
            );
        }
        record
    }};
}

#[test]
fn mandatory_mode_and_sa_binding_cover_both_gcm_roles() {
    use opc_proto_ikev2::recovery::Ikev2CommittedWindow as Window;
    for (algorithm, encryption) in ALGORITHMS.into_iter().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            let f = Fixture::new(
                81_010 + (algorithm * 2 + role) as u64,
                encryption,
                direction,
            );
            let record = checked_metadata!(
                f.window.record().domain(),
                f.spis,
                direction,
                |a, proposal, disposition| SyncRecord::from_persisted(
                    a,
                    None,
                    None,
                    proposal,
                    None,
                    disposition,
                    0
                )
                .unwrap()
            );
            let window =
                Window::restore(record.domain(), f.profile, &f.keys, &record, &f.iv).unwrap();
            assert!(window.replay_request().unwrap().is_none());
        }
    }
}

#[test]
fn mandatory_mode_and_sa_binding_cover_all_cbc_profiles_and_roles() {
    use opc_proto_ikev2::recovery::{
        Ikev2CbcRecoveryProfile as Cbc, Ikev2CommittedWindow as Window,
    };
    for (algorithm, profile) in super::cbc::profiles().enumerate() {
        for (role, direction) in DIRECTIONS.into_iter().enumerate() {
            let f = super::cbc::Fixture::new(
                profile,
                direction,
                81_100 + (algorithm * 2 + role) as u64,
            );
            let record =
                checked_metadata!(&f.domain, f.spis, direction, |a, proposal, disposition| {
                    SyncRecord::from_persisted_cbc(a, None, None, proposal, None, disposition)
                        .unwrap()
                });
            let window =
                Window::<Cbc>::restore(&f.domain, profile, &f.keys, &record, &f.epoch).unwrap();
            assert!(window.replay_request().unwrap().is_none());
        }
    }
}

macro_rules! preserves_event {
    ($record:expr) => {{
        let original = $record;
        let sync = *original.sync_state().unwrap();
        let recovery = original.sync_recovery().unwrap().clone();
        let checked = Record::from_profile_persisted(
            original.domain().clone(),
            original.generation(),
            original.next_send(),
            original.next_receive(),
            original.outbound().cloned(),
            original.inbound().cloned(),
            ProfileSync::Negotiated {
                agreement: sync.agreement(),
                state: sync,
                recovery: Some(recovery.clone()),
            },
        )
        .unwrap();
        assert_eq!(checked, *original);
        assert_eq!(checked.sync_recovery(), Some(&recovery));
        // Event presence alone is insufficient: the original policy/proposal must
        // still pass the existing history and packet validators.
        let no_history = checked.sync_state().unwrap();
        assert!(no_history.highest_local_proposal().is_some());
        checked
    }};
}

#[test]
fn checked_profile_preserves_real_pending_sync_event_in_each_cipher() {
    crate::support::ensure_ike_crypto();
    use opc_proto_ikev2::{
        recovery::{
            Ikev2CbcRecoveryProfile as Cbc, Ikev2CommittedWindow as Window,
            Ikev2SyncClock as Clock, Ikev2SyncRecoveryPolicy as Policy,
        },
        Ikev2AesGcmIvPurpose as Purpose,
    };
    for (role, direction) in DIRECTIONS.into_iter().enumerate() {
        for (algorithm, encryption) in ALGORITHMS.into_iter().enumerate() {
            let mut f = Fixture::new(
                81_300 + (algorithm * 2 + role) as u64,
                encryption,
                direction,
            );
            let a = agreement(f.spis, direction, Mode::Negotiated);
            let seed = Record::from_profile_persisted(
                f.window.record().domain().clone(),
                0,
                Some(0),
                Some(0),
                None,
                None,
                ProfileSync::Negotiated {
                    agreement: a,
                    state: SyncRecord::from_persisted(
                        a,
                        None,
                        None,
                        None,
                        None,
                        Disposition::Continue,
                        0,
                    )
                    .unwrap(),
                    recovery: None,
                },
            )
            .unwrap();
            f.window = Window::restore(seed.domain(), f.profile, &f.keys, &seed, &f.iv).unwrap();
            let clock = Clock::new(100, 1);
            let prepared = f
                .window
                .begin_sync(Policy::new(7, clock, 1000, 3, 10).unwrap(), clock, None)
                .unwrap()
                .prepare(
                    f.profile,
                    &f.keys,
                    f.allocator.allocate(Purpose::Ordinary).unwrap(),
                )
                .unwrap();
            let checked = preserves_event!(prepared.record());
            drop(prepared);
            let restored =
                Window::restore(checked.domain(), f.profile, &f.keys, &checked, &f.iv).unwrap();
            assert_eq!(restored.record(), &checked);
        }
        for (algorithm, profile) in super::cbc::profiles().enumerate() {
            let f = super::cbc::Fixture::new(
                profile,
                direction,
                81_400 + (algorithm * 2 + role) as u64,
            );
            let a = agreement(f.spis, direction, Mode::Negotiated);
            let seed = Record::from_profile_persisted(
                f.domain.clone(),
                0,
                Some(0),
                Some(0),
                None,
                None,
                ProfileSync::Negotiated {
                    agreement: a,
                    state: SyncRecord::from_persisted_cbc(
                        a,
                        None,
                        None,
                        None,
                        None,
                        Disposition::Continue,
                    )
                    .unwrap(),
                    recovery: None,
                },
            )
            .unwrap();
            let mut window =
                Window::<Cbc>::restore(&f.domain, profile, &f.keys, &seed, &f.epoch).unwrap();
            let clock = Clock::new(100, 1);
            let prepared = window
                .begin_sync(Policy::new(7, clock, 1000, 3, 10).unwrap(), clock, None)
                .unwrap()
                .prepare(profile, &f.keys)
                .unwrap();
            let checked = preserves_event!(prepared.record());
            drop(prepared);
            let restored =
                Window::<Cbc>::restore(&f.domain, profile, &f.keys, &checked, &f.epoch).unwrap();
            assert_eq!(restored.record(), &checked);
        }
    }
}
