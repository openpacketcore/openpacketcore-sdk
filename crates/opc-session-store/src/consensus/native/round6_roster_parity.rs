//! Signed roster commands enter through the same committed journal as leases.
use super::*;
use crate::consensus::types::{
    protected_roster_profile_v2_voter_set_digest, ConsensusRosterAdmissionCommand,
    ConsensusRosterAdmissionOutcome, ConsensusRosterTerminalOutcome, RosterV2PersistenceFixture,
};
use crate::fenced_mutation_roster::{Phase, Profile};

fn command(
    native: &NativeStorage,
    now: Timestamp,
    id: SessionConsensusRequestId,
    intent: SessionMutationIntent,
) -> Entry<SessionRaftTypeConfig> {
    let origin = *native.business.members.first().unwrap();
    Entry {
        log_id: LogId::new(
            native.business.applied().unwrap().leader_id,
            native.business.applied().unwrap().index + 1,
        ),
        payload: EntryPayload::Normal(SessionConsensusCommand {
            schema_version: crate::consensus::SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: native.business.identity,
            request_id: id,
            logical_time: now,
            intent: SessionMutationIntent::Authorized {
                origin,
                authority_identity: native.business.identity,
                mutation: Box::new(intent),
            },
        }),
    }
}
fn admission(
    native: &NativeStorage,
    signed: &RosterV2PersistenceFixture,
    now: Timestamp,
) -> Entry<SessionRaftTypeConfig> {
    let admission = ConsensusRosterAdmissionCommand::new_with_provenance_and_ingress_request_id_v2(
        signed.admission.clone(),
        signed.authority.clone(),
        signed.admission_ingress.request_id(),
        signed.admission_ingress.clone(),
        signed.admission_provenance.clone(),
    )
    .unwrap();
    command(
        native,
        now,
        admission.request_id().unwrap(),
        SessionMutationIntent::RosterAdmissionV2(Box::new(admission)),
    )
}
struct RosterParity {
    native: NativeStorage,
    fake: FakeSessionBackend,
    clock: Arc<ReplayClock>,
    journal: Vec<crate::ReplicationEntry>,
}
impl RosterParity {
    async fn apply(
        &mut self,
        entry: Entry<SessionRaftTypeConfig>,
        pressure: bool,
    ) -> NativeApplied {
        let EntryPayload::Normal(ref value) = entry.payload else {
            unreachable!()
        };
        *self.clock.0.lock().unwrap() = value.logical_time;
        let retired = self
            .native
            .business
            .keys
            .values()
            .filter(|row| row.retired_epoch.is_some())
            .count();
        let maximum = if pressure && retired > 0 {
            self.native.business.keys.len()
        } else {
            validation::MAX_ITEMS
        };
        let result = retention::with_key_capacity_limit_for_test(maximum, || {
            apply(&mut self.native, &[entry])
        });
        let replica = crate::fake::tests::with_tracked_key_limit_for_test(&self.fake, maximum);
        for entry in &result.notifications {
            replica.replicate_entry(entry.clone()).await.unwrap();
            self.journal.push(entry.clone());
            assert_eq!(
                native_state(&self.native),
                replay_state_for_test(&self.fake).await
            );
            let rebuilt = FakeSessionBackend::new().with_clock(self.clock.clone());
            rebuilt
                .rebuild_replication_state(self.journal.clone())
                .await
                .unwrap();
            assert_eq!(
                native_state(&self.native),
                replay_state_for_test(&rebuilt).await
            );
        }
        result
    }
}
async fn signed_roster_parity(seed: u64) {
    use opc_consensus::engine::{CommittedLeaderId, Membership};
    let fixture =
        crate::consensus::types::tests::roster_v2_fresh_wal_persistence_fixture(Phase::Aborted);
    let members = [7, 8, 9]
        .into_iter()
        .map(|id| SessionConsensusNodeId::new(id).unwrap())
        .collect::<BTreeSet<_>>();
    let mut native = NativeStorage::empty(fixture.identity, members.clone()).unwrap();
    native.business.roster_root = Some(Arc::new(fixture.root.clone()));
    native.business.admit_business().unwrap();
    native.log.admit(&native.business).unwrap();
    apply(
        &mut native,
        &[Entry {
            log_id: LogId::new(CommittedLeaderId::new(1, *members.first().unwrap()), 0),
            payload: EntryPayload::Membership(Membership::new(vec![members.clone()], members)),
        }],
    );
    let clock = Arc::new(ReplayClock(std::sync::Mutex::new(
        fixture.authority.acquired_at(),
    )));
    let fake = FakeSessionBackend::new().with_clock(clock.clone());
    let mut driver = RosterParity {
        native,
        fake,
        clock,
        journal: Vec::new(),
    };
    let lease = command(
        &driver.native,
        fixture.authority.acquired_at(),
        SessionConsensusRequestId::from_bytes([1; 16]),
        SessionMutationIntent::AcquireLease {
            key: fixture.authority.key().clone(),
            owner: fixture.authority.owner().clone(),
            ttl: Duration::from_secs(60),
        },
    );
    let result = driver.apply(lease, false).await;
    let Ok(SessionMutationOutcome::Lease(guard)) = &result.responses[0].result else {
        panic!("real authority acquisition")
    };
    assert_eq!(guard.fence(), fixture.authority.fence());
    assert_eq!(guard.credential_id(), fixture.authority.credential_id());
    let profile = Profile::v2();
    let activation = command(
        &driver.native,
        fixture.authority.acquired_at().add_seconds(1).unwrap(),
        SessionConsensusRequestId::from_bytes([2; 16]),
        SessionMutationIntent::ActivateProtectedRosterProfileV2 {
            schema_version: profile.schema(),
            consumer_revision: profile.consumer_revision(),
            scope_identity: fixture.identity,
            voter_set_digest: protected_roster_profile_v2_voter_set_digest(
                fixture.identity,
                &driver.native.business.members,
            ),
            profile_digest: profile.digest(),
        },
    );
    assert!(driver.apply(activation, false).await.responses[0]
        .result
        .is_ok());
    let mut random = seed;
    let mut admitted = 0;
    let mut terminal = 0;
    for round in 0..24_u64 {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        let now = fixture
            .authority
            .acquired_at()
            .add_seconds(1 + round as i64)
            .unwrap();
        let signed = crate::consensus::types::tests::roster_v2_persistence_fixture_for_authority(
            Phase::Aborted,
            (u128::from(seed) + u128::from(round)).to_be_bytes(),
            driver.native.business.frontiers.sequence + 1,
            fixture.authority.fence(),
            fixture.authority.credential_id(),
        );
        let q1 = admission(&driver.native, &signed, now);
        let result = driver.apply(q1.clone(), false).await;
        assert!(matches!(
            result.responses[0].result,
            Ok(SessionMutationOutcome::RosterAdmissionV2(
                ConsensusRosterAdmissionOutcome::Admitted { .. }
            ))
        ));
        admitted += 1;
        if random & 1 == 0 {
            // A committed duplicate has no second application effect.
            let mut duplicate = q1;
            duplicate.log_id.index += 1;
            assert!(driver.apply(duplicate, false).await.responses[0]
                .result
                .is_ok());
        }
        let q2 = command(
            &driver.native,
            now,
            signed.terminal_command.request_id().unwrap(),
            SessionMutationIntent::RosterTerminalV2(Box::new(signed.terminal_command.clone())),
        );
        let result = driver.apply(q2, false).await;
        assert!(matches!(
            result.responses[0].result,
            Ok(SessionMutationOutcome::RosterTerminalV2(
                ConsensusRosterTerminalOutcome::Committed { .. }
            ))
        ));
        terminal += 1;
        let publish = command(
            &driver.native,
            now,
            SessionConsensusRequestId::from_bytes((0xA000 + u128::from(round)).to_be_bytes()),
            SessionMutationIntent::AcquireLease {
                key: key(fixture.authority.key(), 120_000 + round),
                owner: fixture.authority.owner().clone(),
                ttl: Duration::from_secs(1),
            },
        );
        assert!(driver.apply(publish, random & 2 != 0).await.responses[0]
            .result
            .is_ok());
        assert_eq!(
            native_state(&driver.native),
            replay_state_for_test(&driver.fake).await
        );
    }
    assert_eq!((admitted, terminal), (24, 24));
    eprintln!("roster_seed={seed:#x} admitted={admitted} terminal={terminal}");
}

#[tokio::test]
async fn round6_seeded_signed_roster_admission_and_terminal_replay_match() {
    signed_roster_parity(0x9E3779B97F4A7C15).await;
}
#[tokio::test]
async fn round6_seeded_signed_roster_second_seed_replay_match() {
    signed_roster_parity(0xD1B54A32D192ED03).await;
}
