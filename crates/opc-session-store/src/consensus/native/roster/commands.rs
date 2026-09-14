//! The committed roster namespace uses the original authority boundary and
//! Q1/Q2 evaluators. Only an accepted savepoint joins the enclosing delta;
//! deterministic rejections still advance the original application history.

use super::store::Store;
use super::*;
use crate::consensus::types::{
    protected_roster_profile_v2_voter_set_digest, protected_roster_profile_voter_set_digest,
    ConsensusRosterAdmissionOutcome, ConsensusRosterTerminalOutcome,
};
use crate::sqlite::consensus::{
    roster_engine, ProtectedRosterCommandApplyError as ApplyError, ProtectedRosterCommandRef,
    ProtectedRosterProfileVersion, RosterCommandRef,
};

fn v1_activated(
    identity: SessionConsensusIdentity,
    members: &BTreeSet<SessionConsensusNodeId>,
    frontiers: &NativeFrontiers,
) -> bool {
    frontiers.v1_activation.as_ref().is_some_and(|activation| {
        activation.identity == identity
            && activation.voters == protected_roster_profile_voter_set_digest(identity, members)
    })
}

fn v2_activated(
    identity: SessionConsensusIdentity,
    members: &BTreeSet<SessionConsensusNodeId>,
    frontiers: &NativeFrontiers,
) -> bool {
    frontiers
        .roster_v2_activation
        .as_ref()
        .is_some_and(|activation| {
            activation.identity == identity
                && activation.voters
                    == protected_roster_profile_v2_voter_set_digest(identity, members)
                && activation.profile == crate::fenced_mutation_roster::Profile::v2().digest()
        })
}

pub(in crate::consensus::native) fn validate_activation(
    identity: SessionConsensusIdentity,
    members: &BTreeSet<SessionConsensusNodeId>,
    frontiers: &NativeFrontiers,
) -> io::Result<()> {
    if (frontiers.roster_v1_namespace && !v1_activated(identity, members, frontiers))
        || (frontiers.roster_v2_activation.is_some() && !v2_activated(identity, members, frontiers))
    {
        return Err(invalid(
            "native roster profile or namespace activation differs",
        ));
    }
    Ok(())
}

pub(super) fn validate_row_profile(row: &Row, frontiers: &NativeFrontiers) -> io::Result<()> {
    let activated = match row.projection().profile {
        Profile::V1 => frontiers.roster_v1_namespace,
        Profile::V2 => frontiers.roster_v2_activation.is_some(),
    };
    if !activated {
        return Err(invalid("native roster row precedes its profile namespace"));
    }
    Ok(())
}

impl NativeState {
    pub(crate) fn protected_roster_v2_activation_matches(
        &self,
        identity: SessionConsensusIdentity,
        members: &BTreeSet<SessionConsensusNodeId>,
    ) -> bool {
        identity == self.identity
            && members == &self.members
            && v2_activated(identity, members, &self.frontiers)
    }
}

impl NativeDelta<'_> {
    pub(in crate::consensus::native) fn roster_command(
        &mut self,
        command: &SessionConsensusCommand,
        roster: ProtectedRosterCommandRef<'_>,
        index: u64,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<SessionConsensusResponse> {
        check()?;
        let now = self
            .frontiers
            .logical_time
            .map_or(command.logical_time, |prior| {
                prior.max(command.logical_time)
            });
        let sequence = self
            .frontiers
            .sequence
            .checked_add(1)
            .filter(|sequence| *sequence <= COUNTER_MAX)
            .ok_or_else(|| invalid("native roster application sequence exhausted"))?;
        let digest = command
            .calculate_applied_digest(sequence, self.frontiers.digest, now)
            .map_err(|_| invalid("native roster command digest failed"))?;
        let ProtectedRosterCommandRef {
            roster,
            authority_identity,
        } = roster;
        let activated = match roster.profile() {
            ProtectedRosterProfileVersion::V1 => {
                v1_activated(self.base.identity, &self.base.members, &self.frontiers)
            }
            ProtectedRosterProfileVersion::V2 => {
                v2_activated(self.base.identity, &self.base.members, &self.frontiers)
            }
        };
        if !activated {
            return Err(invalid("native roster profile activation is missing"));
        }
        match &roster {
            RosterCommandRef::Admission(_, ProtectedRosterProfileVersion::V1) => {
                self.frontiers.roster_v1_namespace = true
            }
            RosterCommandRef::TerminalV1(_) if !self.frontiers.roster_v1_namespace => {
                return Err(invalid(
                    "native roster terminal precedes V1 namespace activation",
                ))
            }
            _ => {}
        }
        let mut store = Store::for_command(self, check)?;
        let result = match &roster {
            RosterCommandRef::Admission(q1, ProtectedRosterProfileVersion::V1) => {
                roster_engine::admit_v1(
                    &mut store,
                    self.base.identity,
                    authority_identity,
                    index,
                    now,
                    q1,
                )
                .map(|outcome| (SessionMutationOutcome::RosterAdmission(outcome), None))
            }
            RosterCommandRef::Admission(q1, ProtectedRosterProfileVersion::V2) => {
                roster_engine::admit_v2(
                    &mut store,
                    self.base.identity,
                    authority_identity,
                    index,
                    now,
                    q1,
                )
                .map(|outcome| (SessionMutationOutcome::RosterAdmissionV2(outcome), None))
            }
            RosterCommandRef::TerminalV1(q2) => roster_engine::terminal_v1(
                &mut store,
                self.base.identity,
                authority_identity,
                sequence,
                index,
                now,
                q2,
            )
            .map(|(outcome, replication)| {
                (SessionMutationOutcome::RosterTerminal(outcome), replication)
            }),
            RosterCommandRef::TerminalV2(q2) => roster_engine::terminal_v2(
                &mut store,
                self.base.identity,
                authority_identity,
                sequence,
                index,
                now,
                q2,
            )
            .map(|(outcome, replication)| {
                (
                    SessionMutationOutcome::RosterTerminalV2(outcome),
                    replication,
                )
            }),
        };
        let (outcome, replication) = match result {
            Ok(value) => {
                check()?;
                let (ledger, changes, keys, revision) = store.finish_with_changes()?;
                self.accept_roster_savepoint(ledger, changes, keys, revision)?;
                value
            }
            Err(ApplyError::Rejected(rejection)) => {
                // Dropping the complete savepoint also drops any late staged
                // record, index, witness, restore-revision or journal update.
                drop(store);
                let outcome = match roster {
                    RosterCommandRef::Admission(q1, ProtectedRosterProfileVersion::V1) => {
                        ConsensusRosterAdmissionOutcome::rejected(q1, rejection)
                            .map(SessionMutationOutcome::RosterAdmission)
                    }
                    RosterCommandRef::Admission(q1, ProtectedRosterProfileVersion::V2) => {
                        ConsensusRosterAdmissionOutcome::rejected(q1, rejection)
                            .map(SessionMutationOutcome::RosterAdmissionV2)
                    }
                    RosterCommandRef::TerminalV1(q2) => {
                        ConsensusRosterTerminalOutcome::rejected(q2, rejection)
                            .map(SessionMutationOutcome::RosterTerminal)
                    }
                    RosterCommandRef::TerminalV2(q2) => {
                        ConsensusRosterTerminalOutcome::rejected_v2(q2, rejection)
                            .map(SessionMutationOutcome::RosterTerminalV2)
                    }
                }
                .map_err(|_| invalid("native roster rejection binding is invalid"))?;
                (outcome, None)
            }
            Err(ApplyError::Fatal) => {
                return Err(invalid("native roster evaluator storage failed"))
            }
        };
        self.frontiers.sequence = sequence;
        self.frontiers.digest = digest;
        self.frontiers.logical_time = Some(now);
        if let Some(op) = replication {
            #[cfg(any(test, feature = "test-control"))]
            let notification_started = std::time::Instant::now();
            let sequence = self
                .frontiers
                .watch_sequence
                .checked_add(1)
                .filter(|sequence| *sequence <= COUNTER_MAX)
                .ok_or_else(|| invalid("native roster watch sequence exhausted"))?;
            let notification = ReplicationEntry {
                sequence,
                tx_id: ReplicationTxId::from_request_bytes(*command.request_id.as_bytes()),
                op,
                timestamp: now,
            };
            notification
                .validate()
                .map_err(|_| invalid("native roster replication notification invalid"))?;
            self.frontiers.watch_sequence = sequence;
            self.notifications.push(notification);
            #[cfg(any(test, feature = "test-control"))]
            crate::sqlite::consensus::record_native_roster_notification_timing(
                notification_started,
            );
        }
        #[cfg(any(test, feature = "test-control"))]
        if matches!(
            &outcome,
            SessionMutationOutcome::RosterTerminal(
                ConsensusRosterTerminalOutcome::Committed { .. }
            ) | SessionMutationOutcome::RosterTerminalV2(
                ConsensusRosterTerminalOutcome::Committed { .. }
            )
        ) {
            self.terminal_remainder_started = Some(std::time::Instant::now());
        }
        check()?;
        Ok(self.response(index, Ok(outcome)))
    }

    pub(in crate::consensus::native) fn maintain_roster(
        &mut self,
        now: Timestamp,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        if !self.frontiers.roster_v1_namespace && self.frontiers.roster_v2_activation.is_none() {
            return Ok(());
        }
        check()?;
        let mut store = Store::for_command(self, check)?;
        if store.maintain_due(now)? {
            let (ledger, changes, keys, revision) = store.finish_with_changes()?;
            self.accept_roster_savepoint(ledger, changes, keys, revision)?;
        }
        check()
    }
}
