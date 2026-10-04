//! Complete persisted after-images from one certified business capture.
//! No journal/container is cloned, sorted or rescanned from the live owner.

use super::super::generation::{self as frame, BusinessContext};
use super::*;
use crate::backend::ReplicationOp;
use std::io::Write;

impl BusinessProof {
    pub(in crate::consensus::native) fn generation_context(&self) -> BusinessContext {
        let roster = if self.roster_root.is_some()
            || self.roster.counts() != [0; 2]
            || self.roster.witness().is_some()
            || self.frontiers.roster_v1_namespace
            || self.frontiers.roster_v2_activation.is_some()
        {
            Some(frame::RosterContext {
                root: self.roster_root.as_ref().map(|root| root.fingerprint()),
                counts: self.roster.counts(),
                content: self.roster.content(),
                witness: self.roster.witness(),
            })
        } else {
            None
        };
        BusinessContext {
            identity: self.identity,
            members: self.members.clone(),
            frontiers: self.frontiers.clone(),
            counts: self.tables.map(|table| table.count),
            content: self.tables.map(|table| table.checksum),
            roster,
        }
    }
}

pub(in crate::consensus::native) fn generic_payload(
    row: Option<&NativeGenericReceipt>,
) -> io::Result<usize> {
    match row {
        None | Some(NativeGenericReceipt::FencedV1(_)) => Ok(0),
        Some(NativeGenericReceipt::Ordinary(row)) => ordinary_payload(row),
    }
}

pub(in crate::consensus::native) fn ordinary_payload(
    row: &NativeOrdinaryReceipt,
) -> io::Result<usize> {
    use crate::backend::CompareAndSetResult;
    match &row.response.result {
        Ok(
            SessionMutationOutcome::Unit
            | SessionMutationOutcome::Lease(_)
            | SessionMutationOutcome::ConsumerRecord(None)
            | SessionMutationOutcome::CompareAndSet(
                CompareAndSetResult::Success | CompareAndSetResult::Conflict { current: None },
            ),
        ) => Ok(0),
        Ok(
            SessionMutationOutcome::ConsumerRecord(Some(record))
            | SessionMutationOutcome::CompareAndSet(CompareAndSetResult::Conflict {
                current: Some(record),
            }),
        ) => Ok(record.payload.len()),
        Err(error) if business::deterministic(error) => {
            if matches!(error,StoreError::InvalidKey(message) if message.len() > 1024) {
                return Err(invalid(
                    "native ordinary error exceeds its fixed message vocabulary",
                ));
            }
            Ok(0)
        }
        _ => Err(invalid(
            "native generation generic response requires its command codec",
        )),
    }
}

// Native V2 emits one lease effect followed by one mutation, preserving the
// original journal's order and every complete field. Verify that exact bounded
// shape before assigning its decoder reservation. Full normal-command codecs
// remain required when those native command families are implemented.
pub(in crate::consensus::native) fn notification_payload(
    row: &ReplicationEntry,
) -> io::Result<usize> {
    let ReplicationOp::Batch { ops } = &row.op else {
        return ordinary_notification_payload(&row.op);
    };
    if ops.len() != 2
        || !matches!(
            &ops[0],
            ReplicationOp::AcquireLease { .. } | ReplicationOp::RenewLease { .. }
        )
    {
        return Err(invalid(
            "native generation notification lease shape invalid",
        ));
    }
    match &ops[1] {
        ReplicationOp::CompareAndSet { new_record, .. } => Ok(new_record.payload.len()),
        ReplicationOp::DeleteFenced { .. } | ReplicationOp::RefreshTtl { .. } => Ok(0),
        _ => Err(invalid(
            "native generation notification mutation shape invalid",
        )),
    }
}

fn ordinary_notification_payload(op: &ReplicationOp) -> io::Result<usize> {
    match op {
        ReplicationOp::CompareAndSet { new_record, .. } => Ok(new_record.payload.len()),
        ReplicationOp::ProtectedRosterEstablished {
            expected_record,
            successor,
            ..
        } => {
            let replacement = match &**successor {
                crate::backend::ProtectedRosterEstablishedSuccessor::Put { record } => {
                    record.payload.len()
                }
                crate::backend::ProtectedRosterEstablishedSuccessor::Delete
                | crate::backend::ProtectedRosterEstablishedSuccessor::NoOp => 0,
            };
            expected_record
                .payload
                .len()
                .checked_add(replacement)
                .ok_or_else(|| invalid("native roster notification payload overflow"))
        }
        ReplicationOp::ProtectedRosterEstablishedCreate { record, .. } => Ok(record.payload.len()),
        ReplicationOp::AcquireLease { .. }
        | ReplicationOp::RenewLease { .. }
        | ReplicationOp::ReleaseLease { .. }
        | ReplicationOp::DeleteFenced { .. }
        | ReplicationOp::RefreshTtl { .. } => Ok(0),
        _ => Err(invalid(
            "native generation notification requires its command codec",
        )),
    }
}

impl BusinessChanges {
    pub(in crate::consensus::native) fn generation_roster_counts(&self) -> [usize; 2] {
        self.roster.generation_counts()
    }

    pub(in crate::consensus::native) fn write_roster_generation(
        &self,
        writer: &mut dyn Write,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        let scope = roster::fixed_scope(self.target.identity, &self.target.members);
        self.roster
            .write_generation(writer, self.target.roster_root.as_deref(), &scope, check)
    }

    pub(in crate::consensus::native) fn verify_roster_generation(
        &self,
        reader: &mut frame::PositionedReader<'_>,
        check: &impl Fn() -> io::Result<()>,
        relocations: Option<&mut frame::RelocationBuilder>,
    ) -> io::Result<()> {
        let scope = roster::fixed_scope(self.target.identity, &self.target.members);
        self.roster.verify_generation(
            reader,
            self.target.roster_root.as_deref(),
            &scope,
            check,
            relocations,
        )
    }
    pub(in crate::consensus::native) fn generation_starts_at(
        &self,
        proof: &Arc<BusinessProof>,
    ) -> bool {
        Arc::ptr_eq(&self.base, proof)
    }

    pub(in crate::consensus::native) fn generation_counts(&self, logs: usize) -> [usize; 5] {
        [
            self.keys.len(),
            self.receipts.len(),
            self.generic.len(),
            self.notifications.len(),
            logs,
        ]
    }

    pub(in crate::consensus::native) fn write_generation(
        &self,
        writer: &mut dyn Write,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        for (key, change) in &self.keys {
            check()?;
            writer.write_all(&[0])?;
            frame::write_before(writer, change.before_hash.map(|stamp| stamp.content))?;
            frame::write_binary(writer, &(key, change.after.as_deref()))?;
        }
        for (id, change) in self
            .receipts
            .iter()
            .filter(|(_, change)| change.after.is_none())
            .chain(
                self.receipts
                    .iter()
                    .filter(|(_, change)| change.after.is_some()),
            )
        {
            check()?;
            writer.write_all(&[1])?;
            frame::write_before(writer, change.before_hash.map(|stamp| stamp.content))?;
            writer.write_all(&id.to_bytes())?;
            writer.write_all(&[u8::from(change.after.is_some())])?;
            if let Some(row) = &change.after {
                let length = cold::write_receipt(&mut io::sink(), *id, row, check)?;
                writer.write_all(&(length as u32).to_le_bytes())?;
                if cold::write_receipt(writer, *id, row, check)? != length {
                    return Err(invalid("native generation receipt extent changed"));
                }
            }
        }
        for (id, change) in &self.generic {
            check()?;
            generic_payload(change.after.as_deref().map(|row| &**row))?;
            writer.write_all(&[2])?;
            frame::write_before(writer, change.before_hash.map(|stamp| stamp.content))?;
            frame::write_binary(writer, &(id, change.after.as_deref()))?;
        }
        for row in &self.notifications {
            check()?;
            notification_payload(row.resident()?)?;
            writer.write_all(&[3])?;
            frame::write_binary(writer, &**row)?;
        }
        check()
    }

    pub(in crate::consensus::native) fn verify_generation(
        &self,
        reader: &mut frame::PositionedReader<'_>,
        check: &impl Fn() -> io::Result<()>,
        mut relocations: Option<&mut frame::RelocationBuilder>,
    ) -> io::Result<()> {
        for (key, change) in &self.keys {
            check()?;
            frame::expect(reader, &[0])?;
            frame::expect_before(reader, change.before_hash.map(|stamp| stamp.content))?;
            let payload = change
                .after
                .as_ref()
                .and_then(|row| row.record.as_ref())
                .map_or(0, |row| row.payload.len());
            frame::payload_scratch(payload, check, || {
                frame::verify_binary::<(SessionKey, Option<NativeKeyState>)>(
                    reader,
                    &(key, change.after.as_deref()),
                )
            })?;
        }
        for (id, change) in self
            .receipts
            .iter()
            .filter(|(_, change)| change.after.is_none())
            .chain(
                self.receipts
                    .iter()
                    .filter(|(_, change)| change.after.is_some()),
            )
        {
            check()?;
            frame::expect(reader, &[1])?;
            frame::expect_before(reader, change.before_hash.map(|stamp| stamp.content))?;
            frame::expect(reader, &id.to_bytes())?;
            frame::expect(reader, &[u8::from(change.after.is_some())])?;
            if let Some(row) = &change.after {
                let length = cold::write_receipt(&mut io::sink(), *id, row, check)?;
                let offset = reader
                    .position()
                    .checked_add(4)
                    .ok_or_else(|| invalid("native receipt relocation offset overflow"))?;
                let input = frame::read_bytes(reader, length)?;
                cold::verify_generation_bytes(input.bytes(), *id, row, &self.target, check)?;
                if let Some(relocations) = &mut relocations {
                    relocations.receipt(*id, row, offset, input.bytes().len() as u32)?;
                }
            }
        }
        for (id, change) in &self.generic {
            check()?;
            let payload = generic_payload(change.after.as_deref().map(|row| &**row))?;
            frame::expect(reader, &[2])?;
            frame::expect_before(reader, change.before_hash.map(|stamp| stamp.content))?;
            frame::payload_scratch(payload, check, || {
                frame::verify_binary::<(SessionConsensusRequestId, Option<NativeGenericReceipt>)>(
                    reader,
                    &(id, change.after.as_deref()),
                )
            })?;
        }
        for row in &self.notifications {
            check()?;
            frame::expect(reader, &[3])?;
            let offset = reader
                .position()
                .checked_add(4)
                .ok_or_else(|| invalid("native notification relocation offset overflow"))?;
            frame::payload_scratch(notification_payload(row.resident()?)?, check, || {
                frame::verify_binary::<ReplicationEntry>(reader, row.resident()?)
            })?;
            let length = reader
                .position()
                .checked_sub(offset)
                .and_then(|length| u32::try_from(length).ok())
                .ok_or_else(|| invalid("native notification relocation length overflow"))?;
            if let Some(relocations) = &mut relocations {
                relocations.notification(row, offset, length)?;
            }
        }
        check()
    }
}
