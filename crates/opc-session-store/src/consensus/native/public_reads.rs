//! Public reads use the same immutable business predecessor as application.
//! Carrier authentication, request hashing and output copies run detached
//! from the WAL mutex. The adapter retains admission until this work retires.

use super::*;
use crate::consensus::verified_snapshot::VerificationMemory;
use crate::sqlite::consensus::consumer_receipts::ConsumerReceiptStore;
use crate::sqlite::consensus::roster_engine::RosterCommandStore;

pub(crate) struct ConsumerReceipts<'a> {
    state: &'a NativeState,
    _memory: VerificationMemory,
}

impl ConsumerReceipts<'_> {
    fn require_identity(&self, identity: SessionConsensusIdentity) -> io::Result<()> {
        if identity != self.state.identity {
            return Err(invalid("native consumer receipt identity differs"));
        }
        self.state.require_business_proof()?;
        Ok(())
    }
}

impl ConsumerReceiptStore for ConsumerReceipts<'_> {
    fn outcome(
        &self,
        identity: SessionConsensusIdentity,
        id: SessionConsensusRequestId,
    ) -> io::Result<Option<([u8; 32], SessionConsensusResponse)>> {
        self.require_identity(identity)?;
        let Some(receipt) = self.state.generic_receipts.get(&id) else {
            return Ok(None);
        };
        validation::validate_generic(&id, receipt, &self.state.frontiers)?;
        match &**receipt {
            NativeGenericReceipt::Ordinary(row) => Ok(Some((
                row.payload_digest,
                owned::ordinary_response(&row.response)?,
            ))),
            NativeGenericReceipt::FencedV1(_) => Ok(None),
        }
    }

    fn fenced(
        &self,
        identity: SessionConsensusIdentity,
        id: SessionConsensusRequestId,
    ) -> Result<bool, StoreError> {
        self.require_identity(identity).map_err(|_| unavailable())?;
        Ok(self
            .state
            .generic_receipts
            .get(&id)
            .is_some_and(|row| matches!(&**row, NativeGenericReceipt::FencedV1(_))))
    }

    fn occupied(
        &self,
        identity: SessionConsensusIdentity,
        id: SessionConsensusRequestId,
    ) -> Result<bool, StoreError> {
        self.require_identity(identity).map_err(|_| unavailable())?;
        Ok(self.state.generic_receipts.contains_key(&id))
    }
}

impl NativeState {
    /// Passive test receipt witness from the selected native owner. No SQL
    /// materialization or consensus proposal participates in this observation.
    #[cfg(feature = "test-control")]
    pub(crate) fn padding_receipt_for_test(
        &self,
        storage_identity: SessionConsensusIdentity,
        authority_identity: SessionConsensusIdentity,
        request_id: SessionConsensusRequestId,
    ) -> io::Result<crate::sqlite::consensus::ConsensusPaddingReceiptStatus> {
        use crate::sqlite::consensus::{
            authorized_mutation_payload_digest, ConsensusPaddingReceiptStatus,
        };

        self.require_business_proof()?;
        if self.identity != storage_identity {
            return Err(invalid("native padding receipt storage identity differs"));
        }
        let expected = authorized_mutation_payload_digest(
            storage_identity,
            authority_identity,
            &SessionMutationIntent::AdvanceLogicalTime,
        )?;
        let Some(receipt) = self.generic_receipts.get(&request_id) else {
            return Ok(ConsensusPaddingReceiptStatus::NotFound);
        };
        validation::validate_generic(&request_id, receipt, &self.frontiers)?;
        let NativeGenericReceipt::Ordinary(receipt) = &**receipt else {
            return Ok(ConsensusPaddingReceiptStatus::Conflict);
        };
        if receipt.payload_digest != expected {
            return Ok(ConsensusPaddingReceiptStatus::Conflict);
        }
        let response = &receipt.response;
        // validate_generic checked the complete applied/sequence/time bounds.
        // As for the independent SQL witness, require the exact padding shape
        // and equality with the machine digest/time at its current sequence.
        if !matches!(response.result, Ok(SessionMutationOutcome::Unit))
            || response.raft_log_index == 0
            || (response.sequence == self.frontiers.sequence
                && (response.digest != Some(self.frontiers.digest)
                    || response.logical_time != self.frontiers.logical_time))
        {
            return Err(invalid("native padding receipt response differs"));
        }
        Ok(ConsensusPaddingReceiptStatus::Recorded {
            raft_log_index: response.raft_log_index,
        })
    }

    pub(crate) fn replication_log(
        &self,
        start: u64,
        limit: usize,
        check: &dyn Fn() -> io::Result<()>,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        let range = crate::backend::ReplicationLogRange::try_new(start, limit)?;
        if range.is_empty() || range.first_sequence() > self.frontiers.watch_sequence {
            return Ok(Vec::new());
        }
        check().map_err(|_| unavailable())?;
        self.require_business_proof().map_err(|_| unavailable())?;
        let first = usize::try_from(range.first_sequence() - 1).map_err(|_| unavailable())?;
        let count = self
            .notifications
            .len()
            .checked_sub(first)
            .ok_or_else(unavailable)?
            .min(limit);
        // Reserve both exact output containers and one full validator's
        // scratch before reading. Selected decoders retain their own guards.
        let container_bytes = count
            .checked_mul(
                std::mem::size_of::<ReplicationEntry>() + std::mem::size_of::<VerificationMemory>(),
            )
            .ok_or_else(unavailable)?;
        let _containers = VerificationMemory::reserve(
            container_bytes
                .checked_add(8 * crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES + 64 * 1024)
                .ok_or_else(unavailable)?,
        )
        .map_err(|_| unavailable())?;
        let mut reservations = Vec::new();
        reservations
            .try_reserve_exact(count)
            .map_err(|_| unavailable())?;
        let mut result = Vec::new();
        result.try_reserve_exact(count).map_err(|_| unavailable())?;
        for position in first..first + count {
            check().map_err(|_| unavailable())?;
            let sequence = u64::try_from(position).map_err(|_| unavailable())? + 1;
            let row = self.notifications.get(position).ok_or_else(unavailable)?;
            row.validate(sequence, &self.frontiers)
                .map_err(|_| unavailable())?;
            let decoded = row
                .read(&self.frontiers, &|| check())
                .map_err(|_| unavailable())?;
            let entry = decoded.entry();
            validation::validate_notification(entry, sequence, &self.frontiers)
                .map_err(|_| unavailable())?;
            // Counting serialization allocates no output. The closed effect
            // shape has at most two records and two batch elements; double
            // byte backing plus fixed object/allocation overhead covers the
            // independent copy, including Bytes and encrypted-payload Arcs.
            let bytes = image::binary::encoded_len(entry, generation::MAX_ITEM)
                .map_err(|_| unavailable())?
                .checked_mul(2)
                .and_then(|bytes| {
                    bytes.checked_add(2 * std::mem::size_of::<ReplicationEntry>() + 32 * 64)
                })
                .ok_or_else(unavailable)?;
            reservations.push(VerificationMemory::reserve(bytes).map_err(|_| unavailable())?);
            result.push(owned::notification(entry).map_err(|_| unavailable())?);
        }
        check().map_err(|_| unavailable())?;
        crate::backend::validate_replication_log_page_owned(start, limit, result)
    }

    pub(crate) fn consumer_receipts(&self) -> Result<ConsumerReceipts<'_>, StoreError> {
        // The evaluator retains at most the binding and operation response.
        // Reserve their complete ordinary payload copies before any lookup.
        let memory = VerificationMemory::reserve(
            4 * crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES + 256 * 1024,
        )
        .map_err(|_| unavailable())?;
        Ok(ConsumerReceipts {
            state: self,
            _memory: memory,
        })
    }

    pub(crate) fn with_roster_read<T>(
        &self,
        identity: SessionConsensusIdentity,
        wall_time_floor: Timestamp,
        check: &dyn Fn() -> io::Result<()>,
        read: impl FnOnce(&dyn RosterCommandStore, Timestamp) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        check().map_err(|_| unavailable())?;
        if identity != self.identity {
            return Err(unavailable());
        }
        // Hydration owns its original decoder reservation. This separate
        // reservation covers the bounded evaluator output and frontiers.
        let _memory =
            VerificationMemory::reserve(4 * roster::carrier::MAX_CANONICAL_BYTES + 256 * 1024)
                .map_err(|_| unavailable())?;
        let delta = self
            .prepare_using_checked(&[], None, &|| check())
            .map_err(|_| unavailable())?;
        let store = roster::store::Store::for_command(&delta, check).map_err(|_| unavailable())?;
        let now = self
            .logical_time()
            .map_or(wall_time_floor, |time| time.max(wall_time_floor));
        let result = read(&store, now);
        check().map_err(|_| unavailable())?;
        result
    }

    pub(crate) fn roster_v2_history_is_activated(&self) -> bool {
        self.frontiers.roster_v2_activation.is_some()
    }

    pub(crate) fn watch_sequence(&self) -> u64 {
        self.frontiers.watch_sequence
    }
}
