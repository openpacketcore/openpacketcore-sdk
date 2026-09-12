//! Fixed-size metadata copied from fully decoded rows while their allocation
//! reservations are held. No record, response, String, Bytes, collection or
//! borrowed callback crosses that boundary. These values are comparison data;
//! only the complete catalog reader can bind them to an admitted prefix.

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(in crate::consensus::native) struct KeyId {
    // Four original bounded identifiers occupy fewer than 512 postcard bytes.
    // This complete key avoids hash-only identity and decoder-owned aliases.
    bytes: [u8; 512],
    length: u16,
}

impl KeyId {
    pub(in crate::consensus::native) fn of(key: &SessionKey) -> io::Result<Self> {
        let mut bytes = [0; 512];
        let length = postcard::to_slice(key, &mut bytes)
            .map_err(|_| invalid("native catalog key exceeds its complete identifier bound"))?
            .len();
        Ok(Self {
            bytes,
            length: length as u16,
        })
    }
}

#[derive(Clone, Copy)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(in crate::consensus::native) struct Row<T> {
    pub(in crate::consensus::native) content: [u8; 32],
    pub(in crate::consensus::native) facts: T,
}

#[derive(Clone, Copy)]
pub(in crate::consensus::native) struct Key {
    pub(in crate::consensus::native) format: Format,
    pub(in crate::consensus::native) fence: u64,
    pub(in crate::consensus::native) credential: Option<u64>,
    pub(in crate::consensus::native) commitment: [u8; 32],
    pub(in crate::consensus::native) reserved: bool,
    pub(in crate::consensus::native) business: Business,
}

/// Comparison of an original fully validated authoritative business value.
/// Its complete SessionKey remains the catalog lookup identity. This never
/// substitutes for the final ledger's original exact business predicate.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::consensus::native) enum Business {
    Absent,
    Ineligible,
    Present([u8; 32]),
}

impl Business {
    pub(in crate::consensus::native) fn of(
        value: &crate::fenced_mutation_roster_storage::ProductionBusinessState,
    ) -> io::Result<Self> {
        Ok(Self::Present(changes::fingerprint(
            6,
            value.key(),
            &(value.generation(), value.canonical_bytes()),
        )?))
    }
}

impl Key {
    pub(super) fn of(key: &SessionKey, row: &NativeKeyState, format: Format) -> io::Result<Self> {
        let business = match row.record.as_ref() {
            None => Business::Absent,
            Some(record) if row.reserved => {
                let value = crate::fenced_mutation_roster_storage::ProductionBusinessState::from_authoritative_record(record)
                    .map_err(|_| invalid("native reserved business row is not an original authoritative value"))?;
                Business::of(&value)?
            }
            Some(_) => Business::Ineligible,
        };
        Ok(Self {
            format,
            fence: row.fence,
            credential: row.lease.as_ref().map(|lease| lease.credential_id),
            commitment: crate::fenced_mutation_roster::session_key_commitment(key),
            reserved: row.reserved,
            business,
        })
    }
}

#[derive(Clone, Copy)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(in crate::consensus::native) struct Response {
    pub(in crate::consensus::native) sequence: u64,
    pub(in crate::consensus::native) logical_time: Timestamp,
    pub(in crate::consensus::native) raft_index: u64,
}

impl Response {
    pub(in crate::consensus::native) fn of(row: &SessionConsensusResponse) -> io::Result<Self> {
        Ok(Self {
            sequence: row.sequence,
            logical_time: row
                .logical_time
                .ok_or_else(|| invalid("native catalog response time absent"))?,
            raft_index: row.raft_log_index,
        })
    }

    pub(in crate::consensus::native) fn validate(
        self,
        frontiers: &NativeFrontiers,
    ) -> io::Result<()> {
        if self.sequence > frontiers.sequence
            || frontiers
                .logical_time
                .is_none_or(|now| self.logical_time > now)
            || frontiers
                .applied
                .is_none_or(|id| self.raft_index > id.index)
        {
            return Err(invalid("native catalog response exceeds final frontiers"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(in crate::consensus::native) struct Request {
    pub(super) format: Format,
    payload_digest: [u8; 32],
    pub(super) retained_until: Option<Timestamp>,
    response: Option<Response>,
}

impl Request {
    pub(super) fn of(row: &NativeGenericReceipt, format: Format) -> io::Result<Self> {
        let (payload_digest, retained_until) = match row {
            NativeGenericReceipt::Ordinary(row) => (row.payload_digest, None),
            NativeGenericReceipt::FencedV1(row) => (row.payload_digest, Some(row.retained_until)),
        };
        Ok(Self {
            format,
            payload_digest,
            retained_until,
            response: row.response().map(Response::of).transpose()?,
        })
    }

    pub(super) fn validate(self, frontiers: &NativeFrontiers) -> io::Result<()> {
        if let Some(until) = self.retained_until {
            if self.format == Format::V2
                || frontiers.v1_activation.is_none()
                || (self.response.is_none() && frontiers.logical_time.is_none_or(|now| until > now))
            {
                return Err(invalid("native catalog V1 receipt context differs"));
            }
        } else if self.response.is_none() {
            return Err(invalid("native catalog ordinary response absent"));
        }
        if let Some(response) = self.response {
            response.validate(frontiers)?;
        }
        Ok(())
    }

    pub(super) fn validate_replacement(self, before: Self, changed: bool) -> io::Result<()> {
        if before.payload_digest != self.payload_digest
            || before.retained_until != self.retained_until
            || (changed
                && !(self.retained_until.is_some()
                    && before.response.is_some()
                    && self.response.is_none()))
        {
            return Err(invalid("native catalog request receipt binding changed"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(in crate::consensus::native) struct Receipt {
    pub(in crate::consensus::native) ordinal: u64,
    pub(in crate::consensus::native) payload_digest: [u8; 32],
    pub(in crate::consensus::native) retained_until: Timestamp,
    pub(in crate::consensus::native) response: Option<Response>,
}

impl Receipt {
    pub(in crate::consensus::native) fn of(
        id: FencedTransitionV2RequestId,
        row: &NativeReceipt,
    ) -> io::Result<Row<Self>> {
        Ok(Row {
            content: changes::fingerprint(1, &id, row)?,
            facts: Self {
                ordinal: row.ordinal,
                payload_digest: row.payload_digest,
                retained_until: row.retained_until,
                response: row.response.as_deref().map(Response::of).transpose()?,
            },
        })
    }
}

#[derive(Clone, Copy)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(in crate::consensus::native) struct Notification {
    pub(in crate::consensus::native) sequence: u64,
    pub(in crate::consensus::native) timestamp: Timestamp,
}

#[derive(Clone, Copy)]
pub(in crate::consensus::native) struct Log {
    pub(in crate::consensus::native) id: LogId<SessionConsensusNodeId>,
    pub(in crate::consensus::native) membership: Option<[u8; 32]>,
}

pub(in crate::consensus::native) fn membership(
    value: &opc_consensus::engine::Membership<SessionConsensusNodeId, EmptyNode>,
) -> io::Result<[u8; 32]> {
    let mut writer = HashWriter(Sha256::new());
    writer.write_all(b"OPC-native-catalog-membership-v1\0")?;
    serde_json::to_writer(&mut writer, value)
        .map_err(|_| invalid("native catalog membership cannot encode"))?;
    Ok(writer.0.finalize().into())
}
