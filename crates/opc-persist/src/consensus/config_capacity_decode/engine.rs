//! Closed bounded-profile Openraft request builders. The profile discriminator
//! is checked before these collection visitors, and the authenticated sender
//! and record proofs are checked before handing the request to Openraft.

use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;

use opc_consensus::engine::raft::{AppendEntriesRequest, InstallSnapshotRequest};
use opc_consensus::engine::{
    EmptyNode, Entry, EntryPayload, LogId, Membership, SnapshotMeta, StoredMembership, Vote,
};
use opc_consensus::{ConsensusCodecError, ConsensusNodeId};
use serde::de::MapAccess;

use super::*;
use crate::consensus::{
    ConfigConsensusCommand, ConfigConsensusIdentity, ConfigConsensusRequestId, ConfigRaftTypeConfig,
};

mod config_capacity_native_json;

#[cfg(test)]
mod config_capacity_snapshot_extent_tests;

const MEMBERS: usize = 9;
pub(in crate::consensus) const SNAPSHOT_ID_BYTES: usize = 128;
const SNAPSHOT_CHUNK_BYTES: usize = 1_048_576;

struct BoundedVec<T, const MAX: usize>(Vec<T>);

impl<'de, T: Deserialize<'de>, const MAX: usize> Deserialize<'de> for BoundedVec<T, MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Sequence<T, const MAX: usize>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const MAX: usize> Visitor<'de> for Sequence<T, MAX> {
            type Value = BoundedVec<T, MAX>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded configuration engine sequence")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut input: A) -> Result<Self::Value, A::Error> {
                let extent = input.size_hint().unwrap_or(MAX);
                if extent > MAX {
                    return Err(invalid());
                }
                let mut values = Vec::new();
                while let Some(value) = input.next_element()? {
                    if values.len() == extent {
                        return Err(invalid());
                    }
                    if values.is_empty() {
                        values
                            .try_reserve_exact(extent)
                            .map_err(|_| invalid::<A::Error>())?;
                    }
                    values.push(value);
                }
                Ok(BoundedVec(values))
            }
        }
        deserializer.deserialize_seq(Sequence::<T, MAX>(PhantomData))
    }
}

struct Nodes(BTreeMap<ConsensusNodeId, EmptyNode>);

impl<'de> Deserialize<'de> for Nodes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct NodeVisitor;
        impl<'de> Visitor<'de> for NodeVisitor {
            type Value = Nodes;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded configuration engine nodes")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut input: A) -> Result<Self::Value, A::Error> {
                if input.size_hint().is_some_and(|size| size > MEMBERS) {
                    return Err(invalid());
                }
                let mut nodes = BTreeMap::new();
                while let Some((id, node)) = input.next_entry()? {
                    if nodes.len() == MEMBERS || nodes.insert(id, node).is_some() {
                        return Err(invalid());
                    }
                }
                Ok(Nodes(nodes))
            }
        }
        deserializer.deserialize_map(NodeVisitor)
    }
}

#[derive(Deserialize)]
#[serde(rename = "Membership")]
struct MembershipFields {
    configs: BoundedVec<BoundedVec<ConsensusNodeId, MEMBERS>, 1>,
    nodes: Nodes,
}

struct FixedMembership(Membership<ConsensusNodeId, EmptyNode>);

impl<'de> Deserialize<'de> for FixedMembership {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let fields = MembershipFields::deserialize(deserializer)?;
        if fields.configs.0.is_empty() {
            if !fields.nodes.0.is_empty() {
                return Err(invalid());
            }
            return Ok(Self(Membership::default()));
        }
        let members = fields
            .configs
            .0
            .into_iter()
            .next()
            .ok_or_else(invalid::<D::Error>)?
            .0;
        let count = members.len();
        let voters: BTreeSet<_> = members.into_iter().collect();
        // Membership::new fills missing nodes. Reject first, so decoding can
        // never normalize an incomplete or duplicate wire roster into validity.
        if count == 0
            || voters.len() != count
            || !voters.iter().copied().eq(fields.nodes.0.keys().copied())
        {
            return Err(invalid());
        }
        Ok(Self(Membership::new(vec![voters], fields.nodes.0)))
    }
}

#[derive(Deserialize)]
#[serde(rename = "ConfigConsensusCommand")]
struct Command {
    schema_version: u16,
    identity: ConfigConsensusIdentity,
    request_id: ConfigConsensusRequestId,
    logical_time: Timestamp,
    intent: Intent,
}

impl From<Command> for ConfigConsensusCommand {
    fn from(value: Command) -> Self {
        Self {
            schema_version: value.schema_version,
            identity: value.identity,
            request_id: value.request_id,
            logical_time: value.logical_time,
            intent: value.intent.into(),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename = "EntryPayload")]
enum Payload {
    Blank,
    Normal(Box<Command>),
    Membership(FixedMembership),
}

#[derive(Deserialize)]
#[serde(rename = "Entry")]
struct EntryFields {
    log_id: LogId<ConsensusNodeId>,
    payload: Payload,
}

impl From<EntryFields> for Entry<ConfigRaftTypeConfig> {
    fn from(value: EntryFields) -> Self {
        Self {
            log_id: value.log_id,
            payload: match value.payload {
                Payload::Blank => EntryPayload::Blank,
                Payload::Normal(command) => EntryPayload::Normal((*command).into()),
                Payload::Membership(membership) => EntryPayload::Membership(membership.0),
            },
        }
    }
}

#[derive(Deserialize)]
#[serde(rename = "AppendEntriesRequest")]
struct Append {
    vote: Vote<ConsensusNodeId>,
    prev_log_id: Option<LogId<ConsensusNodeId>>,
    entries: BoundedVec<EntryFields, { opc_consensus::DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES }>,
    leader_commit: Option<LogId<ConsensusNodeId>>,
}

#[derive(Deserialize)]
#[serde(rename = "StoredMembership")]
struct Stored {
    log_id: Option<LogId<ConsensusNodeId>>,
    membership: FixedMembership,
}

#[derive(Deserialize)]
#[serde(rename = "SnapshotMeta")]
struct Meta {
    last_log_id: Option<LogId<ConsensusNodeId>>,
    last_membership: Stored,
    snapshot_id: Text<SNAPSHOT_ID_BYTES>,
}

#[derive(Deserialize)]
#[serde(rename = "InstallSnapshotRequest")]
struct Snapshot {
    vote: Vote<ConsensusNodeId>,
    meta: Meta,
    offset: u64,
    data: Bytes<SNAPSHOT_CHUNK_BYTES>,
    done: bool,
}

pub(in crate::consensus) fn append(
    profile: ConfigCapacityProfile,
    bytes: &[u8],
) -> Result<AppendEntriesRequest<ConfigRaftTypeConfig>, ConsensusCodecError> {
    use crate::consensus::types::decode_config_wire_for_profile;
    match profile {
        ConfigCapacityProfile::Legacy => decode_config_wire_for_profile(profile, bytes),
        ConfigCapacityProfile::BoundedV1 => {
            let value: Append = decode_config_wire_for_profile(profile, bytes)?;
            Ok(AppendEntriesRequest {
                vote: value.vote,
                prev_log_id: value.prev_log_id,
                entries: value.entries.0.into_iter().map(Into::into).collect(),
                leader_commit: value.leader_commit,
            })
        }
        _ => Err(ConsensusCodecError::Decode),
    }
}

pub(in crate::consensus) fn snapshot(
    profile: ConfigCapacityProfile,
    bytes: &[u8],
) -> Result<InstallSnapshotRequest<ConfigRaftTypeConfig>, ConsensusCodecError> {
    use crate::consensus::types::decode_config_wire_for_profile;
    let request: InstallSnapshotRequest<ConfigRaftTypeConfig> = match profile {
        ConfigCapacityProfile::Legacy => decode_config_wire_for_profile(profile, bytes),
        ConfigCapacityProfile::BoundedV1 => {
            let value: Snapshot = decode_config_wire_for_profile(profile, bytes)?;
            Ok(InstallSnapshotRequest {
                vote: value.vote,
                meta: SnapshotMeta {
                    last_log_id: value.meta.last_log_id,
                    last_membership: StoredMembership::new(
                        value.meta.last_membership.log_id,
                        value.meta.last_membership.membership.0,
                    ),
                    snapshot_id: value.meta.snapshot_id.0,
                },
                offset: value.offset,
                data: value.data.0,
                done: value.done,
            })
        }
        _ => Err(ConsensusCodecError::Decode),
    }?;
    // The existing storage envelope limit also bounds every staging seek/write.
    // Check before native handoff, including empty final chunks and overflow.
    let length = u64::try_from(request.data.len()).map_err(|_| ConsensusCodecError::Decode)?;
    if request
        .offset
        .checked_add(length)
        .is_none_or(|end| end > crate::consensus::storage::SNAPSHOT_MAX_WIRE_BYTES)
    {
        return Err(ConsensusCodecError::Decode);
    }
    Ok(request)
}

impl From<Stored> for StoredMembership<ConsensusNodeId, EmptyNode> {
    fn from(value: Stored) -> Self {
        Self::new(value.log_id, value.membership.0)
    }
}

impl From<Meta> for SnapshotMeta<ConsensusNodeId, EmptyNode> {
    fn from(value: Meta) -> Self {
        Self {
            last_log_id: value.last_log_id,
            last_membership: value.last_membership.into(),
            snapshot_id: value.snapshot_id.0,
        }
    }
}

fn native_json_preflight(bytes: &[u8]) -> std::io::Result<()> {
    if bytes.len() > crate::consensus::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES {
        return Err(crate::consensus::sqlite::invalid_data(
            "persisted config consensus encoding exceeds storage limit",
        ));
    }
    json_string_preflight(bytes).map_err(|_| {
        crate::consensus::sqlite::invalid_data("invalid bounded config consensus encoding")
    })?;
    Ok(())
}

fn native<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> std::io::Result<T> {
    native_json_preflight(bytes)?;
    serde_json::from_slice(bytes).map_err(|_| {
        crate::consensus::sqlite::invalid_data("invalid bounded config consensus encoding")
    })
}

// The profile comes from the independently admitted store, never from the row
// being decoded. In particular, an older command revision cannot select the
// permissive decoder within a bounded store. Legacy keeps its original serde.
pub(in crate::consensus) fn native_entry(
    profile: ConfigCapacityProfile,
    bytes: &[u8],
) -> std::io::Result<Entry<ConfigRaftTypeConfig>> {
    match profile {
        ConfigCapacityProfile::Legacy => serde_json::from_slice(bytes).map_err(|_| {
            crate::consensus::sqlite::invalid_data("config consensus decoding failed")
        }),
        ConfigCapacityProfile::BoundedV1 => config_capacity_native_json::entry(bytes),
        _ => Err(crate::consensus::sqlite::invalid_data(
            "invalid config capacity profile",
        )),
    }
}

pub(in crate::consensus) fn native_membership(
    profile: ConfigCapacityProfile,
    bytes: &[u8],
) -> std::io::Result<StoredMembership<ConsensusNodeId, EmptyNode>> {
    match profile {
        ConfigCapacityProfile::Legacy => serde_json::from_slice(bytes).map_err(|_| {
            crate::consensus::sqlite::invalid_data("config consensus decoding failed")
        }),
        ConfigCapacityProfile::BoundedV1 => native::<Stored>(bytes).map(Into::into),
        _ => Err(crate::consensus::sqlite::invalid_data(
            "invalid config capacity profile",
        )),
    }
}

pub(in crate::consensus) fn native_snapshot_meta(
    profile: ConfigCapacityProfile,
    bytes: &[u8],
) -> std::io::Result<SnapshotMeta<ConsensusNodeId, EmptyNode>> {
    match profile {
        ConfigCapacityProfile::Legacy => serde_json::from_slice(bytes).map_err(|_| {
            crate::consensus::sqlite::invalid_data("config consensus decoding failed")
        }),
        ConfigCapacityProfile::BoundedV1 => native::<Meta>(bytes).map(Into::into),
        _ => Err(crate::consensus::sqlite::invalid_data(
            "invalid config capacity profile",
        )),
    }
}
