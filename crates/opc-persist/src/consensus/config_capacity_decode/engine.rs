//! Private bounded engine representations. None selects a receive profile.

use std::collections::{BTreeMap, BTreeSet};

use opc_consensus::engine::raft::{AppendEntriesRequest, InstallSnapshotRequest};
use opc_consensus::engine::{
    EmptyNode, Entry, EntryPayload, LogId, Membership, SnapshotMeta, StoredMembership, Vote,
};
use opc_consensus::ConsensusNodeId;
use serde::de::MapAccess;

use super::*;
use crate::consensus::ConfigRaftTypeConfig;

pub(super) mod native_json;

const MEMBERS: usize = crate::consensus::CONFIG_CONSENSUS_MAX_MEMBERS;
const SNAPSHOT_ID_BYTES: usize = 128;
const SNAPSHOT_CHUNK_BYTES: usize = 1_048_576;

struct Nodes(BTreeMap<ConsensusNodeId, EmptyNode>);
impl<'de> Deserialize<'de> for Nodes {
    fn deserialize<D: Deserializer<'de>>(input: D) -> Result<Self, D::Error> {
        struct NodeVisitor;
        impl<'de> Visitor<'de> for NodeVisitor {
            type Value = Nodes;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded configuration voter metadata")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut input: A) -> Result<Nodes, A::Error> {
                if input.size_hint().is_some_and(|count| count > MEMBERS) {
                    return Err(invalid());
                }
                let mut nodes = BTreeMap::new();
                while let Some(id) = input.next_key::<ConsensusNodeId>()? {
                    if nodes.len() == MEMBERS || nodes.contains_key(&id) {
                        return Err(invalid());
                    }
                    nodes.insert(id, input.next_value()?);
                }
                Ok(Nodes(nodes))
            }
        }
        input.deserialize_map(NodeVisitor)
    }
}

#[derive(Deserialize)]
#[serde(rename = "Membership")]
struct MembershipFields {
    configs: List<List<ConsensusNodeId, MEMBERS>, 1>,
    nodes: Nodes,
}

struct FixedMembership(Membership<ConsensusNodeId, EmptyNode>);
impl<'de> Deserialize<'de> for FixedMembership {
    fn deserialize<D: Deserializer<'de>>(input: D) -> Result<Self, D::Error> {
        let fields = MembershipFields::deserialize(input)?;
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
        // Membership::new fills missing nodes, so check exact identity first.
        if count == 0 || voters.len() != count || !voters.iter().eq(fields.nodes.0.keys()) {
            return Err(invalid());
        }
        Ok(Self(Membership::new(vec![voters], fields.nodes.0)))
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
pub(super) struct Append {
    vote: Vote<ConsensusNodeId>,
    prev_log_id: Option<LogId<ConsensusNodeId>>,
    entries: List<EntryFields, { opc_consensus::DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES }>,
    leader_commit: Option<LogId<ConsensusNodeId>>,
}
impl From<Append> for AppendEntriesRequest<ConfigRaftTypeConfig> {
    fn from(value: Append) -> Self {
        Self {
            vote: value.vote,
            prev_log_id: value.prev_log_id,
            entries: value.entries.0.into_iter().map(Into::into).collect(),
            leader_commit: value.leader_commit,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename = "StoredMembership")]
struct Stored {
    log_id: Option<LogId<ConsensusNodeId>>,
    membership: FixedMembership,
}
impl From<Stored> for StoredMembership<ConsensusNodeId, EmptyNode> {
    fn from(value: Stored) -> Self {
        Self::new(value.log_id, value.membership.0)
    }
}

#[derive(Deserialize)]
#[serde(rename = "SnapshotMeta")]
struct Meta {
    last_log_id: Option<LogId<ConsensusNodeId>>,
    last_membership: Stored,
    snapshot_id: Text<SNAPSHOT_ID_BYTES>,
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

#[derive(Deserialize)]
#[serde(rename = "InstallSnapshotRequest")]
pub(super) struct Snapshot {
    vote: Vote<ConsensusNodeId>,
    meta: Meta,
    offset: u64,
    data: Bytes<SNAPSHOT_CHUNK_BYTES>,
    done: bool,
}
impl From<Snapshot> for InstallSnapshotRequest<ConfigRaftTypeConfig> {
    fn from(value: Snapshot) -> Self {
        Self {
            vote: value.vote,
            meta: value.meta.into(),
            offset: value.offset,
            data: value.data.0,
            done: value.done,
        }
    }
}

#[cfg(test)]
mod tests;
