//! Bounded, fixed-roster Async recovery control vocabulary. These values are
//! carried only over the existing authenticated, mode-bound member transport.
//! They are never diagnostics and never grant authority by themselves.

use super::{
    SessionConsensusIdentity, SessionConsensusNodeId as Node, SessionConsensusPeerError,
    SessionConsensusRequestId,
};
use opc_consensus::engine::{LogId, Vote};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const WIRE: &[u8; 23] = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xffOPC-MAJOR-1\0";

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Capability {
    Reserved,
    Legacy,
    ProtectedAuthority,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Status {
    pub node: Node,
    pub boot: SessionConsensusRequestId,
    pub root: [u8; 32],
    pub era: u64,
    pub promise: [u8; 32],
    pub active: bool,
    pub recovering: bool,
    pub capability: Capability,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Round {
    pub identity: SessionConsensusIdentity,
    pub voters: [u8; 32],
    pub era: u64,
    pub nonce: SessionConsensusRequestId,
    pub participants: BTreeMap<Node, Status>,
}

impl Round {
    pub fn digest(&self) -> Result<[u8; 32], SessionConsensusPeerError> {
        let mut hash = Sha256::new();
        hash.update(b"opc-async-unanimous-preparation-v1\0");
        hash.update(
            opc_consensus::encode_bounded(self).map_err(|_| SessionConsensusPeerError::Protocol)?,
        );
        Ok(hash.finalize().into())
    }

    pub fn validate(
        &self,
        identity: SessionConsensusIdentity,
        members: &BTreeSet<Node>,
    ) -> Result<(), SessionConsensusPeerError> {
        if self.identity != identity
            || !(members.len() == 3 || members.len() == 5)
            || self.voters != super::types::fenced_transition_voter_set_digest(identity, members)
            || self.participants.len() != members.len()
            || self.participants.keys().ne(members.iter())
            || self.participants.iter().any(|(node, status)| {
                *node != status.node
                    || status.capability != Capability::Reserved
                    || status.root == [0; 32]
                    || status.era == 0
                    || self.era <= status.era
            })
        {
            return Err(SessionConsensusPeerError::ScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Retained {
    pub vote: Option<Vote<Node>>,
    pub last: Option<LogId<Node>>,
    pub committed: Option<LogId<Node>>,
    pub applied: Option<LogId<Node>>,
    pub purged: Option<LogId<Node>>,
    pub membership: Option<LogId<Node>>,
    pub boundary: Option<(u64, [u8; 32], LogId<Node>)>,
    pub generation: u64,
    pub completed_generation: u64,
    pub sequence: u64,
    pub completed_sequence: u64,
    pub busy: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Prepared {
    pub participant: Status,
    pub promise: [u8; 32],
    pub retained: Retained,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Selection {
    pub round: Round,
    pub prepared: BTreeMap<Node, Prepared>,
    pub leader: Node,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ready {
    pub node: Node,
    pub boot: SessionConsensusRequestId,
    pub root: [u8; 32],
    pub promise: [u8; 32],
    pub vote: Vote<Node>,
    pub boundary: LogId<Node>,
    pub membership: Option<LogId<Node>>,
    pub completed_generation: u64,
    pub completed_sequence: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) enum Action {
    Status,
    Drive,
    Prepare(Round),
    Select(Selection),
    Commit(Selection),
    Ready {
        selection: Selection,
        boundary: LogId<Node>,
    },
    Activate {
        selection: Selection,
        ready: BTreeMap<Node, Ready>,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    tag: [u8; 23],
    pub action: Action,
}
impl Request {
    pub fn new(action: Action) -> Self {
        Self { tag: *WIRE, action }
    }
    pub fn is_valid(&self) -> bool {
        &self.tag == WIRE
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) enum Reply {
    Status(Status),
    Prepared(Box<Prepared>),
    Selected,
    Committed(LogId<Node>),
    Ready(Ready),
    Active,
}
