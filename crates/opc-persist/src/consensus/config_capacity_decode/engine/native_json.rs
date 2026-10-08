//! Preflight parser scratch before privately decoding a bounded native row.
//! Retained readers keep their existing legacy decoder and refuse bounded tags.

use super::*;

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> std::io::Result<T> {
    super::super::json_preflight(bytes).map_err(|()| invalid_row())?;
    serde_json::from_slice(bytes).map_err(|_| invalid_row())
}

fn invalid_row() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "invalid bounded configuration encoding",
    )
}

pub(in crate::consensus::config_capacity_decode) fn entry(
    bytes: &[u8],
) -> std::io::Result<Entry<ConfigRaftTypeConfig>> {
    decode::<EntryFields>(bytes).map(Into::into)
}

pub(in crate::consensus::config_capacity_decode) fn membership(
    bytes: &[u8],
) -> std::io::Result<StoredMembership<ConsensusNodeId, EmptyNode>> {
    decode::<Stored>(bytes).map(Into::into)
}

pub(in crate::consensus::config_capacity_decode) fn snapshot_meta(
    bytes: &[u8],
) -> std::io::Result<SnapshotMeta<ConsensusNodeId, EmptyNode>> {
    decode::<Meta>(bytes).map(Into::into)
}
