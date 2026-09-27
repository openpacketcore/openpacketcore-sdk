//! Share the common intent stream without changing either digest transcript.

use super::{
    ConfigConsensusCommand, ConfigConsensusEntryDigest, ConfigDigestWriter, PersistError,
    Timestamp, COMMAND_DIGEST_DOMAIN, OUTCOME_DIGEST_DOMAIN,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{self, Write};

impl ConfigConsensusCommand {
    /// Compute the collision and applied-chain digests for a new command.
    pub(crate) fn payload_and_applied_digests(
        &self,
        sequence: u64,
        previous: ConfigConsensusEntryDigest,
        effective_time: Timestamp,
    ) -> Result<([u8; 32], ConfigConsensusEntryDigest), PersistError> {
        let mut outcome_hasher = Sha256::new();
        outcome_hasher.update(OUTCOME_DIGEST_DOMAIN);
        let mut applied_hasher = Sha256::new();
        applied_hasher.update(COMMAND_DIGEST_DOMAIN);
        {
            let mut outcome = ConfigDigestWriter::new(&mut outcome_hasher);
            let mut applied = ConfigDigestWriter::new(&mut applied_hasher);
            write_transcripts(
                self,
                sequence,
                previous,
                effective_time,
                &mut outcome,
                &mut applied,
            )
            .map_err(|_| PersistError::inconsistent_state("config consensus digests failed"))?;
            #[cfg(all(test, target_os = "linux"))]
            {
                crate::consensus::store::config_capacity_cost_observation::command_digest(
                    self.request_id,
                    true,
                    outcome.sink.bytes,
                    outcome.sink.updates,
                );
                crate::consensus::store::config_capacity_cost_observation::command_digest(
                    self.request_id,
                    false,
                    applied.sink.bytes,
                    applied.sink.updates,
                );
            }
        }
        Ok((
            outcome_hasher.finalize().into(),
            ConfigConsensusEntryDigest::from_bytes(applied_hasher.finalize().into()),
        ))
    }
}

// These two prefixes are the existing compact tuple/command framing. Keep
// field values on the original serializer, and destructure the complete command
// so a newly added field requires an explicit transcript decision here. The
// independent serde_json oracle checks both complete byte streams.
pub(super) fn write_transcripts<O: Write, A: Write>(
    command: &ConfigConsensusCommand,
    sequence: u64,
    previous: ConfigConsensusEntryDigest,
    effective_time: Timestamp,
    outcome: &mut O,
    applied: &mut A,
) -> io::Result<()> {
    let ConfigConsensusCommand {
        schema_version,
        identity,
        request_id,
        logical_time,
        intent,
    } = command;
    outcome.write_all(b"[")?;
    json(outcome, &intent.minimum_command_version())?;
    outcome.write_all(b",")?;
    json(outcome, identity)?;
    outcome.write_all(b",")?;

    applied.write_all(b"[")?;
    json(applied, &sequence)?;
    applied.write_all(b",")?;
    json(applied, &previous)?;
    applied.write_all(b",")?;
    json(applied, &effective_time)?;
    applied.write_all(b",{\"schema_version\":")?;
    json(applied, schema_version)?;
    applied.write_all(b",\"identity\":")?;
    json(applied, identity)?;
    applied.write_all(b",\"request_id\":")?;
    json(applied, request_id)?;
    applied.write_all(b",\"logical_time\":")?;
    json(applied, logical_time)?;
    applied.write_all(b",\"intent\":")?;

    #[cfg(all(test, target_os = "linux"))]
    let shared;
    {
        let mut pair = IntentWriters {
            outcome: &mut *outcome,
            applied: &mut *applied,
            #[cfg(all(test, target_os = "linux"))]
            bytes: 0,
            #[cfg(all(test, target_os = "linux"))]
            writes: 0,
        };
        json(&mut pair, intent)?;
        #[cfg(all(test, target_os = "linux"))]
        {
            shared = (pair.bytes, pair.writes);
        }
    }
    outcome.write_all(b"]")?;
    applied.write_all(b"}]")?;
    outcome.flush()?;
    applied.flush()?;
    #[cfg(all(test, target_os = "linux"))]
    crate::consensus::store::config_capacity_cost_observation::shared_digest_intent(
        command.request_id,
        shared.0,
        shared.1,
    );
    Ok(())
}

// Only the common intent bytes go to both original bounded digest buffers.
// Neither transcript is retained, and each SHA state keeps its own domain,
// prefix, suffix and finalization. Preserve short writes and the first error.
struct IntentWriters<'a, O, A> {
    outcome: &'a mut O,
    applied: &'a mut A,
    #[cfg(all(test, target_os = "linux"))]
    bytes: usize,
    #[cfg(all(test, target_os = "linux"))]
    writes: usize,
}

impl<O: Write, A: Write> Write for IntentWriters<'_, O, A> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.outcome.write_all(bytes)?;
        self.applied.write_all(bytes)?;
        #[cfg(all(test, target_os = "linux"))]
        {
            self.bytes += bytes.len();
            self.writes += 1;
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.outcome.flush()?;
        self.applied.flush()
    }
}

fn json<W: Write, T: Serialize + ?Sized>(writer: &mut W, value: &T) -> io::Result<()> {
    crate::consensus::config_capacity_json::to_writer(writer, value).map_err(io::Error::other)
}
