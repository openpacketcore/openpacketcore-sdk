//! Independent copies of completely decoded roster commands. These preserve
//! the original signed carriers and cached digests; they grant no authority.

use super::*;
use std::io;

fn authority_copy(value: &AuthorityBinding) -> io::Result<AuthorityBinding> {
    AuthorityBinding::from_consensus_parts(
        value.scope().digest(),
        crate::consensus::native::owned::key(value.key())?,
        value.owner().clone(),
        value.fence(),
        AuthorityLeaseMetadata::new(
            value.credential_id(),
            value.generation(),
            value.acquired_at(),
            value.expires_at(),
        ),
    )
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "native owned roster authority invalid",
        )
    })
}

fn authority_bytes(value: &AuthorityBinding) -> Option<usize> {
    value
        .key()
        .log_row_reuse_allocation_bytes()?
        .checked_add(value.owner().allocation_capacity())
}

impl ConsensusRosterAdmissionCommand {
    pub(crate) fn copy_for_native_read(&self) -> io::Result<Self> {
        Ok(Self {
            admission: self.admission.copy_for_native_read()?,
            authority: authority_copy(&self.authority)?,
            ingress_request_id: self.ingress_request_id,
            ingress_attestation: self.ingress_attestation.clone(),
            admission_provenance: self.admission_provenance.clone(),
            digest_cache: self.digest_cache,
        })
    }

    // Includes the command's Box allocation at the intent boundary and all
    // actual String/Vec capacities. No decoder-owned backing is retained.
    pub(crate) fn native_read_allocation_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(self.admission.native_read_allocation_bytes()?)?
            .checked_add(authority_bytes(&self.authority)?)?
            .checked_add(self.ingress_attestation.0.capacity())?
            .checked_add(self.admission_provenance.0.capacity())
    }
}

impl ConsensusRosterTerminalCommand {
    pub(crate) fn copy_for_native_read(&self) -> io::Result<Self> {
        let mut copied = self.clone();
        copied.authority = authority_copy(&self.authority)?;
        Ok(copied)
    }

    pub(crate) fn native_read_allocation_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(authority_bytes(&self.authority)?)?
            .checked_add(self.record.0.capacity())?
            .checked_add(self.proof_bundle.0.capacity())?
            .checked_add(self.terminal_evidence.0.capacity())?
            .checked_add(self.ingress_attestation.0.capacity())
    }
}

impl ConsensusRosterTerminalCommandV2 {
    pub(crate) fn copy_for_native_read(&self) -> io::Result<Self> {
        let mut copied = self.clone();
        copied.authority = authority_copy(&self.authority)?;
        Ok(copied)
    }

    pub(crate) fn native_read_allocation_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(authority_bytes(&self.authority)?)?
            .checked_add(self.record.0.capacity())?
            .checked_add(self.proof_bundle.0.capacity())?
            .checked_add(self.terminal_evidence.0.capacity())?
            .checked_add(self.ingress_attestation.0.capacity())
    }
}
