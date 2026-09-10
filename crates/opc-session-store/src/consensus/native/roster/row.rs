//! An admitted roster row keeps either the complete original carrier or an
//! exact selected range and small comparison metadata. Only full hydration
//! can create that metadata; it is never decoded as an admission certificate.

use super::super::resident::SelectedRange;
use super::*;
use sha2::{Digest as _, Sha256};
use std::sync::Arc;

struct Cold {
    range: SelectedRange,
    canonical_length: usize,
    canonical_digest: [u8; 32],
}

pub(crate) struct Row {
    pub(super) binding: RequestBindingKey,
    pub(super) projection: Projection,
    pub(super) facts: Facts,
    reserved_key: Option<SessionKey>,
    pub(super) canonical: Vec<u8>,
    cold: Option<Cold>,
    // Hot canonical carriers retain their original lifetime reservation. Cold
    // rows own only the prospective resident metadata, as the other selected
    // row types do; that metadata belongs to whole-process RSS. Copies are
    // reserved until ownership transfers into this resident representation.
    _memory: Option<VerificationMemory>,
}

impl super::super::resident::RowFingerprint for Row {
    fn row_fingerprint(&self, table: u8, key: &impl Serialize) -> io::Result<[u8; 32]> {
        use super::super::changes::fingerprint;
        if table != 4 || fingerprint(table, key, &())? != fingerprint(table, &self.binding, &())? {
            return Err(invalid("native roster fingerprint key differs"));
        }
        let (length, digest) = match &self.cold {
            Some(cold) if self.canonical.is_empty() => {
                (cold.canonical_length, cold.canonical_digest)
            }
            Some(_) => return Err(invalid("native roster has two carrier representations")),
            None => (
                self.canonical.len(),
                <[u8; 32]>::from(Sha256::digest(&self.canonical)),
            ),
        };
        // Both forms commit to the same original carrier and admitted scalar
        // facts. This process comparison performs no selected I/O and cannot
        // construct or authenticate a row.
        fingerprint(
            table,
            key,
            &(
                &self.projection,
                self.facts,
                self.reserved_key(),
                length,
                digest,
            ),
        )
    }
}

impl Row {
    // Synthetic scalar-only index fixtures are never production carriers.
    #[cfg(test)]
    pub(super) fn index_fixture(
        binding: RequestBindingKey,
        projection: Projection,
        facts: Facts,
    ) -> io::Result<Self> {
        Ok(Self {
            binding,
            projection,
            facts,
            reserved_key: None,
            canonical: Vec::new(),
            cold: None,
            _memory: Some(VerificationMemory::reserve(1024)?),
        })
    }

    pub(crate) fn from_hydration(hydrated: &carrier::Hydration) -> io::Result<Self> {
        Self::copy(hydrated, None)
    }

    fn copy(hydrated: &carrier::Hydration, cold: Option<Cold>) -> io::Result<Self> {
        let canonical_bytes = if cold.is_some() {
            0
        } else {
            hydrated.canonical().len()
        };
        let bytes = canonical_bytes
            .checked_add(std::mem::size_of::<Self>() + 256)
            .and_then(|bytes| {
                bytes.checked_add(
                    hydrated
                        .reserved_key()
                        .map_or(Some(0), SessionKey::log_row_reuse_allocation_bytes)?,
                )
            })
            .ok_or_else(|| invalid("native roster row allocation overflow"))?;
        let memory = VerificationMemory::reserve(bytes)?;
        let reserved_key = hydrated
            .reserved_key()
            .map(|key| {
                Ok::<_, io::Error>(SessionKey {
                    tenant: key.tenant.clone(),
                    nf_kind: key.nf_kind.clone(),
                    key_type: key.key_type.clone(),
                    stable_id: crate::model::StableId::try_from(key.stable_id.as_bytes())
                        .map_err(|_| invalid("native roster key copy invalid"))?,
                })
            })
            .transpose()?;
        let canonical = if cold.is_some() {
            Vec::new()
        } else {
            hydrated.canonical().to_vec()
        };
        let mut row = Self {
            binding: hydrated.binding(),
            projection: hydrated.projection.clone(),
            facts: hydrated.facts,
            reserved_key,
            canonical,
            cold,
            _memory: Some(memory),
        };
        if row.cold.is_some() {
            row._memory = None;
        }
        Ok(row)
    }

    pub(in crate::consensus::native) fn hydration_fingerprint(
        hydrated: &carrier::Hydration,
    ) -> io::Result<[u8; 32]> {
        super::super::changes::fingerprint(
            4,
            &hydrated.binding(),
            &(
                &hydrated.projection,
                hydrated.facts,
                hydrated.reserved_key(),
                hydrated.canonical().len(),
                <[u8; 32]>::from(Sha256::digest(hydrated.canonical())),
            ),
        )
    }

    pub(crate) fn binding(&self) -> RequestBindingKey {
        self.binding
    }
    pub(crate) fn projection(&self) -> &Projection {
        &self.projection
    }
    pub(crate) fn facts(&self) -> Facts {
        self.facts
    }
    pub(crate) fn reserved_key(&self) -> Option<&SessionKey> {
        self.reserved_key.as_ref()
    }
    #[cfg(test)]
    pub(crate) fn is_cold(&self) -> bool {
        self.cold.is_some()
    }

    /// Pure resident access never opens a selected source implicitly.
    pub(crate) fn canonical(&self) -> io::Result<&[u8]> {
        if self.cold.is_some() {
            return Err(invalid("native roster carrier requires a detached read"));
        }
        Ok(&self.canonical)
    }

    /// Comparison only. Callers supply bytes from the unchanged authenticated
    /// evaluator/hydration; a matching hash cannot admit an arbitrary carrier.
    pub(crate) fn matches_canonical(&self, canonical: &[u8]) -> bool {
        match &self.cold {
            None => self.canonical == canonical,
            Some(cold) => {
                self.canonical.is_empty()
                    && canonical.len() == cold.canonical_length
                    && <[u8; 32]>::from(Sha256::digest(canonical)) == cold.canonical_digest
            }
        }
    }

    fn matches_hydration(&self, hydrated: &carrier::Hydration) -> bool {
        self.binding == hydrated.binding()
            && self.projection == hydrated.projection
            && self.facts == hydrated.facts
            && self.reserved_key() == hydrated.reserved_key()
            && self.matches_canonical(hydrated.canonical())
    }

    pub(crate) fn hydrate(
        &self,
        root: &RosterAttestationTrustRootV1,
        scope: &MembershipValidationScope,
    ) -> io::Result<carrier::Hydration> {
        let canonical = self.canonical()?;
        let _input = VerificationMemory::reserve(canonical.len())?;
        let hydrated = carrier::hydrate(
            self.projection.clone(),
            self.binding,
            canonical.to_vec(),
            root,
            scope,
        )
        .map_err(|_| invalid("native roster carrier authentication failed"))?;
        if !self.matches_hydration(&hydrated) {
            return Err(invalid(
                "native roster scalar projection differs from its carrier",
            ));
        }
        Ok(hydrated)
    }

    fn read(
        range: &SelectedRange,
        root: &RosterAttestationTrustRootV1,
        scope: &MembershipValidationScope,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<carrier::Hydration> {
        let input = range.read(check)?;
        let length = u32::try_from(input.bytes().len())
            .map_err(|_| invalid("native roster selected extent overflow"))?;
        let hydrated = frame::read_row(&mut io::Cursor::new(input.bytes()), length, root, scope)?;
        check()?;
        Ok(hydrated)
    }

    /// Full signature, identity and canonical validation runs outside State
    /// on every selected read. The enclosing ledger checks the current floor,
    /// cursor, business reservation, witness and applied horizon separately.
    pub(crate) fn hydrate_detached(
        &self,
        root: &RosterAttestationTrustRootV1,
        scope: &MembershipValidationScope,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<carrier::Hydration> {
        check()?;
        let hydrated = match &self.cold {
            None => self.hydrate(root, scope)?,
            Some(cold) => Self::read(&cold.range, root, scope, check)?,
        };
        if !self.matches_hydration(&hydrated) {
            return Err(invalid(
                "native selected roster carrier differs from its admitted row",
            ));
        }
        check()?;
        Ok(hydrated)
    }

    /// Reconstruct a prospective cold row using original full authentication.
    /// Neither a caller-provided fingerprint nor a serialized fact is accepted.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_selected_range(
        source: Arc<prefix::VerifiedPrefix>,
        offset: u64,
        length: u32,
        root: &RosterAttestationTrustRootV1,
        scope: &MembershipValidationScope,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Self> {
        let range = SelectedRange::new(source, offset, length, frame::MAX_ROW)?;
        let hydrated = Self::read(&range, root, scope, check)?;
        let cold = Cold {
            range,
            canonical_length: hydrated.canonical().len(),
            canonical_digest: Sha256::digest(hydrated.canonical()).into(),
        };
        let row = Self::copy(&hydrated, Some(cold))?;
        check()?;
        Ok(row)
    }

    /// Exact readback before representation relocation. The caller preserves
    /// the SharedRow revision and publishes only after durable selection.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn selected(
        &self,
        source: Arc<prefix::VerifiedPrefix>,
        offset: u64,
        length: u32,
        root: &RosterAttestationTrustRootV1,
        scope: &MembershipValidationScope,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Self> {
        let range = SelectedRange::new(source, offset, length, frame::MAX_ROW)?;
        let hydrated = Self::read(&range, root, scope, check)?;
        if !self.matches_hydration(&hydrated) {
            return Err(invalid(
                "native roster selected readback differs from captured row",
            ));
        }
        let cold = Cold {
            range,
            canonical_length: hydrated.canonical().len(),
            canonical_digest: Sha256::digest(hydrated.canonical()).into(),
        };
        let row = Self::copy(&hydrated, Some(cold))?;
        check()?;
        Ok(row)
    }
}
