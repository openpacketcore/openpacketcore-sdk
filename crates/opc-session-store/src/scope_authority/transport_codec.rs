//! Native claim codecs for authenticated transports; no capability construction.
use super::*;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, ScopeAuthorityError> {
    let bytes = postcard::to_allocvec(value).map_err(|_| ScopeAuthorityError::InvalidRequest)?;
    if bytes.len() > MAX_SCOPE_AUTHORITY_RECORD_BYTES {
        return Err(ScopeAuthorityError::InvalidRequest);
    }
    Ok(bytes)
}
fn decode<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, ScopeAuthorityError> {
    if bytes.len() > MAX_SCOPE_AUTHORITY_RECORD_BYTES {
        return Err(ScopeAuthorityError::InvalidRequest);
    }
    let (value, trailing): (T, &[u8]) =
        postcard::take_from_bytes(bytes).map_err(|_| ScopeAuthorityError::InvalidRequest)?;
    if !trailing.is_empty() || encode(&value)? != bytes {
        return Err(ScopeAuthorityError::InvalidRequest);
    }
    Ok(value)
}
fn scope_valid(scope: &ScopeId) -> Result<(), ScopeAuthorityError> {
    if scope.slot == [0; 32] {
        return Err(ScopeAuthorityError::InvalidRequest);
    }
    TenantId::new(scope.tenant.as_str()).map_err(|_| ScopeAuthorityError::InvalidRequest)?;
    NetworkFunctionKind::new(scope.nf_kind.as_str())
        .map_err(|_| ScopeAuthorityError::InvalidRequest)?;
    Ok(())
}

impl ScopeId {
    /// Canonical native scope bytes, bounded by the authority protocol limit.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, ScopeAuthorityError> {
        scope_valid(self)?;
        encode(self)
    }
    /// Decode native scope claims, rejecting malformed and noncanonical bytes.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ScopeAuthorityError> {
        let value = decode(bytes)?;
        scope_valid(&value)?;
        Ok(value)
    }
}
impl ScopeExecution {
    /// RFC026 public execution commitment over the native execution codec.
    pub fn transport_digest(&self) -> Result<[u8; 32], ScopeAuthorityError> {
        self.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"openpacketcore/scope/execution/v1\0");
        hash.update(encode(self)?);
        Ok(hash.finalize().into())
    }
}
impl ScopeAuthorityStamp {
    /// Canonical native claims; these bytes never convey effect authority.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, ScopeAuthorityError> {
        self.validate()?;
        scope_valid(self.scope())?;
        encode(self)
    }
    /// Decode and validate bounded native claims without issuing a capability.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ScopeAuthorityError> {
        let value: Self = decode(bytes)?;
        value.validate()?;
        scope_valid(value.scope())?;
        Ok(value)
    }
}
impl ScopeAuthorityView {
    /// Encode a structurally coherent native CurrentView, including an unused scope.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, ScopeAuthorityError> {
        self.validate_transport_claims()?;
        encode(self)
    }
    /// Decode canonical CurrentView claims; the authenticated read supplies trust.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ScopeAuthorityError> {
        let value: Self = decode(bytes)?;
        value.validate_transport_claims()?;
        Ok(value)
    }

    fn validate_transport_claims(&self) -> Result<(), ScopeAuthorityError> {
        scope_valid(&self.scope)?;
        if self.revision == 0 {
            if self.retired_through != 0
                || self.admission_generation_floor != 0
                || self.stamp.is_some()
                || self.active
                || self.closed_digest.is_some()
            {
                return Err(ScopeAuthorityError::InvalidRequest);
            }
            return Ok(());
        }
        let stamp = self
            .stamp
            .as_ref()
            .ok_or(ScopeAuthorityError::InvalidRequest)?;
        stamp.validate()?;
        if self.revision > COUNTER_MAX
            || stamp.revision != self.revision
            || stamp.scope() != &self.scope
            || self.retired_through >= stamp.incarnation().get()
            || self.admission_generation_floor != stamp.execution.admission_generation
            || (self.active && self.closed_digest.is_some())
            || (!self.active && self.closed_digest.is_none_or(|digest| digest == [0; 32]))
        {
            return Err(ScopeAuthorityError::InvalidRequest);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{admitted, close, scope};
    use super::*;
    use sha2::{Digest, Sha256};
    #[test]
    fn native_transport_claims_roundtrip_and_execution_digest_match_native_fields() {
        let state = admitted();
        let stamp = state.view.stamp().unwrap();
        let encoded = stamp.encode_canonical().unwrap();
        assert_eq!(encoded, postcard::to_allocvec(stamp).unwrap());
        assert_eq!(
            ScopeAuthorityStamp::decode_canonical(&encoded).unwrap(),
            *stamp
        );
        assert_eq!(
            ScopeId::decode_canonical(&scope().encode_canonical().unwrap()).unwrap(),
            scope()
        );
        let mut hash = Sha256::new();
        hash.update(b"openpacketcore/scope/execution/v1\0");
        hash.update(postcard::to_allocvec(stamp.execution()).unwrap());
        assert_eq!(
            stamp.execution().transport_digest().unwrap(),
            <[u8; 32]>::from(hash.finalize())
        );
        for value in [
            ScopeState::empty(scope()).view,
            state.view.clone(),
            state.transition(&close(&state, 3)).unwrap().view,
        ] {
            let encoded = value.encode_canonical().unwrap();
            assert_eq!(encoded, postcard::to_allocvec(&value).unwrap());
            assert_eq!(
                ScopeAuthorityView::decode_canonical(&encoded).unwrap(),
                value
            );
            let mut trailing = encoded;
            trailing.push(0);
            assert!(ScopeAuthorityView::decode_canonical(&trailing).is_err());
        }
    }
    #[test]
    fn view_decoding_rejects_incoherent_floors_and_closed_claims() {
        let state = admitted();
        let original = state.view;
        for index in 0..6 {
            let mut view = original.clone();
            match index {
                0 => view.admission_generation_floor += 1,
                1 => view.retired_through = view.stamp().unwrap().incarnation().get(),
                2 => view.revision += 1,
                3 => view.closed_digest = Some([1; 32]),
                4 => view.active = false,
                _ => view.stamp = None,
            }
            assert!(
                ScopeAuthorityView::decode_canonical(&postcard::to_allocvec(&view).unwrap())
                    .is_err()
            );
        }
        let mut empty = ScopeState::empty(scope()).view;
        empty.admission_generation_floor = 1;
        assert!(
            ScopeAuthorityView::decode_canonical(&postcard::to_allocvec(&empty).unwrap()).is_err()
        );
    }
}
