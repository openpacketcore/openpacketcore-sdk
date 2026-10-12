//! Complete, bounded method-17 observations. Decoding never creates authority.

use super::wire::{put_lp16, put_lp32, Reader, WireError};
use opc_session_store::scope_batch::*;

fn unavailable(_: impl std::fmt::Debug) -> ScopeChildReadError {
    ScopeBatchError::Unavailable.into()
}

pub(crate) fn encode_observation(
    request: &ScopeChildReadRequest,
    rows: &[Option<ScopeChildRecord>],
) -> Result<Vec<u8>, ScopeChildReadError> {
    if rows.len() != request.keys().len() {
        return Err(ScopeBatchError::FormatMismatch.into());
    }
    let mut bytes = vec![0];
    let namespace = postcard::to_allocvec(request.stamp().namespace())
        .map_err(|_| ScopeBatchError::FormatMismatch)?;
    put_lp16(&mut bytes, &namespace).map_err(|_| ScopeBatchError::FormatMismatch)?;
    bytes.push(rows.len() as u8);
    for (key, row) in request.keys().iter().zip(rows) {
        let encoded = row
            .as_ref()
            .map(|row| {
                if row.key() != *key || row.namespace() != request.stamp().namespace() {
                    return Err(ScopeBatchError::FormatMismatch);
                }
                row.encode_canonical()
                    .map_err(|_| ScopeBatchError::FormatMismatch)
            })
            .transpose()?;
        let extra = 33 + encoded.as_ref().map_or(0, |value| 4 + value.len());
        if bytes.len() + extra > MAX_SCOPE_CHILD_OBSERVATION_BYTES {
            return Ok(vec![1]);
        }
        bytes.extend_from_slice(key.as_bytes());
        bytes.push(u8::from(encoded.is_some()));
        if let Some(encoded) = encoded {
            put_lp32(&mut bytes, &encoded).map_err(|_| ScopeBatchError::FormatMismatch)?;
        }
    }
    Ok(bytes)
}

pub(crate) fn decode_observation(
    request: &ScopeChildReadRequest,
    bytes: &[u8],
) -> Result<Vec<Option<ScopeChildRecord>>, ScopeChildReadError> {
    if bytes.len() > MAX_SCOPE_CHILD_OBSERVATION_BYTES {
        return Err(unavailable(WireError));
    }
    if bytes == [1] {
        return Err(ScopeChildReadError::ObservationTooLarge);
    }
    let mut reader = Reader::new(bytes);
    if reader.u8().map_err(unavailable)? != 0 {
        return Err(unavailable(WireError));
    }
    // Compare the canonical namespace before allocating any peer-controlled rows.
    let namespace = postcard::to_allocvec(request.stamp().namespace()).map_err(unavailable)?;
    if reader
        .lp16(opc_session_store::scope_authority::MAX_SCOPE_AUTHORITY_RECORD_BYTES)
        .map_err(unavailable)?
        != namespace
        || usize::from(reader.u8().map_err(unavailable)?) != request.keys().len()
    {
        return Err(unavailable(WireError));
    }
    let mut rows = Vec::with_capacity(request.keys().len());
    for key in request.keys() {
        if reader.array::<32>().map_err(unavailable)? != *key.as_bytes() {
            return Err(unavailable(WireError));
        }
        let row = match reader.u8().map_err(unavailable)? {
            0 => None,
            1 => {
                let encoded = reader
                    .lp32(MAX_SCOPE_CHILD_RECORD_BYTES)
                    .map_err(unavailable)?;
                let row = ScopeChildRecord::decode_canonical(encoded).map_err(unavailable)?;
                if row.key() != *key || row.namespace() != request.stamp().namespace() {
                    return Err(unavailable(WireError));
                }
                Some(row)
            }
            _ => return Err(unavailable(WireError)),
        };
        rows.push(row);
    }
    reader.finish().map_err(unavailable)?;
    Ok(rows)
}
