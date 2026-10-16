//! Compact generation-only encoding of the bounded Async recovery frontier.
//! The command wire and portable SQLite image retain Boundary's original
//! named JSON representation. The new root's generation vocabulary encodes
//! its canonical postcard bytes as padded base64, avoiding decimal byte
//! arrays for the complete 32-owner proof in each of a delta's two contexts.

use super::{async_recovery::Boundary, image::binary};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};

// At most 32 owner bindings (65 bytes each) and completion receipts (96
// bytes each), plus the fixed inventory, challenge and boundary metadata.
// Eight KiB includes worst-width varints and leaves over two KiB of slack.
pub(super) const MAX_RECOVERY_BYTES: usize = 8 * 1024;

pub(super) struct Recovery<'a>(pub(super) &'a Option<Boundary>);

impl Serialize for Recovery<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            None => serializer.serialize_none(),
            Some(boundary) => {
                let length = binary::encoded_len(boundary, MAX_RECOVERY_BYTES)
                    .map_err(serde::ser::Error::custom)?;
                let mut bytes = Vec::with_capacity(length);
                binary::write_to(boundary, &mut bytes, MAX_RECOVERY_BYTES)
                    .map_err(serde::ser::Error::custom)?;
                serializer.serialize_some(&BASE64.encode(bytes))
            }
        }
    }
}

pub(super) fn recovery<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<Option<Boundary>, D::Error> {
    let Some(value) = Option::<String>::deserialize(decoder)? else {
        return Ok(None);
    };
    if value.len() > 4 * MAX_RECOVERY_BYTES.div_ceil(3) {
        return Err(serde::de::Error::custom(
            "native recovery frontier exceeds encoding bound",
        ));
    }
    let bytes = BASE64.decode(value).map_err(serde::de::Error::custom)?;
    if bytes.len() > MAX_RECOVERY_BYTES {
        return Err(serde::de::Error::custom(
            "native recovery frontier exceeds encoding bound",
        ));
    }
    binary::decode(&bytes)
        .map(Some)
        .map_err(serde::de::Error::custom)
}
