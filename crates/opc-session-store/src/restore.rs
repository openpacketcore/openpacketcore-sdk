//! Restore evidence vocabulary for stateful packet-core CNFs.
//!
//! The helpers in this module summarize durable session-store record headers
//! and restore gates without decoding product payloads or making any packet
//! forwarding claim.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;

use aes_gcm_siv::{
    aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
    Aes256GcmSiv,
};
use hmac::{Hmac, Mac};
use opc_key::Zeroizing;
use opc_redaction::{redact_text, RedactionSummary};
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    hex::encode_lower, OwnerId, SessionKey, SessionKeyType, StateClass, StateType, StoreError,
    StoredSessionRecord,
};

/// Default maximum restore scan page size.
pub const RESTORE_SCAN_DEFAULT_PAGE_SIZE: usize = 256;

/// Hard maximum restore scan page size.
pub const RESTORE_SCAN_MAX_PAGE_SIZE: usize = 1024;

/// Hard maximum combined payload bytes returned by one restore page.
///
/// Backends must stop before crossing this limit. A single record whose
/// payload exceeds the limit is rejected rather than returned partially.
pub const RESTORE_SCAN_MAX_PAGE_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

/// Hard maximum logical bytes retained by one restore page.
///
/// This includes record structs, key and metadata allocations, payload bytes,
/// page metadata, and the raw continuation cursor. Encoded transports apply
/// their independent negotiated frame ceiling in addition to this in-memory
/// bound.
pub const RESTORE_SCAN_MAX_PAGE_RETAINED_BYTES: usize = 8 * 1024 * 1024;

/// Hard maximum key and filter-metadata bytes examined for one SQLite page.
///
/// Payload blobs are not selected by the candidate query and therefore are
/// counted only if their record is admitted to the retained page.
pub const RESTORE_SCAN_MAX_EXAMINED_METADATA_BYTES: usize = 8 * 1024 * 1024;

/// Maximum SQLite virtual-machine instructions spent on one restore page.
pub const RESTORE_SCAN_MAX_SQLITE_VM_STEPS: usize = 2_000_000;

/// Maximum wall-clock milliseconds spent inside one SQLite restore query.
pub const RESTORE_SCAN_MAX_SQLITE_WORK_MILLIS: u64 = 1_000;

/// Maximum live candidate rows examined while building one restore page.
///
/// A page may contain fewer records than requested (including zero) when a
/// narrow scope excludes candidates. In that case an advancing cursor lets
/// the caller continue without any page performing an unbounded sparse scan.
pub const RESTORE_SCAN_MAX_EXAMINED_ROWS_PER_PAGE: usize = 4_096;

const RESTORE_SCAN_CURSOR_VERSION: u8 = 1;
const RESTORE_SCAN_SCOPE_DIGEST_DOMAIN: &[u8] = b"openpacketcore/session-restore-scope/v1\0";
const RESTORE_SCAN_CURSOR_AAD: &[u8] = b"openpacketcore/session-restore-cursor/v1";
const RESTORE_SCAN_CURSOR_AEAD_KEY_DOMAIN: &[u8] =
    b"openpacketcore/session-restore-cursor/aead-key/v1\0";
const RESTORE_SCAN_CURSOR_NONCE_KEY_DOMAIN: &[u8] =
    b"openpacketcore/session-restore-cursor/nonce-key/v1\0";
const RESTORE_SCAN_CURSOR_NONCE_BYTES: usize = 12;
const RESTORE_SCAN_CURSOR_TENANT_BYTES: usize = 128;
const RESTORE_SCAN_CURSOR_NF_KIND_BYTES: usize = 64;
const RESTORE_SCAN_CURSOR_KEY_TYPE_BYTES: usize = 128;
const RESTORE_SCAN_CURSOR_STABLE_ID_BYTES: usize = crate::STABLE_ID_MAX_BYTES;
const RESTORE_SCAN_CURSOR_FIELD_LENGTH_BYTES: usize = 4;
const RESTORE_SCAN_CURSOR_EXAMINED_BYTES: usize = 8;
const RESTORE_SCAN_CURSOR_TAG_BYTES: usize = 16;
const RESTORE_SCAN_CURSOR_LEGACY_BYTES: usize = 1 + RESTORE_SCAN_CURSOR_EXAMINED_BYTES;
const RESTORE_SCAN_CURSOR_PLAINTEXT_FIXED_BYTES: usize = 16
    + 8
    + 16
    + 32
    + RESTORE_SCAN_CURSOR_EXAMINED_BYTES
    + (4 * RESTORE_SCAN_CURSOR_FIELD_LENGTH_BYTES);
const RESTORE_SCAN_CURSOR_MIN_PLAINTEXT_BYTES: usize = RESTORE_SCAN_CURSOR_PLAINTEXT_FIXED_BYTES;
const RESTORE_SCAN_CURSOR_MAX_PLAINTEXT_BYTES: usize = RESTORE_SCAN_CURSOR_PLAINTEXT_FIXED_BYTES
    + RESTORE_SCAN_CURSOR_TENANT_BYTES
    + RESTORE_SCAN_CURSOR_NF_KIND_BYTES
    + RESTORE_SCAN_CURSOR_KEY_TYPE_BYTES
    + RESTORE_SCAN_CURSOR_STABLE_ID_BYTES;
const RESTORE_SCAN_CURSOR_ENVELOPE_BYTES: usize = 1
    + RESTORE_SCAN_CURSOR_EXAMINED_BYTES
    + RESTORE_SCAN_CURSOR_NONCE_BYTES
    + RESTORE_SCAN_CURSOR_TAG_BYTES;
const RESTORE_SCAN_CURSOR_MIN_DURABLE_BYTES: usize =
    RESTORE_SCAN_CURSOR_ENVELOPE_BYTES + RESTORE_SCAN_CURSOR_MIN_PLAINTEXT_BYTES;
const RESTORE_SCAN_CURSOR_MAX_DURABLE_BYTES: usize =
    RESTORE_SCAN_CURSOR_ENVELOPE_BYTES + RESTORE_SCAN_CURSOR_MAX_PLAINTEXT_BYTES;
const RESTORE_SCAN_CURSOR_MAX_HEX_CHARS: usize = RESTORE_SCAN_CURSOR_MAX_DURABLE_BYTES * 2;
const RESTORE_SCAN_CURSOR_AAD_BYTES: usize =
    RESTORE_SCAN_CURSOR_AAD.len() + 1 + RESTORE_SCAN_CURSOR_EXAMINED_BYTES;

/// Opaque cursor for paged restore scans.
///
/// The token binds a backend position to one durable backend incarnation,
/// record revision, logical-time snapshot, and request scope. Its only clear
/// metadata is a cumulative examined-row position bound into authentication,
/// used to validate the issuer's claimed pagination step. It contains no plaintext session-key,
/// time, or product payload identifiers through its wire or debug form.
/// Backends reject tokens issued for another store or for state that changed
/// between pages.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RestoreScanCursor {
    token: Arc<[u8]>,
}

impl std::fmt::Debug for RestoreScanCursor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RestoreScanCursor")
            .field("version", &self.token.first().copied())
            .field("token", &"[redacted]")
            .finish()
    }
}

impl RestoreScanCursor {
    /// Build a legacy offset cursor for compatibility-only backends.
    ///
    /// Production durable backends return versioned snapshot-bound cursors.
    pub fn from_offset(offset: usize) -> Self {
        let mut token = [0_u8; RESTORE_SCAN_CURSOR_LEGACY_BYTES];
        // Rust supports targets whose pointer width is at most 64 bits.
        let offset = (offset as u64).to_be_bytes();
        token[1..].copy_from_slice(&offset);
        Self {
            token: Arc::from(token),
        }
    }

    /// Return the backend-neutral numeric position represented by this cursor.
    ///
    /// This accessor remains for compatibility with the legacy protocol. It
    /// does not reveal a session identifier. Durable cursors expose the same
    /// cumulative examined-row position so a peer page can be checked for a
    /// structurally consistent claimed step without decrypting the seek key.
    /// The issuing backend authenticates that position when it consumes the
    /// cursor; a receiver cannot infer page completeness from it.
    pub fn offset(&self) -> usize {
        let offset = self.examined_position().unwrap_or(u64::MAX);
        if offset > usize::MAX as u64 {
            usize::MAX
        } else {
            offset as usize
        }
    }

    pub(crate) fn retained_token_bytes(&self) -> usize {
        self.token.len()
    }

    pub(crate) fn durable_retained_token_bytes_for_key(
        seek_key: &SessionKey,
    ) -> Result<usize, StoreError> {
        let plaintext_bytes = RESTORE_SCAN_CURSOR_PLAINTEXT_FIXED_BYTES
            .checked_add(seek_key.tenant.as_str().len())
            .and_then(|value| value.checked_add(seek_key.nf_kind.as_str().len()))
            .and_then(|value| value.checked_add(seek_key.key_type.as_str().len()))
            .and_then(|value| value.checked_add(seek_key.stable_id.len()))
            .ok_or(StoreError::RestoreScanWorkBudgetExceeded)?;
        if plaintext_bytes > RESTORE_SCAN_CURSOR_MAX_PLAINTEXT_BYTES {
            return Err(StoreError::RestoreScanWorkBudgetExceeded);
        }
        RESTORE_SCAN_CURSOR_ENVELOPE_BYTES
            .checked_add(plaintext_bytes)
            .ok_or(StoreError::RestoreScanWorkBudgetExceeded)
    }

    pub(crate) fn durable(
        authentication_key: &[u8; 32],
        backend_epoch: [u8; 16],
        snapshot_revision: u64,
        snapshot_time: Timestamp,
        scope: &RestoreScanScope,
        seek_key: &SessionKey,
        examined_position: u64,
    ) -> Result<Self, StoreError> {
        let plaintext_capacity = Self::durable_retained_token_bytes_for_key(seek_key)?
            .checked_sub(RESTORE_SCAN_CURSOR_ENVELOPE_BYTES)
            .ok_or(StoreError::RestoreScanWorkBudgetExceeded)?;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(plaintext_capacity));
        plaintext.extend_from_slice(&backend_epoch);
        plaintext.extend_from_slice(&snapshot_revision.to_be_bytes());
        plaintext.extend_from_slice(
            &snapshot_time
                .as_offset_datetime()
                .unix_timestamp_nanos()
                .to_be_bytes(),
        );
        plaintext.extend_from_slice(&restore_scope_digest(scope));
        plaintext.extend_from_slice(&examined_position.to_be_bytes());
        append_cursor_field(
            &mut plaintext,
            seek_key.tenant.as_str().as_bytes(),
            RESTORE_SCAN_CURSOR_TENANT_BYTES,
        )?;
        append_cursor_field(
            &mut plaintext,
            seek_key.nf_kind.as_str().as_bytes(),
            RESTORE_SCAN_CURSOR_NF_KIND_BYTES,
        )?;
        append_cursor_field(
            &mut plaintext,
            seek_key.key_type.as_str().as_bytes(),
            RESTORE_SCAN_CURSOR_KEY_TYPE_BYTES,
        )?;
        append_cursor_field(
            &mut plaintext,
            seek_key.stable_id.as_ref(),
            RESTORE_SCAN_CURSOR_STABLE_ID_BYTES,
        )?;
        if plaintext.len() != plaintext_capacity {
            return Err(StoreError::BackendUnavailable(
                "session restore cursor failed".into(),
            ));
        }

        let aad = restore_cursor_aad(examined_position);
        let aead_key =
            derive_restore_cursor_subkey(authentication_key, RESTORE_SCAN_CURSOR_AEAD_KEY_DOMAIN)?;
        let nonce_key =
            derive_restore_cursor_subkey(authentication_key, RESTORE_SCAN_CURSOR_NONCE_KEY_DOMAIN)?;
        let nonce = synthetic_restore_cursor_nonce(&nonce_key, &aad, &plaintext)?;
        let cipher = Aes256GcmSiv::new(GenericArray::from_slice(aead_key.as_ref()));
        let tag = cipher
            .encrypt_in_place_detached(GenericArray::from_slice(&nonce), &aad, &mut plaintext)
            .map_err(|_| StoreError::BackendUnavailable("session restore cursor failed".into()))?;

        let token_capacity = RESTORE_SCAN_CURSOR_ENVELOPE_BYTES
            .checked_add(plaintext.len())
            .ok_or(StoreError::RestoreScanWorkBudgetExceeded)?;
        let mut token = Vec::with_capacity(token_capacity);
        token.push(RESTORE_SCAN_CURSOR_VERSION);
        token.extend_from_slice(&examined_position.to_be_bytes());
        token.extend_from_slice(&nonce);
        token.extend_from_slice(&plaintext);
        token.extend_from_slice(tag.as_slice());
        if token.len() != token_capacity {
            return Err(StoreError::BackendUnavailable(
                "session restore cursor failed".into(),
            ));
        }
        Ok(Self {
            token: Arc::from(token),
        })
    }

    pub(crate) fn authenticated_parts(
        &self,
        scope: &RestoreScanScope,
        authentication_key: &[u8; 32],
    ) -> Result<([u8; 16], u64, Timestamp, SessionKey, u64), StoreError> {
        if self.token.first().copied() != Some(RESTORE_SCAN_CURSOR_VERSION)
            || !(RESTORE_SCAN_CURSOR_MIN_DURABLE_BYTES..=RESTORE_SCAN_CURSOR_MAX_DURABLE_BYTES)
                .contains(&self.token.len())
        {
            return Err(StoreError::RestoreScanCursorStale);
        }
        let examined_position = self
            .examined_position()
            .ok_or(StoreError::RestoreScanCursorStale)?;
        let nonce_start = 1 + RESTORE_SCAN_CURSOR_EXAMINED_BYTES;
        let ciphertext_start = nonce_start + RESTORE_SCAN_CURSOR_NONCE_BYTES;
        let tag_start = self
            .token
            .len()
            .checked_sub(RESTORE_SCAN_CURSOR_TAG_BYTES)
            .ok_or(StoreError::RestoreScanCursorStale)?;
        if tag_start < ciphertext_start {
            return Err(StoreError::RestoreScanCursorStale);
        }
        let mut plaintext = Zeroizing::new(Vec::with_capacity(tag_start - ciphertext_start));
        plaintext.extend_from_slice(&self.token[ciphertext_start..tag_start]);
        let aad = restore_cursor_aad(examined_position);
        let aead_key =
            derive_restore_cursor_subkey(authentication_key, RESTORE_SCAN_CURSOR_AEAD_KEY_DOMAIN)
                .map_err(|_| StoreError::RestoreScanCursorStale)?;
        let cipher = Aes256GcmSiv::new(GenericArray::from_slice(aead_key.as_ref()));
        cipher
            .decrypt_in_place_detached(
                GenericArray::from_slice(&self.token[nonce_start..ciphertext_start]),
                &aad,
                &mut plaintext,
                GenericArray::from_slice(&self.token[tag_start..]),
            )
            .map_err(|_| StoreError::RestoreScanCursorStale)?;
        let nonce_key =
            derive_restore_cursor_subkey(authentication_key, RESTORE_SCAN_CURSOR_NONCE_KEY_DOMAIN)
                .map_err(|_| StoreError::RestoreScanCursorStale)?;
        let expected_nonce = synthetic_restore_cursor_nonce(&nonce_key, &aad, &plaintext)
            .map_err(|_| StoreError::RestoreScanCursorStale)?;
        if self.token[nonce_start..ciphertext_start] != expected_nonce {
            return Err(StoreError::RestoreScanCursorStale);
        }

        let mut cursor = 0_usize;
        let backend_epoch = take_array::<16>(&plaintext, &mut cursor)
            .map_err(|_| StoreError::RestoreScanCursorStale)?;
        let snapshot_revision = u64::from_be_bytes(
            take_array::<8>(&plaintext, &mut cursor)
                .map_err(|_| StoreError::RestoreScanCursorStale)?,
        );
        let snapshot_time_unix_nanos = i128::from_be_bytes(
            take_array::<16>(&plaintext, &mut cursor)
                .map_err(|_| StoreError::RestoreScanCursorStale)?,
        );
        let scope_digest = take_array::<32>(&plaintext, &mut cursor)
            .map_err(|_| StoreError::RestoreScanCursorStale)?;
        let authenticated_examined_position = u64::from_be_bytes(
            take_array::<8>(&plaintext, &mut cursor)
                .map_err(|_| StoreError::RestoreScanCursorStale)?,
        );
        if authenticated_examined_position != examined_position {
            return Err(StoreError::RestoreScanCursorStale);
        }
        let tenant = take_cursor_field(&plaintext, &mut cursor, RESTORE_SCAN_CURSOR_TENANT_BYTES)?;
        let nf_kind =
            take_cursor_field(&plaintext, &mut cursor, RESTORE_SCAN_CURSOR_NF_KIND_BYTES)?;
        let key_type =
            take_cursor_field(&plaintext, &mut cursor, RESTORE_SCAN_CURSOR_KEY_TYPE_BYTES)?;
        let stable_id =
            take_cursor_field(&plaintext, &mut cursor, RESTORE_SCAN_CURSOR_STABLE_ID_BYTES)?;
        if cursor != plaintext.len() {
            return Err(StoreError::RestoreScanCursorStale);
        }
        if backend_epoch == [0; 16] || scope_digest != restore_scope_digest(scope) {
            return Err(StoreError::RestoreScanCursorStale);
        }
        let snapshot_time =
            time::OffsetDateTime::from_unix_timestamp_nanos(snapshot_time_unix_nanos)
                .map(Timestamp::from_offset_datetime)
                .map_err(|_| StoreError::RestoreScanCursorStale)?;
        let tenant =
            std::str::from_utf8(&tenant).map_err(|_| StoreError::RestoreScanCursorStale)?;
        let nf_kind =
            std::str::from_utf8(&nf_kind).map_err(|_| StoreError::RestoreScanCursorStale)?;
        let key_type =
            std::str::from_utf8(&key_type).map_err(|_| StoreError::RestoreScanCursorStale)?;
        let seek_key = SessionKey {
            tenant: TenantId::new(tenant.to_owned())
                .map_err(|_| StoreError::RestoreScanCursorStale)?,
            nf_kind: NetworkFunctionKind::new(nf_kind.to_owned())
                .map_err(|_| StoreError::RestoreScanCursorStale)?,
            key_type: SessionKeyType::from_str(key_type)
                .map_err(|_| StoreError::RestoreScanCursorStale)?,
            stable_id: crate::StableId::try_from(stable_id)
                .map_err(|_| StoreError::RestoreScanCursorStale)?,
        };
        Ok((
            backend_epoch,
            snapshot_revision,
            snapshot_time,
            seek_key,
            examined_position,
        ))
    }

    pub(crate) fn is_legacy(&self) -> bool {
        self.token.first().copied() == Some(0)
    }

    /// Whether this is a compatibility-only numeric cursor.
    ///
    /// Remote production adapters must reject this profile; it exists only
    /// for deterministic in-process test backends.
    pub fn is_legacy_compatibility(&self) -> bool {
        self.is_legacy()
    }

    fn validate_for_scope(&self, _scope: &RestoreScanScope) -> Result<(), StoreError> {
        if self.is_legacy() {
            if self.token.len() != RESTORE_SCAN_CURSOR_LEGACY_BYTES {
                return Err(StoreError::RestoreScanCursorStale);
            }
            return Ok(());
        }
        if self.token.first().copied() != Some(RESTORE_SCAN_CURSOR_VERSION)
            || !(RESTORE_SCAN_CURSOR_MIN_DURABLE_BYTES..=RESTORE_SCAN_CURSOR_MAX_DURABLE_BYTES)
                .contains(&self.token.len())
        {
            return Err(StoreError::RestoreScanCursorStale);
        }
        Ok(())
    }

    fn examined_position(&self) -> Option<u64> {
        self.token
            .get(1..1 + RESTORE_SCAN_CURSOR_EXAMINED_BYTES)?
            .try_into()
            .ok()
            .map(u64::from_be_bytes)
    }

    fn encode_token(&self) -> String {
        encode_lower(&self.token[..])
    }

    fn decode_token(value: &str) -> Result<Self, &'static str> {
        if value.len() > RESTORE_SCAN_CURSOR_MAX_HEX_CHARS {
            return Err("restore scan cursor exceeds the maximum length");
        }
        if value.len() < RESTORE_SCAN_CURSOR_LEGACY_BYTES * 2 || !value.len().is_multiple_of(2) {
            return Err("restore scan cursor has an invalid length");
        }
        if !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err("restore scan cursor is not lowercase hexadecimal");
        }
        let first = value.as_bytes();
        let version =
            (decode_hex_nibble(first[0]).ok_or("restore scan cursor is not hexadecimal")? << 4)
                | decode_hex_nibble(first[1]).ok_or("restore scan cursor is not hexadecimal")?;
        let decoded_len = value.len() / 2;
        match version {
            0 if decoded_len == RESTORE_SCAN_CURSOR_LEGACY_BYTES => {}
            RESTORE_SCAN_CURSOR_VERSION
                if (RESTORE_SCAN_CURSOR_MIN_DURABLE_BYTES
                    ..=RESTORE_SCAN_CURSOR_MAX_DURABLE_BYTES)
                    .contains(&decoded_len) => {}
            0 | RESTORE_SCAN_CURSOR_VERSION => {
                return Err("restore scan cursor has an invalid length")
            }
            _ => return Err("restore scan cursor version is unsupported"),
        }
        let mut bytes = Vec::with_capacity(decoded_len);
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let high =
                decode_hex_nibble(pair[0]).ok_or("restore scan cursor is not hexadecimal")?;
            let low = decode_hex_nibble(pair[1]).ok_or("restore scan cursor is not hexadecimal")?;
            debug_assert_eq!(index, bytes.len());
            bytes.push((high << 4) | low);
        }

        Ok(Self {
            token: Arc::from(bytes),
        })
    }
}

fn append_cursor_field(output: &mut Vec<u8>, value: &[u8], max: usize) -> Result<(), StoreError> {
    if value.len() > max {
        return Err(StoreError::RestoreScanWorkBudgetExceeded);
    }
    let length =
        u32::try_from(value.len()).map_err(|_| StoreError::RestoreScanWorkBudgetExceeded)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn take_cursor_field(
    plaintext: &[u8],
    cursor: &mut usize,
    max: usize,
) -> Result<Vec<u8>, StoreError> {
    let length = usize::try_from(u32::from_be_bytes(
        take_array::<4>(plaintext, cursor).map_err(|_| StoreError::RestoreScanCursorStale)?,
    ))
    .map_err(|_| StoreError::RestoreScanCursorStale)?;
    if length > max {
        return Err(StoreError::RestoreScanCursorStale);
    }
    let end = cursor
        .checked_add(length)
        .ok_or(StoreError::RestoreScanCursorStale)?;
    let value = plaintext
        .get(*cursor..end)
        .ok_or(StoreError::RestoreScanCursorStale)?
        .to_vec();
    *cursor = end;
    Ok(value)
}

impl Serialize for RestoreScanCursor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.encode_token())
    }
}

impl<'de> Deserialize<'de> for RestoreScanCursor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct CursorVisitor;

        impl serde::de::Visitor<'_> for CursorVisitor {
            type Value = RestoreScanCursor;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a bounded lowercase-hex restore scan cursor")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                RestoreScanCursor::decode_token(value).map_err(E::custom)
            }

            fn visit_borrowed_str<E>(self, value: &'_ str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(value)
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value.len() > RESTORE_SCAN_CURSOR_MAX_HEX_CHARS {
                    return Err(E::custom("restore scan cursor exceeds the maximum length"));
                }
                self.visit_str(&value)
            }
        }

        deserializer.deserialize_str(CursorVisitor)
    }
}

fn restore_cursor_aad(examined_position: u64) -> [u8; RESTORE_SCAN_CURSOR_AAD_BYTES] {
    let mut aad = [0_u8; RESTORE_SCAN_CURSOR_AAD_BYTES];
    aad[..RESTORE_SCAN_CURSOR_AAD.len()].copy_from_slice(RESTORE_SCAN_CURSOR_AAD);
    aad[RESTORE_SCAN_CURSOR_AAD.len()] = RESTORE_SCAN_CURSOR_VERSION;
    aad[RESTORE_SCAN_CURSOR_AAD.len() + 1..].copy_from_slice(&examined_position.to_be_bytes());
    aad
}

fn derive_restore_cursor_subkey(
    authentication_key: &[u8; 32],
    domain: &[u8],
) -> Result<Zeroizing<[u8; 32]>, StoreError> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(authentication_key)
        .map_err(|_| StoreError::BackendUnavailable("session restore cursor failed".into()))?;
    mac.update(domain);
    Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
}

fn synthetic_restore_cursor_nonce(
    nonce_key: &[u8; 32],
    aad: &[u8],
    canonical_plaintext: &[u8],
) -> Result<[u8; RESTORE_SCAN_CURSOR_NONCE_BYTES], StoreError> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(nonce_key)
        .map_err(|_| StoreError::BackendUnavailable("session restore cursor failed".into()))?;
    mac.update(aad);
    mac.update(canonical_plaintext);
    let digest = Zeroizing::new(<[u8; 32]>::from(mac.finalize().into_bytes()));
    let mut nonce = [0_u8; RESTORE_SCAN_CURSOR_NONCE_BYTES];
    nonce.copy_from_slice(&digest[..RESTORE_SCAN_CURSOR_NONCE_BYTES]);
    Ok(nonce)
}

fn decode_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn take_array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N], &'static str> {
    let end = cursor
        .checked_add(N)
        .ok_or("restore scan cursor length overflowed")?;
    let value = bytes
        .get(*cursor..end)
        .ok_or("restore scan cursor ended unexpectedly")?
        .try_into()
        .map_err(|_| "restore scan cursor field has an invalid length")?;
    *cursor = end;
    Ok(value)
}

fn restore_scope_digest(scope: &RestoreScanScope) -> [u8; 32] {
    fn update_optional(hasher: &mut Sha256, value: Option<&[u8]>) {
        match value {
            Some(value) => {
                hasher.update([1]);
                // Rust targets supported by this crate have pointers no wider
                // than the fixed u64 digest length field.
                let length = value.len() as u64;
                hasher.update(length.to_be_bytes());
                hasher.update(value);
            }
            None => hasher.update([0]),
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(RESTORE_SCAN_SCOPE_DIGEST_DOMAIN);
    update_optional(
        &mut hasher,
        scope.tenant.as_ref().map(|value| value.as_str().as_bytes()),
    );
    update_optional(
        &mut hasher,
        scope
            .nf_kind
            .as_ref()
            .map(|value| value.as_str().as_bytes()),
    );
    let key_type = scope.key_type.as_ref().map(ToString::to_string);
    update_optional(&mut hasher, key_type.as_deref().map(str::as_bytes));
    let state_class = scope.state_class.map(|value| value.to_string());
    update_optional(&mut hasher, state_class.as_deref().map(str::as_bytes));
    update_optional(
        &mut hasher,
        scope
            .state_type
            .as_ref()
            .map(|value| value.as_str().as_bytes()),
    );
    update_optional(
        &mut hasher,
        scope.owner.as_ref().map(|value| value.as_str().as_bytes()),
    );
    hasher.finalize().into()
}

/// Typed scope for backend-neutral restore scans.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RestoreScanScope {
    /// Optional tenant filter.
    pub tenant: Option<TenantId>,
    /// Optional network-function kind filter.
    pub nf_kind: Option<NetworkFunctionKind>,
    /// Optional session-key type filter.
    pub key_type: Option<SessionKeyType>,
    /// Optional state-class filter.
    pub state_class: Option<StateClass>,
    /// Optional state-type filter.
    pub state_type: Option<StateType>,
    /// Optional record-owner filter.
    pub owner: Option<OwnerId>,
}

impl RestoreScanScope {
    /// Scope that matches every live record.
    pub fn all() -> Self {
        Self::default()
    }

    /// Whether this scope includes `record`.
    pub fn matches_record(&self, record: &StoredSessionRecord) -> bool {
        self.tenant
            .as_ref()
            .is_none_or(|tenant| tenant == &record.key.tenant)
            && self
                .nf_kind
                .as_ref()
                .is_none_or(|nf_kind| nf_kind == &record.key.nf_kind)
            && self
                .key_type
                .as_ref()
                .is_none_or(|key_type| key_type == &record.key.key_type)
            && self
                .state_class
                .is_none_or(|state_class| state_class == record.state_class)
            && self
                .state_type
                .as_ref()
                .is_none_or(|state_type| state_type == &record.state_type)
            && self
                .owner
                .as_ref()
                .is_none_or(|owner| owner == &record.owner)
    }
}

/// Restore scan request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreScanRequest {
    /// Scope to scan.
    pub scope: RestoreScanScope,
    /// Cursor returned by a previous page, or `None` for the first page.
    pub cursor: Option<RestoreScanCursor>,
    /// Maximum records to return in this page.
    pub limit: usize,
}

impl RestoreScanRequest {
    /// Build a first-page request for all live records.
    pub const fn all(limit: usize) -> Self {
        Self {
            scope: RestoreScanScope {
                tenant: None,
                nf_kind: None,
                key_type: None,
                state_class: None,
                state_type: None,
                owner: None,
            },
            cursor: None,
            limit,
        }
    }

    /// Validate page-size bounds.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.limit == 0 {
            return Err(StoreError::InvalidRestoreScanRequest(
                "restore scan limit must be greater than zero".to_string(),
            ));
        }
        if self.limit > RESTORE_SCAN_MAX_PAGE_SIZE {
            return Err(StoreError::RestoreScanPageTooLarge {
                requested: self.limit,
                max: RESTORE_SCAN_MAX_PAGE_SIZE,
            });
        }
        if let Some(cursor) = &self.cursor {
            cursor.validate_for_scope(&self.scope)?;
        }
        Ok(())
    }
}

impl Default for RestoreScanRequest {
    fn default() -> Self {
        Self::all(RESTORE_SCAN_DEFAULT_PAGE_SIZE)
    }
}

/// Pagination/evidence profile for a restore page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestoreScanCursorProfile {
    /// Compatibility-only numeric offsets used by deterministic local fakes.
    LegacyCompatibility,
    /// Confidential, authenticated, snapshot-bound durable seek cursors.
    DurableOpaqueV1,
}

/// One page of a backend restore scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreScanPage {
    /// Live records returned in this page.
    pub records: Vec<StoredSessionRecord>,
    /// Number of records returned in this page.
    pub loaded_count: usize,
    /// Records examined and excluded by the supplied scope while building
    /// this page. Backends that push the complete scope into their storage
    /// query report zero rather than running an unbounded global count.
    pub excluded_count: usize,
    /// Cursor for the next page, or `None` when the issuing backend reports
    /// the scan complete.
    pub next_cursor: Option<RestoreScanCursor>,
    /// Cursor/evidence profile used to build this page.
    pub cursor_profile: RestoreScanCursorProfile,
    /// Whether the issuing backend reports that this page completed the scan.
    pub complete: bool,
}

impl RestoreScanPage {
    /// Build a page from records and pagination metadata.
    pub fn new(
        records: Vec<StoredSessionRecord>,
        excluded_count: usize,
        next_cursor: Option<RestoreScanCursor>,
    ) -> Self {
        let loaded_count = records.len();
        let complete = next_cursor.is_none();
        Self {
            records,
            loaded_count,
            excluded_count,
            next_cursor,
            cursor_profile: RestoreScanCursorProfile::LegacyCompatibility,
            complete,
        }
    }

    /// Build a page backed by durable opaque cursor authority.
    pub(crate) fn new_durable(
        records: Vec<StoredSessionRecord>,
        excluded_count: usize,
        next_cursor: Option<RestoreScanCursor>,
    ) -> Self {
        let mut page = Self::new(records, excluded_count, next_cursor);
        page.cursor_profile = RestoreScanCursorProfile::DurableOpaqueV1;
        page
    }

    /// Header-only restore summary for this page.
    pub fn record_summary(&self) -> RestoreRecordSummary {
        RestoreRecordSummary::from_records(&self.records, self.excluded_count)
    }

    /// Logical memory retained by this page's records, metadata, payloads,
    /// and raw continuation cursor.
    pub fn retained_bytes(&self) -> Result<usize, StoreError> {
        restore_page_retained_bytes(&self.records, self.next_cursor.as_ref())
    }

    /// Validate this page against the request that produced it.
    ///
    /// Network adapters must call this on untrusted peer responses before
    /// exposing records to a compatibility consumer. This validates bounds,
    /// ordering, scope, cursor shape, and claimed progress only. It cannot
    /// prove that an authenticated server did not omit a record or falsely
    /// report a terminal page. Production restore completeness comes from the
    /// local Openraft-applied state after a linearizable barrier.
    pub fn validate_for_request(&self, request: &RestoreScanRequest) -> Result<(), StoreError> {
        request.validate()?;

        if self.records.len() > request.limit {
            return Err(StoreError::InvalidRestoreScanResponse(
                "restore scan returned more records than requested".to_string(),
            ));
        }
        let payload_bytes = self.records.iter().try_fold(0_usize, |total, record| {
            total.checked_add(record.payload.len()).ok_or_else(|| {
                StoreError::InvalidRestoreScanResponse(
                    "restore scan payload byte count overflowed".to_string(),
                )
            })
        })?;
        if payload_bytes > RESTORE_SCAN_MAX_PAGE_PAYLOAD_BYTES {
            return Err(StoreError::InvalidRestoreScanResponse(
                "restore scan exceeded the page payload-byte limit".to_string(),
            ));
        }
        if self
            .records
            .iter()
            .any(|record| record.key.stable_id.len() > RESTORE_SCAN_CURSOR_STABLE_ID_BYTES)
        {
            return Err(StoreError::InvalidRestoreScanResponse(
                "restore scan record key exceeds the local consensus ceiling".to_string(),
            ));
        }
        if self.retained_bytes().map_err(|_| {
            StoreError::InvalidRestoreScanResponse(
                "restore scan retained-byte count overflowed".to_string(),
            )
        })? > RESTORE_SCAN_MAX_PAGE_RETAINED_BYTES
        {
            return Err(StoreError::InvalidRestoreScanResponse(
                "restore scan exceeded the retained-page byte limit".to_string(),
            ));
        }
        if self.loaded_count != self.records.len() {
            return Err(StoreError::InvalidRestoreScanResponse(
                "restore scan loaded count does not match the record count".to_string(),
            ));
        }
        if self.complete != self.next_cursor.is_none() {
            return Err(StoreError::InvalidRestoreScanResponse(
                "restore scan completion flag and next cursor disagree".to_string(),
            ));
        }
        match self.cursor_profile {
            RestoreScanCursorProfile::LegacyCompatibility => {
                if request
                    .cursor
                    .as_ref()
                    .is_some_and(|cursor| !cursor.is_legacy())
                    || self
                        .next_cursor
                        .as_ref()
                        .is_some_and(|cursor| !cursor.is_legacy())
                {
                    return Err(StoreError::InvalidRestoreScanResponse(
                        "legacy restore page mixed cursor profiles".to_string(),
                    ));
                }
            }
            RestoreScanCursorProfile::DurableOpaqueV1 => {
                if request
                    .cursor
                    .as_ref()
                    .is_some_and(|cursor| cursor.is_legacy())
                    || self
                        .next_cursor
                        .as_ref()
                        .is_some_and(|cursor| cursor.is_legacy())
                {
                    return Err(StoreError::InvalidRestoreScanResponse(
                        "durable restore page mixed cursor profiles".to_string(),
                    ));
                }
            }
        }
        if self
            .records
            .iter()
            .any(|record| !request.scope.matches_record(record))
        {
            return Err(StoreError::InvalidRestoreScanResponse(
                "restore scan returned a record outside the requested scope".to_string(),
            ));
        }

        for pair in self.records.windows(2) {
            if pair[0].key == pair[1].key {
                return Err(StoreError::InvalidRestoreScanResponse(
                    "restore scan returned a duplicate session key".to_string(),
                ));
            }
            if compare_restore_records(&pair[0], &pair[1]).is_ge() {
                return Err(StoreError::InvalidRestoreScanResponse(
                    "restore scan records are not in deterministic order".to_string(),
                ));
            }
        }

        let examined_records = self
            .records
            .len()
            .checked_add(self.excluded_count)
            .ok_or_else(|| {
                StoreError::InvalidRestoreScanResponse(
                    "restore scan examined-row count overflowed".to_string(),
                )
            })?;
        if examined_records > RESTORE_SCAN_MAX_EXAMINED_ROWS_PER_PAGE {
            return Err(StoreError::InvalidRestoreScanResponse(
                "restore scan exceeded the examined-row page limit".to_string(),
            ));
        }

        if let Some(next_cursor) = &self.next_cursor {
            if examined_records == 0 {
                return Err(StoreError::InvalidRestoreScanResponse(
                    "incomplete restore scan page made no progress".to_string(),
                ));
            }
            next_cursor
                .validate_for_scope(&request.scope)
                .map_err(|_| {
                    StoreError::InvalidRestoreScanResponse(
                        "restore scan cursor is malformed or belongs to another scope".to_string(),
                    )
                })?;
            let previous_position = match request.cursor.as_ref() {
                Some(cursor) => cursor.examined_position().ok_or_else(|| {
                    StoreError::InvalidRestoreScanResponse(
                        "restore scan request cursor position is malformed".to_string(),
                    )
                })?,
                None => 0,
            };
            let examined_records = u64::try_from(examined_records).map_err(|_| {
                StoreError::InvalidRestoreScanResponse(
                    "restore scan examined-row position is not representable".to_string(),
                )
            })?;
            let expected_position =
                previous_position
                    .checked_add(examined_records)
                    .ok_or_else(|| {
                        StoreError::InvalidRestoreScanResponse(
                            "restore scan cursor position overflowed".to_string(),
                        )
                    })?;
            if next_cursor.examined_position() != Some(expected_position) {
                return Err(StoreError::InvalidRestoreScanResponse(
                    "restore scan cursor did not advance by the examined-row count".to_string(),
                ));
            }
            if next_cursor.is_legacy() && (self.records.is_empty() || self.excluded_count != 0) {
                return Err(StoreError::InvalidRestoreScanResponse(
                    "legacy restore page lacks bounded progress evidence".to_string(),
                ));
            }
        }

        Ok(())
    }
}

pub(crate) fn restore_record_retained_bytes(
    record: &StoredSessionRecord,
) -> Result<usize, StoreError> {
    restore_record_retained_bytes_from_lengths(
        record.key.tenant.as_str().len(),
        record.key.nf_kind.as_str().len(),
        record.key.key_type.as_str().len(),
        record.key.stable_id.len(),
        record.owner.as_str().len(),
        record.state_type.as_str().len(),
        record.payload.len(),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn restore_record_retained_bytes_from_lengths(
    tenant_bytes: usize,
    nf_kind_bytes: usize,
    key_type_bytes: usize,
    stable_id_bytes: usize,
    owner_bytes: usize,
    state_type_bytes: usize,
    payload_bytes: usize,
) -> Result<usize, StoreError> {
    [
        std::mem::size_of::<StoredSessionRecord>(),
        tenant_bytes,
        nf_kind_bytes,
        key_type_bytes,
        stable_id_bytes,
        owner_bytes,
        state_type_bytes,
        payload_bytes,
    ]
    .into_iter()
    .try_fold(0_usize, |total, value| {
        total
            .checked_add(value)
            .ok_or(StoreError::RestoreScanWorkBudgetExceeded)
    })
}

pub(crate) fn restore_page_retained_bytes(
    records: &[StoredSessionRecord],
    next_cursor: Option<&RestoreScanCursor>,
) -> Result<usize, StoreError> {
    let records_bytes = records.iter().try_fold(0_usize, |total, record| {
        total
            .checked_add(restore_record_retained_bytes(record)?)
            .ok_or(StoreError::RestoreScanWorkBudgetExceeded)
    })?;
    std::mem::size_of::<RestoreScanPage>()
        .checked_add(records_bytes)
        .and_then(|total| {
            next_cursor.map_or(Some(total), |cursor| {
                total.checked_add(cursor.retained_token_bytes())
            })
        })
        .ok_or(StoreError::RestoreScanWorkBudgetExceeded)
}

/// Deterministic ordering shared by restore-scan backends.
pub(crate) fn compare_restore_records(
    left: &StoredSessionRecord,
    right: &StoredSessionRecord,
) -> std::cmp::Ordering {
    left.key
        .tenant
        .as_str()
        .cmp(right.key.tenant.as_str())
        .then_with(|| left.key.nf_kind.as_str().cmp(right.key.nf_kind.as_str()))
        .then_with(|| left.key.key_type.cmp(&right.key.key_type))
        .then_with(|| {
            left.key
                .stable_id
                .as_ref()
                .cmp(right.key.stable_id.as_ref())
        })
        .then_with(|| left.state_class.cmp(&right.state_class))
        .then_with(|| left.state_type.cmp(&right.state_type))
        .then_with(|| left.owner.cmp(&right.owner))
        .then_with(|| left.generation.cmp(&right.generation))
}

/// Generic restore progress stage for startup and failover evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestoreStage {
    /// Connection to the session-store substrate.
    SessionStoreConnect,
    /// Ownership or lease validation before restore can proceed.
    Ownership,
    /// Durable record enumeration and load.
    RecordLoad,
    /// Generation and fence validation for loaded records.
    GenerationFenceValidation,
    /// Dataplane reinstall or replay of restored state.
    DataplaneReinstall,
    /// Peer health or degraded-mode classification.
    PeerDegradedClassification,
}

/// Machine-readable restore block reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestoreBlockReasonCode {
    /// The session store could not be reached or authenticated.
    SessionStoreUnavailable,
    /// Current ownership could not be proven.
    OwnershipConflict,
    /// A stale owner/fence was rejected during restore.
    StaleOwnerRejected,
    /// Record enumeration or header load failed.
    RecordLoadFailed,
    /// A loaded record failed generation or fence validation.
    GenerationFenceInvalid,
    /// Dataplane reinstall has not completed yet.
    DataplaneReinstallPending,
    /// Dataplane reinstall failed and traffic must stay blocked.
    DataplaneReinstallFailed,
    /// A peer is degraded and restore must not claim full readiness.
    PeerDegraded,
}

/// Redaction-safe reason a restore workflow is blocked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreBlockReason {
    /// Restore stage that produced the block.
    pub stage: RestoreStage,
    /// Machine-readable reason code.
    pub code: RestoreBlockReasonCode,
    /// Redaction-safe operator/evidence message.
    pub message: String,
    /// Whether this block prevents traffic readiness claims.
    pub traffic_blocking: bool,
}

impl RestoreBlockReason {
    /// Build a restore block reason and redact message text for evidence.
    pub fn new(
        stage: RestoreStage,
        code: RestoreBlockReasonCode,
        message: impl AsRef<str>,
        traffic_blocking: bool,
    ) -> Self {
        Self {
            stage,
            code,
            message: redact_restore_message(message.as_ref()),
            traffic_blocking,
        }
    }

    /// Session-store connection block.
    pub fn session_store_connect(message: impl AsRef<str>) -> Self {
        Self::new(
            RestoreStage::SessionStoreConnect,
            RestoreBlockReasonCode::SessionStoreUnavailable,
            message,
            true,
        )
    }

    /// Ownership conflict block.
    pub fn ownership_conflict(message: impl AsRef<str>) -> Self {
        Self::new(
            RestoreStage::Ownership,
            RestoreBlockReasonCode::OwnershipConflict,
            message,
            true,
        )
    }

    /// Stale owner/fence rejection block.
    pub fn stale_owner_rejected(message: impl AsRef<str>) -> Self {
        Self::new(
            RestoreStage::Ownership,
            RestoreBlockReasonCode::StaleOwnerRejected,
            message,
            true,
        )
    }

    /// Record-load block.
    pub fn record_load(message: impl AsRef<str>) -> Self {
        Self::new(
            RestoreStage::RecordLoad,
            RestoreBlockReasonCode::RecordLoadFailed,
            message,
            true,
        )
    }

    /// Generation/fence validation block.
    pub fn generation_fence_validation(message: impl AsRef<str>) -> Self {
        Self::new(
            RestoreStage::GenerationFenceValidation,
            RestoreBlockReasonCode::GenerationFenceInvalid,
            message,
            true,
        )
    }

    /// Dataplane reinstall pending block.
    pub fn dataplane_reinstall_pending(message: impl AsRef<str>) -> Self {
        Self::new(
            RestoreStage::DataplaneReinstall,
            RestoreBlockReasonCode::DataplaneReinstallPending,
            message,
            true,
        )
    }

    /// Dataplane reinstall failure block.
    pub fn dataplane_reinstall_failed(message: impl AsRef<str>) -> Self {
        Self::new(
            RestoreStage::DataplaneReinstall,
            RestoreBlockReasonCode::DataplaneReinstallFailed,
            message,
            true,
        )
    }

    /// Peer degraded classification block.
    pub fn peer_degraded(message: impl AsRef<str>, traffic_blocking: bool) -> Self {
        Self::new(
            RestoreStage::PeerDegradedClassification,
            RestoreBlockReasonCode::PeerDegraded,
            message,
            traffic_blocking,
        )
    }

    /// Whether this reason prevents traffic readiness claims.
    pub const fn blocks_traffic(&self) -> bool {
        self.traffic_blocking
    }
}

/// Header-only summary of a stored session record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRecordHeaderSummary {
    /// SHA-256 digest of the composite session key.
    pub key_digest: String,
    /// Tenant identifier from the key.
    pub tenant: String,
    /// Network-function kind from the key.
    pub nf_kind: String,
    /// Session key type from the key.
    pub key_type: String,
    /// Record state class.
    pub state_class: StateClass,
    /// Record state type.
    pub state_type: String,
    /// Record generation.
    pub generation: u64,
    /// Record fence.
    pub fence: u64,
    /// Owner recorded on the stored header.
    pub owner: String,
    /// Whether the record has an expiry deadline.
    pub expires: bool,
    /// Whether this record is an authoritative session record.
    pub authoritative: bool,
}

impl StoredRecordHeaderSummary {
    /// Build a redaction-safe header summary from a stored record.
    pub fn from_record(record: &StoredSessionRecord) -> Self {
        Self {
            key_digest: encode_lower(&record.key.digest()),
            tenant: record.key.tenant.to_string(),
            nf_kind: record.key.nf_kind.to_string(),
            key_type: record.key.key_type.to_string(),
            state_class: record.state_class,
            state_type: record.state_type.to_string(),
            generation: record.generation.get(),
            fence: record.fence.get(),
            owner: record.owner.to_string(),
            expires: record.expires_at.is_some(),
            authoritative: record.state_class == StateClass::AuthoritativeSession,
        }
    }
}

/// Owner/fence aggregation for restore evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerFenceMetadata {
    /// Owner represented by this aggregate.
    pub owner: String,
    /// Number of loaded records for this owner.
    pub record_count: usize,
    /// Number of authoritative records for this owner.
    pub authoritative_count: usize,
    /// Highest generation observed for this owner.
    pub highest_generation: u64,
    /// Highest fence observed for this owner.
    pub highest_fence: u64,
}

/// Summary of record headers loaded during restore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreRecordSummary {
    /// Number of records loaded from the session store.
    pub loaded_count: usize,
    /// Number of loaded authoritative records.
    pub authoritative_count: usize,
    /// Number of records excluded by caller restore policy.
    pub excluded_count: usize,
    /// Highest generation observed across loaded records.
    pub highest_generation: Option<u64>,
    /// Highest fence observed across loaded records.
    pub highest_fence: Option<u64>,
    /// Per-owner generation/fence metadata.
    pub owner_fence_metadata: Vec<OwnerFenceMetadata>,
    /// Redaction-safe stored-record header summaries.
    pub headers: Vec<StoredRecordHeaderSummary>,
}

impl RestoreRecordSummary {
    /// Build a restore summary from already loaded stored records.
    pub fn from_records(records: &[StoredSessionRecord], excluded_count: usize) -> Self {
        summarize_restore_records(records, excluded_count)
    }
}

/// Summarize loaded stored-record headers for restore evidence.
pub fn summarize_restore_records(
    records: &[StoredSessionRecord],
    excluded_count: usize,
) -> RestoreRecordSummary {
    let mut headers = records
        .iter()
        .map(StoredRecordHeaderSummary::from_record)
        .collect::<Vec<_>>();
    headers.sort_by(|left, right| {
        left.owner
            .cmp(&right.owner)
            .then_with(|| left.key_digest.cmp(&right.key_digest))
            .then_with(|| left.state_type.cmp(&right.state_type))
    });

    let loaded_count = headers.len();
    let authoritative_count = headers.iter().filter(|header| header.authoritative).count();
    let highest_generation = headers.iter().map(|header| header.generation).max();
    let highest_fence = headers.iter().map(|header| header.fence).max();

    let mut owner_map = BTreeMap::<String, OwnerFenceMetadata>::new();
    for header in &headers {
        let metadata =
            owner_map
                .entry(header.owner.clone())
                .or_insert_with(|| OwnerFenceMetadata {
                    owner: header.owner.clone(),
                    record_count: 0,
                    authoritative_count: 0,
                    highest_generation: 0,
                    highest_fence: 0,
                });
        metadata.record_count += 1;
        if header.authoritative {
            metadata.authoritative_count += 1;
        }
        metadata.highest_generation = metadata.highest_generation.max(header.generation);
        metadata.highest_fence = metadata.highest_fence.max(header.fence);
    }

    RestoreRecordSummary {
        loaded_count,
        authoritative_count,
        excluded_count,
        highest_generation,
        highest_fence,
        owner_fence_metadata: owner_map.into_values().collect(),
        headers,
    }
}

fn redact_restore_message(message: &str) -> String {
    let mut summary = RedactionSummary::default();
    redact_text(message, &mut summary)
}

#[cfg(test)]
mod cursor_tests {
    use super::*;
    use bytes::Bytes;
    use proptest::prelude::*;

    fn test_cursor() -> (RestoreScanCursor, [u8; 32], RestoreScanScope) {
        let authentication_key = [0x5a; 32];
        let scope = RestoreScanScope {
            tenant: Some(TenantId::from_static("tenant-secret")),
            ..RestoreScanScope::all()
        };
        let seek_key = SessionKey {
            tenant: TenantId::from_static("tenant-secret"),
            nf_kind: NetworkFunctionKind::upf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"subscriber-derived-secret")
                .try_into()
                .expect("valid stable ID"),
        };
        let snapshot_time = Timestamp::from_offset_datetime(
            time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(987_654),
        );
        let cursor = RestoreScanCursor::durable(
            &authentication_key,
            [0x33; 16],
            42,
            snapshot_time,
            &scope,
            &seek_key,
            4_096,
        )
        .expect("build test cursor");
        (cursor, authentication_key, scope)
    }

    proptest! {
        #[test]
        fn every_single_bit_cursor_edit_fails_authentication(
            candidate_bit in 0_usize..4_096
        ) {
            let (mut cursor, authentication_key, scope) = test_cursor();
            let bit = candidate_bit % (cursor.token.len() * 8);
            Arc::make_mut(&mut cursor.token)[bit / 8] ^= 1_u8 << (bit % 8);
            prop_assert_eq!(
                cursor.authenticated_parts(&scope, &authentication_key),
                Err(StoreError::RestoreScanCursorStale)
            );
        }
    }

    #[test]
    fn cursor_wire_and_debug_are_bounded_opaque_and_round_trip() {
        let (cursor, authentication_key, scope) = test_cursor();
        let encoded = serde_json::to_string(&cursor).expect("encode cursor");
        assert!(encoded.len() <= RESTORE_SCAN_CURSOR_MAX_HEX_CHARS + 2);
        assert!(!encoded.contains("tenant-secret"));
        assert!(!encoded.contains("subscriber-derived-secret"));
        assert!(!encoded.contains("1970"));
        assert!(!format!("{cursor:?}").contains("tenant-secret"));

        let decoded: RestoreScanCursor = serde_json::from_str(&encoded).expect("decode cursor");
        assert_eq!(decoded, cursor);
        decoded
            .authenticated_parts(&scope, &authentication_key)
            .expect("round-tripped cursor authenticates");
    }

    #[test]
    fn durable_cursor_encoding_is_canonical_and_progress_is_exact() {
        let (_, authentication_key, scope) = test_cursor();
        let seek_key = SessionKey {
            tenant: TenantId::from_static("tenant-secret"),
            nf_kind: NetworkFunctionKind::upf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"subscriber-derived-secret")
                .try_into()
                .expect("valid stable ID"),
        };
        let snapshot_time = Timestamp::from_offset_datetime(
            time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(987_654),
        );
        let make_cursor = |examined_position| {
            RestoreScanCursor::durable(
                &authentication_key,
                [0x33; 16],
                42,
                snapshot_time,
                &scope,
                &seek_key,
                examined_position,
            )
            .expect("build deterministic cursor")
        };
        let request_cursor = make_cursor(4_096);
        assert_eq!(request_cursor, make_cursor(4_096));

        let request = RestoreScanRequest {
            scope: scope.clone(),
            cursor: Some(request_cursor),
            limit: 1,
        };
        RestoreScanPage::new_durable(Vec::new(), 1, Some(make_cursor(4_097)))
            .validate_for_request(&request)
            .expect("exact durable progress");
        for invalid in [make_cursor(4_096), make_cursor(4_095), make_cursor(4_098)] {
            assert!(matches!(
                RestoreScanPage::new_durable(Vec::new(), 1, Some(invalid))
                    .validate_for_request(&request),
                Err(StoreError::InvalidRestoreScanResponse(_))
            ));
        }
    }

    #[test]
    fn cursor_represents_consensus_bounded_stable_ids() {
        let authentication_key = [0x5a; 32];
        let scope = RestoreScanScope::all();
        let seek_key = SessionKey {
            tenant: TenantId::from_static("tenant-a"),
            nf_kind: NetworkFunctionKind::upf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from(vec![0x6a; RESTORE_SCAN_CURSOR_STABLE_ID_BYTES])
                .try_into()
                .expect("maximum stable ID"),
        };
        let snapshot_time = Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH);
        let cursor = RestoreScanCursor::durable(
            &authentication_key,
            [0x33; 16],
            42,
            snapshot_time,
            &scope,
            &seek_key,
            1,
        )
        .expect("consensus-bounded key fits the cursor");
        assert!(cursor.token.len() <= RESTORE_SCAN_CURSOR_MAX_DURABLE_BYTES);
        cursor
            .authenticated_parts(&scope, &authentication_key)
            .expect("maximum cursor authenticates");

        assert_eq!(
            crate::StableId::new(Bytes::from(vec![
                0x6a;
                RESTORE_SCAN_CURSOR_STABLE_ID_BYTES + 1
            ])),
            Err(crate::StableIdError::InvalidWidth)
        );
    }

    #[test]
    fn cursor_decoder_rejects_hostile_token_shapes() {
        let (cursor, _, _) = test_cursor();
        let encoded_cursor = cursor.encode_token();
        let unsupported_maximum =
            format!("02{}", "0".repeat(RESTORE_SCAN_CURSOR_MAX_HEX_CHARS - 2));
        for token in [
            String::new(),
            "00".to_string(),
            "0".repeat(RESTORE_SCAN_CURSOR_LEGACY_BYTES * 2 + 1),
            "g".repeat(encoded_cursor.len()),
            "A".repeat(encoded_cursor.len()),
            "0".repeat(RESTORE_SCAN_CURSOR_MAX_HEX_CHARS + 2),
            unsupported_maximum,
        ] {
            let encoded = serde_json::to_string(&token).expect("encode hostile token");
            assert!(serde_json::from_str::<RestoreScanCursor>(&encoded).is_err());
        }
    }
}
