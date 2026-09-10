//! Explicit OPCNAT01/02 key layout. Those discriminators retain their original
//! LeaseGuard/active tuple; the new lease columns belong only to OPCNAT03 and
//! OPCNJ002. No legacy marker is interpreted using a changed postcard layout.

use super::*;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Lease {
    guard: LeaseGuard,
    active: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Key {
    record: Option<StoredSessionRecord>,
    lease: Option<Lease>,
    fence: u64,
    reserved: bool,
}

impl Key {
    pub(super) fn into_current(self, key: &SessionKey) -> io::Result<NativeKeyState> {
        let lease = self
            .lease
            .map(|old| {
                old.guard
                    .validate_profile()
                    .map_err(|_| invalid("native legacy lease guard invalid"))?;
                if old.guard.key() != key {
                    return Err(invalid("native legacy lease key differs"));
                }
                let mut row = NativeLease::from_guard(&old.guard)
                    .map_err(|_| invalid("native legacy lease expiry invalid"))?;
                row.active = old.active;
                Ok(row)
            })
            .transpose()?;
        Ok(NativeKeyState {
            record: self.record,
            lease,
            fence: self.fence,
            reserved: self.reserved,
        })
    }

    pub(super) fn from_current(key: &SessionKey, row: &NativeKeyState) -> io::Result<Self> {
        let lease = row
            .lease
            .as_ref()
            .map(|value| {
                let acquired_at = value.acquired_at.ok_or_else(|| {
                    invalid("native legacy writer cannot represent a nullable lease acquisition")
                })?;
                if value.expires_at_unix_ms
                    != crate::sqlite::ops::timestamp_unix_millis(value.guard_expires_at)
                        .map_err(|_| invalid("native legacy lease expiry invalid"))?
                {
                    return Err(invalid(
                        "native legacy writer cannot represent a distinct released expiry",
                    ));
                }
                Ok(Lease {
                    guard: LeaseGuard::new(
                        key.clone(),
                        value.owner.clone(),
                        value.fence,
                        acquired_at,
                        value.guard_expires_at,
                        value.credential_id,
                    ),
                    active: value.active,
                })
            })
            .transpose()?;
        Ok(Self {
            record: row.record.clone(),
            lease,
            fence: row.fence,
            reserved: row.reserved,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_image_v3_preserves_nullable_and_released_lease_columns_with_distinct_discriminator() {
        use crate::consensus::native::changes::tests::fixture;
        for nullable in [false, true] {
            let (mut storage, _, _) = fixture();
            let key = storage.business.keys.keys().next().unwrap().clone();
            let mut row = (**storage.business.keys.get(&key).unwrap()).clone();
            let lease = row.lease.as_mut().unwrap();
            lease.active = false;
            lease.guard_expires_at = lease.guard_expires_at.add_seconds(-10).unwrap();
            if nullable {
                lease.acquired_at = None;
            }
            let expected = postcard::to_allocvec(&row).unwrap();
            storage
                .business
                .keys
                .insert(key.clone(), SharedRow::new(row));
            storage.business.admit_business().unwrap();
            let mut bytes = Vec::new();
            storage
                .write_legacy_v3_image_for_test(&mut bytes, [0x94; 32], 7)
                .unwrap();
            assert_eq!(&bytes[..8], b"OPCNAT03");
            let decoded = NativeStorage::read_image(
                &mut bytes.as_slice(),
                [0x94; 32],
                7,
                storage.business.identity,
            )
            .unwrap();
            assert_eq!(
                postcard::to_allocvec(&**decoded.business.keys.get(&key).unwrap()).unwrap(),
                expected
            );
            assert!(
                storage
                    .write_legacy_v2_image_for_test(&mut Vec::new(), [0x94; 32], 7)
                    .is_err(),
                "old layout cannot silently discard lease columns"
            );
            for magic in [b"OPCNAT01", b"OPCNAT02"] {
                let mut mislabeled = bytes.clone();
                mislabeled[..8].copy_from_slice(magic);
                assert!(NativeStorage::read_image(
                    &mut mislabeled.as_slice(),
                    [0x94; 32],
                    7,
                    storage.business.identity
                )
                .is_err());
            }
        }
    }
}
