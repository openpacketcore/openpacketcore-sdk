//! The destination-local cursor identity belongs to the complete native base
//! image. It is absent from contexts, deltas, selectors and serialized proofs.
//! A cold read returns only this choice; the original pinned snapshot install
//! must independently establish authority before the catalog is admitted.

use super::*;
use crate::sqlite::ops::RestoreScanIncarnation;
use serde::de::{self, Visitor};
use std::fmt;

#[derive(PartialEq, Eq)]
pub(super) struct BaseRestore(Zeroizing<[u8; 48]>);

impl BaseRestore {
    pub(super) fn from_origin(origin: &NativeSnapshotAuthority) -> Self {
        Self(origin.incarnation().native_image())
    }

    pub(super) fn incarnation(&self) -> io::Result<RestoreScanIncarnation> {
        RestoreScanIncarnation::from_native_image(self.0.as_slice())
            .map_err(|_| invalid("native base restore identity invalid"))
    }

    pub(super) fn require_origin(
        value: Option<&Self>,
        origin: Option<&NativeSnapshotAuthority>,
        format: Format,
    ) -> io::Result<()> {
        match (value, origin) {
            (None, None) => Ok(()),
            (Some(value), Some(origin))
                if format == Format::V4 && value.0 == origin.incarnation().native_image() =>
            {
                Ok(())
            }
            _ => Err(invalid(
                "native base restore identity differs from original installation",
            )),
        }
    }
}

impl Serialize for BaseRestore {
    fn serialize<S: serde::Serializer>(&self, encoder: S) -> Result<S::Ok, S::Error> {
        self.0.as_slice().serialize(encoder)
    }
}

impl<'de> Deserialize<'de> for BaseRestore {
    fn deserialize<D: de::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fixed;
        impl<'de> Visitor<'de> for Fixed {
            type Value = BaseRestore;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a fixed native restore identity")
            }
            fn visit_seq<A: de::SeqAccess<'de>>(
                self,
                mut input: A,
            ) -> Result<Self::Value, A::Error> {
                let mut bytes = Zeroizing::new([0; 48]);
                for byte in bytes.iter_mut() {
                    *byte = input
                        .next_element()?
                        .ok_or_else(|| de::Error::custom("native restore identity is short"))?;
                }
                if input.next_element::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom("native restore identity is long"));
                }
                let value = BaseRestore(bytes);
                value
                    .incarnation()
                    .map_err(|_| de::Error::custom("native restore identity invalid"))?;
                Ok(value)
            }
        }
        decoder.deserialize_seq(Fixed)
    }
}

impl Catalog {
    /// Read the local cursor choice from the fully checksum-verified selected
    /// prefix. This performs no repair and does not return install authority.
    /// The caller must run the original pinned installer with this choice and
    /// then call open_with_origin for complete independent row admission.
    pub(crate) fn read_native_incarnation(
        path: &std::path::Path,
        expected: PrefixIdentity,
        maximum: u64,
        identity: SessionConsensusIdentity,
        members: &BTreeSet<SessionConsensusNodeId>,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<RestoreScanIncarnation> {
        let mut choice = None;
        let owner = VerifiedAppendOwner::open(path, expected, maximum, check, |reader| {
            if Format::read(reader, true)? != Format::V4 {
                return Err(invalid(
                    "native restore identity requires a complete V4 base",
                ));
            }
            let loaded = header::base(reader)?;
            let base = &loaded.value;
            if base.binding != expected.binding
                || base.file_epoch != expected.file_epoch
                || base.block_bytes != expected.block_bytes
                || base.checkpoint_epoch > expected.checkpoint_epoch
                || base.operation_sequence > expected.operation_sequence
                || base.context.business.identity != identity
                || &base.context.business.members != members
            {
                return Err(invalid(
                    "native restore base differs from selected local identity",
                ));
            }
            choice = Some(
                base.native_restore
                    .as_ref()
                    .ok_or_else(|| {
                        invalid("native installed base lacks its local restore identity")
                    })?
                    .incarnation()?,
            );
            drop(loaded);
            let mut bytes = Zeroizing::new([0; 4096]);
            loop {
                check()?;
                if reader.read(bytes.as_mut_slice())? == 0 {
                    break;
                }
            }
            Ok(())
        })?;
        drop(owner);
        check()?;
        choice.ok_or_else(|| invalid("native installed restore identity absent"))
    }
}
