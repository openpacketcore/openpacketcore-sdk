//! Canonical immutable identity manifest for one root-cgroup fence generation.

use std::{collections::BTreeSet, num::NonZeroU64};

use crate::root_inventory::RootInventory;

pub(crate) const INSTALL_MANIFEST_BYTES: usize = 2_048;
pub(crate) const INSTALL_PROGRAM_COUNT: usize = 3;
pub(crate) const INSTALL_MAP_COUNT: usize = 7;
pub(crate) const MAX_PROGRAM_MAPS: usize = INSTALL_MAP_COUNT;
const MAX_ROOT_PROGRAMS: usize = 64;
const OBJECT_NAME_BYTES: usize = 16;
const MANIFEST_MAGIC: [u8; 8] = *b"OPCFM001";
const MANIFEST_VERSION: u32 = 1;
const BPF_F_ALLOW_MULTI: u32 = 1 << 1;
const ENCODED_FIELDS_BYTES: usize = 1_112;

/// Stable 128-bit nonce naming one complete pin generation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct InstallGenerationId([u8; 16]);

impl InstallGenerationId {
    pub(crate) fn new(bytes: [u8; 16]) -> Result<Self, ManifestError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(ManifestError::Invalid);
        }
        Ok(Self(bytes))
    }

    pub(crate) const fn bytes(self) -> [u8; 16] {
        self.0
    }
}

impl std::fmt::Debug for InstallGenerationId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("InstallGenerationId(<redacted>)")
    }
}

/// Kernel identity of one program pinned in a complete generation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ManifestProgram {
    pub(crate) name: KernelObjectName,
    pub(crate) id: u32,
    pub(crate) program_type: u32,
    pub(crate) tag: u64,
    pub(crate) map_ids: [u32; MAX_PROGRAM_MAPS],
    pub(crate) map_count: u32,
}

/// Kernel identity and schema of one map pinned in a complete generation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ManifestMap {
    pub(crate) name: KernelObjectName,
    pub(crate) id: u32,
    pub(crate) map_type: u32,
    pub(crate) key_size: u32,
    pub(crate) value_size: u32,
    pub(crate) max_entries: u32,
    pub(crate) map_flags: u32,
}

/// Canonical NUL-padded Linux BPF object name.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct KernelObjectName([u8; OBJECT_NAME_BYTES]);

impl KernelObjectName {
    pub(crate) fn new(name: &str) -> Result<Self, ManifestError> {
        let bytes = name.as_bytes();
        if bytes.is_empty()
            || bytes.len() >= OBJECT_NAME_BYTES
            || bytes
                .iter()
                .any(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
        {
            return Err(ManifestError::Invalid);
        }
        let mut encoded = [0_u8; OBJECT_NAME_BYTES];
        encoded[..bytes.len()].copy_from_slice(bytes);
        Ok(Self(encoded))
    }

    fn from_encoded(encoded: [u8; OBJECT_NAME_BYTES]) -> Result<Self, ManifestError> {
        let first_zero = encoded
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(ManifestError::Invalid)?;
        if first_zero == 0
            || encoded[first_zero..].iter().any(|byte| *byte != 0)
            || encoded[..first_zero]
                .iter()
                .any(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
        {
            return Err(ManifestError::Invalid);
        }
        Ok(Self(encoded))
    }

    pub(crate) fn as_str(&self) -> &str {
        let length = self
            .0
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(OBJECT_NAME_BYTES);
        // Construction admits ASCII only.
        std::str::from_utf8(&self.0[..length]).unwrap_or("")
    }
}

impl std::fmt::Debug for KernelObjectName {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("KernelObjectName(<redacted>)")
    }
}

/// Immutable generation manifest encoded into one frozen BPF array map.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct InstallManifest {
    pub(crate) generation_id: InstallGenerationId,
    pub(crate) artifact_digest: [u8; 32],
    pub(crate) config_digest: [u8; 32],
    pub(crate) pre_revision: NonZeroU64,
    pub(crate) post_revision: NonZeroU64,
    pub(crate) pre_attach_flags: u32,
    pub(crate) post_attach_flags: u32,
    pub(crate) pre_program_ids: [u32; MAX_ROOT_PROGRAMS],
    pub(crate) pre_program_attach_flags: [u32; MAX_ROOT_PROGRAMS],
    pub(crate) pre_program_count: u32,
    pub(crate) programs: [ManifestProgram; INSTALL_PROGRAM_COUNT],
    pub(crate) maps: [ManifestMap; INSTALL_MAP_COUNT],
}

impl InstallManifest {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        generation_id: InstallGenerationId,
        artifact_digest: [u8; 32],
        config_digest: [u8; 32],
        before: &RootInventory,
        post_revision: NonZeroU64,
        programs: [ManifestProgram; INSTALL_PROGRAM_COUNT],
        maps: [ManifestMap; INSTALL_MAP_COUNT],
    ) -> Result<Self, ManifestError> {
        let pre_count =
            u32::try_from(before.program_ids().len()).map_err(|_| ManifestError::Invalid)?;
        let mut pre_program_ids = [0_u32; MAX_ROOT_PROGRAMS];
        let mut pre_program_attach_flags = [0_u32; MAX_ROOT_PROGRAMS];
        pre_program_ids[..before.program_ids().len()].copy_from_slice(before.program_ids());
        pre_program_attach_flags[..before.program_attach_flags().len()]
            .copy_from_slice(before.program_attach_flags());
        let manifest = Self {
            generation_id,
            artifact_digest,
            config_digest,
            pre_revision: before.revision(),
            post_revision,
            pre_attach_flags: before.attach_flags(),
            post_attach_flags: BPF_F_ALLOW_MULTI,
            pre_program_ids,
            pre_program_attach_flags,
            pre_program_count: pre_count,
            programs,
            maps,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub(crate) fn encode(&self) -> Result<[u8; INSTALL_MANIFEST_BYTES], ManifestError> {
        self.validate()?;
        let mut encoded = [0_u8; INSTALL_MANIFEST_BYTES];
        let mut writer = ManifestWriter::new(&mut encoded);
        writer.bytes(&MANIFEST_MAGIC)?;
        writer.u32(MANIFEST_VERSION)?;
        writer.bytes(&self.generation_id.bytes())?;
        writer.bytes(&self.artifact_digest)?;
        writer.bytes(&self.config_digest)?;
        writer.u64(self.pre_revision.get())?;
        writer.u64(self.post_revision.get())?;
        writer.u32(self.pre_attach_flags)?;
        writer.u32(self.post_attach_flags)?;
        writer.u32(self.pre_program_count)?;
        writer.u32(INSTALL_PROGRAM_COUNT as u32)?;
        writer.u32(INSTALL_MAP_COUNT as u32)?;
        for index in 0..MAX_ROOT_PROGRAMS {
            writer.u32(self.pre_program_ids[index])?;
            writer.u32(self.pre_program_attach_flags[index])?;
        }
        for program in &self.programs {
            writer.bytes(&program.name.0)?;
            writer.u32(program.id)?;
            writer.u32(program.program_type)?;
            writer.u64(program.tag)?;
            writer.u32(program.map_count)?;
            for map_id in program.map_ids {
                writer.u32(map_id)?;
            }
        }
        for map in &self.maps {
            writer.bytes(&map.name.0)?;
            writer.u32(map.id)?;
            writer.u32(map.map_type)?;
            writer.u32(map.key_size)?;
            writer.u32(map.value_size)?;
            writer.u32(map.max_entries)?;
            writer.u32(map.map_flags)?;
        }
        if writer.position() != ENCODED_FIELDS_BYTES {
            return Err(ManifestError::Invalid);
        }
        Ok(encoded)
    }

    pub(crate) fn decode(encoded: &[u8; INSTALL_MANIFEST_BYTES]) -> Result<Self, ManifestError> {
        let mut reader = ManifestReader::new(encoded);
        if reader.array::<8>()? != MANIFEST_MAGIC || reader.u32()? != MANIFEST_VERSION {
            return Err(ManifestError::Invalid);
        }
        let generation_id = InstallGenerationId::new(reader.array::<16>()?)?;
        let artifact_digest = reader.array::<32>()?;
        let config_digest = reader.array::<32>()?;
        let pre_revision = NonZeroU64::new(reader.u64()?).ok_or(ManifestError::Invalid)?;
        let post_revision = NonZeroU64::new(reader.u64()?).ok_or(ManifestError::Invalid)?;
        let pre_attach_flags = reader.u32()?;
        let post_attach_flags = reader.u32()?;
        let pre_program_count = reader.u32()?;
        if reader.u32()? != INSTALL_PROGRAM_COUNT as u32
            || reader.u32()? != INSTALL_MAP_COUNT as u32
        {
            return Err(ManifestError::Invalid);
        }
        let mut pre_program_ids = [0_u32; MAX_ROOT_PROGRAMS];
        let mut pre_program_attach_flags = [0_u32; MAX_ROOT_PROGRAMS];
        for index in 0..MAX_ROOT_PROGRAMS {
            pre_program_ids[index] = reader.u32()?;
            pre_program_attach_flags[index] = reader.u32()?;
        }
        let mut programs = [empty_program(); INSTALL_PROGRAM_COUNT];
        for program in &mut programs {
            program.name = KernelObjectName::from_encoded(reader.array::<OBJECT_NAME_BYTES>()?)?;
            program.id = reader.u32()?;
            program.program_type = reader.u32()?;
            program.tag = reader.u64()?;
            program.map_count = reader.u32()?;
            for map_id in &mut program.map_ids {
                *map_id = reader.u32()?;
            }
        }
        let mut maps = [empty_map(); INSTALL_MAP_COUNT];
        for map in &mut maps {
            map.name = KernelObjectName::from_encoded(reader.array::<OBJECT_NAME_BYTES>()?)?;
            map.id = reader.u32()?;
            map.map_type = reader.u32()?;
            map.key_size = reader.u32()?;
            map.value_size = reader.u32()?;
            map.max_entries = reader.u32()?;
            map.map_flags = reader.u32()?;
        }
        if reader.position() != ENCODED_FIELDS_BYTES
            || encoded[ENCODED_FIELDS_BYTES..]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(ManifestError::Invalid);
        }
        let manifest = Self {
            generation_id,
            artifact_digest,
            config_digest,
            pre_revision,
            post_revision,
            pre_attach_flags,
            post_attach_flags,
            pre_program_ids,
            pre_program_attach_flags,
            pre_program_count,
            programs,
            maps,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<(), ManifestError> {
        let pre_count =
            usize::try_from(self.pre_program_count).map_err(|_| ManifestError::Invalid)?;
        if self.artifact_digest.iter().all(|byte| *byte == 0)
            || self.config_digest.iter().all(|byte| *byte == 0)
            || pre_count >= MAX_ROOT_PROGRAMS
            || self.pre_program_ids[..pre_count].contains(&0)
            || self.pre_program_ids[pre_count..].iter().any(|id| *id != 0)
            || self.pre_program_attach_flags[pre_count..]
                .iter()
                .any(|flags| *flags != 0)
            || self.post_revision.get() != self.pre_revision.get().checked_add(1).unwrap_or(0)
            || self.post_attach_flags != BPF_F_ALLOW_MULTI
        {
            return Err(ManifestError::Invalid);
        }
        let expected_pre_flags = if pre_count == 0 { 0 } else { BPF_F_ALLOW_MULTI };
        if self.pre_attach_flags != expected_pre_flags
            || self.pre_program_attach_flags[..pre_count]
                .iter()
                .any(|flags| *flags != expected_pre_flags)
        {
            return Err(ManifestError::Invalid);
        }

        let mut program_ids = BTreeSet::new();
        let mut program_names = BTreeSet::new();
        let mut map_ids = BTreeSet::new();
        let mut map_names = BTreeSet::new();
        for map in &self.maps {
            if map.id == 0
                || map.map_type == 0
                || map.key_size == 0
                || map.value_size == 0
                || map.max_entries == 0
                || !map_ids.insert(map.id)
                || !map_names.insert(map.name)
            {
                return Err(ManifestError::Invalid);
            }
        }
        for program in &self.programs {
            let count = usize::try_from(program.map_count).map_err(|_| ManifestError::Invalid)?;
            if program.id == 0
                || program.program_type == 0
                || program.tag == 0
                || count == 0
                || count > MAX_PROGRAM_MAPS
                || program.map_ids[..count].contains(&0)
                || program.map_ids[count..].iter().any(|id| *id != 0)
                || program.map_ids[..count]
                    .iter()
                    .any(|map_id| !map_ids.contains(map_id))
                || !program_ids.insert(program.id)
                || !program_names.insert(program.name)
            {
                return Err(ManifestError::Invalid);
            }
        }
        if self.pre_program_ids[..pre_count].contains(&self.programs[0].id) {
            return Err(ManifestError::Invalid);
        }
        Ok(())
    }
}

impl std::fmt::Debug for InstallManifest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InstallManifest")
            .field("generation_present", &true)
            .field("program_count", &INSTALL_PROGRAM_COUNT)
            .field("map_count", &INSTALL_MAP_COUNT)
            .field("pre_program_count", &self.pre_program_count)
            .field("revisions_verified_nonzero", &true)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManifestError {
    Invalid,
}

const fn empty_name() -> KernelObjectName {
    KernelObjectName([0_u8; OBJECT_NAME_BYTES])
}

const fn empty_program() -> ManifestProgram {
    ManifestProgram {
        name: empty_name(),
        id: 0,
        program_type: 0,
        tag: 0,
        map_ids: [0_u32; MAX_PROGRAM_MAPS],
        map_count: 0,
    }
}

const fn empty_map() -> ManifestMap {
    ManifestMap {
        name: empty_name(),
        id: 0,
        map_type: 0,
        key_size: 0,
        value_size: 0,
        max_entries: 0,
        map_flags: 0,
    }
}

struct ManifestWriter<'a> {
    destination: &'a mut [u8],
    position: usize,
}

impl<'a> ManifestWriter<'a> {
    fn new(destination: &'a mut [u8]) -> Self {
        Self {
            destination,
            position: 0,
        }
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), ManifestError> {
        let end = self
            .position
            .checked_add(value.len())
            .ok_or(ManifestError::Invalid)?;
        let target = self
            .destination
            .get_mut(self.position..end)
            .ok_or(ManifestError::Invalid)?;
        target.copy_from_slice(value);
        self.position = end;
        Ok(())
    }

    fn u32(&mut self, value: u32) -> Result<(), ManifestError> {
        self.bytes(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), ManifestError> {
        self.bytes(&value.to_le_bytes())
    }

    const fn position(&self) -> usize {
        self.position
    }
}

struct ManifestReader<'a> {
    source: &'a [u8],
    position: usize,
}

impl<'a> ManifestReader<'a> {
    const fn new(source: &'a [u8]) -> Self {
        Self {
            source,
            position: 0,
        }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ManifestError> {
        let end = self.position.checked_add(N).ok_or(ManifestError::Invalid)?;
        let source = self
            .source
            .get(self.position..end)
            .ok_or(ManifestError::Invalid)?;
        let mut value = [0_u8; N];
        value.copy_from_slice(source);
        self.position = end;
        Ok(value)
    }

    fn u32(&mut self) -> Result<u32, ManifestError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ManifestError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    const fn position(&self) -> usize {
        self.position
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root_inventory::RootInventory;

    fn manifest() -> InstallManifest {
        let before = RootInventory::fixture(41, vec![3, 5, 7]);
        let maps = std::array::from_fn(|index| ManifestMap {
            name: KernelObjectName::new(&format!("map_{index}")).expect("map name"),
            id: 101 + index as u32,
            map_type: 2 + index as u32,
            key_size: 4,
            value_size: 40 + index as u32,
            max_entries: 1 + index as u32,
            map_flags: index as u32,
        });
        let programs = std::array::from_fn(|index| {
            let program_map_ids =
                std::array::from_fn::<u32, MAX_PROGRAM_MAPS, _>(|map| 101 + map as u32);
            ManifestProgram {
                name: KernelObjectName::new(&format!("prog_{index}")).expect("program name"),
                id: 201 + index as u32,
                program_type: 8,
                tag: 301 + index as u64,
                map_ids: program_map_ids,
                map_count: INSTALL_MAP_COUNT as u32,
            }
        });
        InstallManifest::new(
            InstallGenerationId::new([9_u8; 16]).expect("generation"),
            [11_u8; 32],
            [13_u8; 32],
            &before,
            NonZeroU64::new(42).expect("post revision"),
            programs,
            maps,
        )
        .expect("manifest")
    }

    #[test]
    fn canonical_round_trip_binds_every_identity_class() {
        let expected = manifest();
        let encoded = expected.encode().expect("encode");
        assert_eq!(InstallManifest::decode(&encoded).expect("decode"), expected);
        assert!(encoded[ENCODED_FIELDS_BYTES..]
            .iter()
            .all(|byte| *byte == 0));
    }

    #[test]
    fn corrupt_header_identity_and_padding_fail_closed() {
        let expected = manifest();
        let encoded = expected.encode().expect("encode");
        for offset in [0, 8, 92, 100, 108, 116, 120, 124, 640, 832] {
            let mut mutated = encoded;
            mutated[offset] ^= 0x80;
            assert_eq!(
                InstallManifest::decode(&mutated),
                Err(ManifestError::Invalid),
                "offset {offset}"
            );
        }
        for offset in [12, 28, 60, 128, 664, 868] {
            let mut mutated = encoded;
            mutated[offset] ^= 1;
            let decoded = InstallManifest::decode(&mutated).expect("canonical identity mutation");
            assert_ne!(decoded, expected, "offset {offset}");
        }
        let mut mutated = encoded;
        mutated[INSTALL_MANIFEST_BYTES - 1] = 1;
        assert_eq!(
            InstallManifest::decode(&mutated),
            Err(ManifestError::Invalid)
        );
    }

    #[test]
    fn kernel_names_are_short_ascii_and_canonically_padded() {
        assert_eq!(
            KernelObjectName::new("opc_fence_gate")
                .expect("name")
                .as_str(),
            "opc_fence_gate"
        );
        for invalid in ["", "invalid-name", "0123456789abcdef"] {
            assert_eq!(KernelObjectName::new(invalid), Err(ManifestError::Invalid));
        }
        let mut noncanonical = [0_u8; OBJECT_NAME_BYTES];
        noncanonical[0] = b'a';
        noncanonical[2] = b'b';
        assert_eq!(
            KernelObjectName::from_encoded(noncanonical),
            Err(ManifestError::Invalid)
        );
    }

    #[test]
    fn manifest_debug_redacts_all_kernel_identities() {
        let manifest = manifest();
        let debug = format!("{manifest:?}");
        for fragment in ["201", "101", "41", "42", "prog_0", "map_0"] {
            assert!(!debug.contains(fragment));
        }
        assert!(debug.contains("program_count: 3"));
        assert!(debug.contains("map_count: 7"));
    }
}
