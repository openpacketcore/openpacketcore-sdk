//! Canonical immutable identity manifest for one root-cgroup fence generation.

use std::collections::BTreeSet;

use crate::root_inventory::RootInventory;
use opc_egress_fence_common::{
    EGRESS_FENCE_CONFIG_MAP_NAME, EGRESS_FENCE_CONFIG_VALUE_LEN, EGRESS_FENCE_CONTROL_PROGRAM_NAME,
    EGRESS_FENCE_COOKIE_KEY_LEN, EGRESS_FENCE_COOKIE_MAP_NAME, EGRESS_FENCE_COOKIE_VALUE_LEN,
    EGRESS_FENCE_COUNTER_MAP_NAME, EGRESS_FENCE_COUNTER_SLOTS, EGRESS_FENCE_CURRENT_MAP_NAME,
    EGRESS_FENCE_CURRENT_VALUE_LEN, EGRESS_FENCE_INSPECT_PROGRAM_NAME, EGRESS_FENCE_LOCK_MAP_NAME,
    EGRESS_FENCE_MAX_COOKIE_ENTRIES, EGRESS_FENCE_MUTATION_MAP_NAME, EGRESS_FENCE_PROGRAM_NAME,
};

pub(crate) const INSTALL_MANIFEST_BYTES: usize = 2_048;
pub(crate) const INSTALL_PROGRAM_COUNT: usize = 3;
/// Shared maps loaded from the committed eBPF object.
pub(crate) const OBJECT_MAP_COUNT: usize = 6;
/// Six shared object maps plus the installer-created frozen manifest map.
pub(crate) const INSTALL_MAP_COUNT: usize = 7;
pub(crate) const MAX_PROGRAM_MAPS: usize = OBJECT_MAP_COUNT;
const MAX_ROOT_PROGRAMS: usize = 64;
const OBJECT_NAME_BYTES: usize = 16;
const MANIFEST_MAGIC: [u8; 8] = *b"OPCFM001";
const MANIFEST_VERSION: u32 = 3;
const BPF_F_ALLOW_MULTI: u32 = 1 << 1;
const BPF_PROG_TYPE_SCHED_CLS: u32 = 3;
const BPF_PROG_TYPE_CGROUP_SKB: u32 = 8;
const BPF_MAP_TYPE_HASH: u32 = 1;
const BPF_MAP_TYPE_ARRAY: u32 = 2;
const BPF_MAP_TYPE_PERCPU_ARRAY: u32 = 6;
pub(crate) const MANIFEST_MAP_NAME: &str = "OPC_FENCE_MAN";
const ENCODED_FIELDS_BYTES: usize = 1_128;

/// Exact maps whose syscall-side mutation is disabled with `BPF_MAP_FREEZE`.
///
/// `OPC_FENCE_LOCK` is intentionally absent. Linux rejects `BPF_MAP_FREEZE`
/// for BTF maps whose values contain special fields such as `bpf_spin_lock`.
/// Its exact schema, kernel identity, program references, and initial zero
/// value remain mandatory admission evidence.
pub(crate) const USERSPACE_FROZEN_MAP_NAMES: [&str; INSTALL_MAP_COUNT - 1] = [
    EGRESS_FENCE_COOKIE_MAP_NAME,
    EGRESS_FENCE_CONFIG_MAP_NAME,
    EGRESS_FENCE_COUNTER_MAP_NAME,
    EGRESS_FENCE_CURRENT_MAP_NAME,
    EGRESS_FENCE_MUTATION_MAP_NAME,
    MANIFEST_MAP_NAME,
];

/// Exact bounded set of names allowed inside one generation directory.
pub(crate) const INSTALL_PIN_OBJECT_NAMES: [&str; INSTALL_PROGRAM_COUNT + INSTALL_MAP_COUNT] = [
    EGRESS_FENCE_PROGRAM_NAME,
    EGRESS_FENCE_CONTROL_PROGRAM_NAME,
    EGRESS_FENCE_INSPECT_PROGRAM_NAME,
    EGRESS_FENCE_COOKIE_MAP_NAME,
    EGRESS_FENCE_CONFIG_MAP_NAME,
    EGRESS_FENCE_COUNTER_MAP_NAME,
    EGRESS_FENCE_CURRENT_MAP_NAME,
    EGRESS_FENCE_LOCK_MAP_NAME,
    EGRESS_FENCE_MUTATION_MAP_NAME,
    MANIFEST_MAP_NAME,
];

#[derive(Clone, Copy)]
struct ProgramSchema {
    name: &'static str,
    program_type: u32,
    map_mask: u8,
}

const PROGRAM_SCHEMAS: [ProgramSchema; INSTALL_PROGRAM_COUNT] = [
    ProgramSchema {
        name: EGRESS_FENCE_PROGRAM_NAME,
        program_type: BPF_PROG_TYPE_CGROUP_SKB,
        map_mask: 0b01_1111,
    },
    ProgramSchema {
        name: EGRESS_FENCE_CONTROL_PROGRAM_NAME,
        program_type: BPF_PROG_TYPE_SCHED_CLS,
        map_mask: 0b11_1011,
    },
    ProgramSchema {
        name: EGRESS_FENCE_INSPECT_PROGRAM_NAME,
        program_type: BPF_PROG_TYPE_SCHED_CLS,
        map_mask: 0b11_1011,
    },
];

#[derive(Clone, Copy)]
struct MapSchema {
    name: &'static str,
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    freeze_policy: MapFreezePolicy,
}

const MAP_SCHEMAS: [MapSchema; INSTALL_MAP_COUNT] = [
    MapSchema {
        name: EGRESS_FENCE_COOKIE_MAP_NAME,
        map_type: BPF_MAP_TYPE_HASH,
        key_size: EGRESS_FENCE_COOKIE_KEY_LEN as u32,
        value_size: EGRESS_FENCE_COOKIE_VALUE_LEN as u32,
        max_entries: EGRESS_FENCE_MAX_COOKIE_ENTRIES,
        map_flags: 0,
        freeze_policy: MapFreezePolicy::Required,
    },
    MapSchema {
        name: EGRESS_FENCE_CONFIG_MAP_NAME,
        map_type: BPF_MAP_TYPE_ARRAY,
        key_size: 4,
        value_size: EGRESS_FENCE_CONFIG_VALUE_LEN as u32,
        max_entries: 1,
        map_flags: 0,
        freeze_policy: MapFreezePolicy::Required,
    },
    MapSchema {
        name: EGRESS_FENCE_COUNTER_MAP_NAME,
        map_type: BPF_MAP_TYPE_PERCPU_ARRAY,
        key_size: 4,
        value_size: 8,
        max_entries: EGRESS_FENCE_COUNTER_SLOTS,
        map_flags: 0,
        freeze_policy: MapFreezePolicy::Required,
    },
    MapSchema {
        name: EGRESS_FENCE_CURRENT_MAP_NAME,
        map_type: BPF_MAP_TYPE_ARRAY,
        key_size: 4,
        value_size: EGRESS_FENCE_CURRENT_VALUE_LEN as u32,
        max_entries: 1,
        map_flags: 0,
        freeze_policy: MapFreezePolicy::Required,
    },
    MapSchema {
        name: EGRESS_FENCE_LOCK_MAP_NAME,
        map_type: BPF_MAP_TYPE_ARRAY,
        key_size: 4,
        value_size: 4,
        max_entries: 1,
        map_flags: 0,
        freeze_policy: MapFreezePolicy::KernelUnsupportedSpecialField,
    },
    MapSchema {
        name: EGRESS_FENCE_MUTATION_MAP_NAME,
        map_type: BPF_MAP_TYPE_ARRAY,
        key_size: 4,
        value_size: 16,
        max_entries: 1,
        map_flags: 0,
        freeze_policy: MapFreezePolicy::Required,
    },
    MapSchema {
        name: MANIFEST_MAP_NAME,
        map_type: BPF_MAP_TYPE_ARRAY,
        key_size: 4,
        value_size: INSTALL_MANIFEST_BYTES as u32,
        max_entries: 1,
        map_flags: 0,
        freeze_policy: MapFreezePolicy::Required,
    },
];

/// Syscall-side freeze requirement persisted for every manifest map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MapFreezePolicy {
    /// Linux rejects `BPF_MAP_FREEZE` because the BTF value has a special
    /// kernel-managed field. This policy is valid only for `OPC_FENCE_LOCK`.
    KernelUnsupportedSpecialField = 0,
    /// Installation must freeze the map and every integrity check must prove
    /// the live kernel map still reports frozen.
    Required = 1,
}

impl MapFreezePolicy {
    pub(crate) fn for_map_name(name: &str) -> Result<Self, ManifestError> {
        MAP_SCHEMAS
            .iter()
            .find(|schema| schema.name == name)
            .map(|schema| schema.freeze_policy)
            .ok_or(ManifestError::Invalid)
    }

    pub(crate) const fn requires_userspace_freeze(self) -> bool {
        matches!(self, Self::Required)
    }

    const fn encode(self) -> u32 {
        self as u32
    }

    fn decode(encoded: u32) -> Result<Self, ManifestError> {
        match encoded {
            0 => Ok(Self::KernelUnsupportedSpecialField),
            1 => Ok(Self::Required),
            _ => Err(ManifestError::Invalid),
        }
    }
}

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
    pub(crate) freeze_policy: MapFreezePolicy,
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
    pub(crate) pre_revision: u64,
    pub(crate) post_revision: u64,
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
        post_revision: u64,
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
        writer.u64(self.pre_revision)?;
        writer.u64(self.post_revision)?;
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
            writer.u32(map.freeze_policy.encode())?;
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
        let pre_revision = reader.u64()?;
        let post_revision = reader.u64()?;
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
            map.freeze_policy = MapFreezePolicy::decode(reader.u32()?)?;
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
            || pre_count != 0
            || self.pre_program_ids.iter().any(|id| *id != 0)
            || self
                .pre_program_attach_flags
                .iter()
                .any(|flags| *flags != 0)
            || self.post_revision != self.pre_revision.checked_add(1).unwrap_or(0)
            || self.pre_attach_flags != 0
            || self.post_attach_flags != BPF_F_ALLOW_MULTI
        {
            return Err(ManifestError::Invalid);
        }

        let mut program_ids = BTreeSet::new();
        let mut map_ids = BTreeSet::new();
        for (map, schema) in self.maps.iter().zip(MAP_SCHEMAS) {
            if map.id == 0
                || map.name.as_str() != schema.name
                || map.map_type != schema.map_type
                || map.key_size != schema.key_size
                || map.value_size != schema.value_size
                || map.max_entries != schema.max_entries
                || map.map_flags != schema.map_flags
                || map.freeze_policy != schema.freeze_policy
                || !map_ids.insert(map.id)
            {
                return Err(ManifestError::Invalid);
            }
        }
        let frozen_map_names = self
            .maps
            .iter()
            .filter(|map| map.freeze_policy.requires_userspace_freeze())
            .map(|map| map.name.as_str())
            .collect::<BTreeSet<_>>();
        if frozen_map_names != USERSPACE_FROZEN_MAP_NAMES.into_iter().collect() {
            return Err(ManifestError::Invalid);
        }
        let shared_map_ids = self.maps[..OBJECT_MAP_COUNT]
            .iter()
            .map(|map| map.id)
            .collect::<BTreeSet<_>>();
        let manifest_map_id = self.maps[OBJECT_MAP_COUNT].id;
        for ((program, schema), index) in self
            .programs
            .iter()
            .zip(PROGRAM_SCHEMAS)
            .zip(0..INSTALL_PROGRAM_COUNT)
        {
            let count = usize::try_from(program.map_count).map_err(|_| ManifestError::Invalid)?;
            let expected_map_ids = expected_program_map_ids(index, &self.maps);
            let actual_map_ids = program.map_ids[..count.min(MAX_PROGRAM_MAPS)]
                .iter()
                .copied()
                .collect::<BTreeSet<_>>();
            if program.id == 0
                || program.name.as_str() != schema.name
                || program.program_type != schema.program_type
                || program.tag == 0
                || count
                    != usize::try_from(schema.map_mask.count_ones())
                        .map_err(|_| ManifestError::Invalid)?
                || count > MAX_PROGRAM_MAPS
                || program.map_ids[..count].contains(&0)
                || program.map_ids[count..].iter().any(|id| *id != 0)
                || actual_map_ids.len() != count
                || actual_map_ids != expected_map_ids
                || !actual_map_ids.is_subset(&shared_map_ids)
                || actual_map_ids.contains(&manifest_map_id)
                || !program_ids.insert(program.id)
            {
                return Err(ManifestError::Invalid);
            }
        }
        Ok(())
    }

    /// Validate the live root inventory against this generation's persisted
    /// exact pre-attachment provenance.
    ///
    /// A prepared generation is recoverable only while the root still matches
    /// the inventory captured before direct attachment. This comparison keeps
    /// the full persisted representation even though the current protocol
    /// admits only an empty pre-attachment program list.
    pub(crate) fn validates_root_pre_attach(&self, observed: &RootInventory) -> bool {
        if self.validate().is_err() {
            return false;
        }
        let Ok(count) = usize::try_from(self.pre_program_count) else {
            return false;
        };
        let Some(expected_program_ids) = self.pre_program_ids.get(..count) else {
            return false;
        };
        let Some(expected_program_flags) = self.pre_program_attach_flags.get(..count) else {
            return false;
        };
        observed.revision() == self.pre_revision
            && observed.attach_flags() == self.pre_attach_flags
            && observed.program_ids() == expected_program_ids
            && observed.program_attach_flags() == expected_program_flags
    }

    /// Validate the live root inventory against this generation's persisted
    /// direct-attachment provenance.
    pub(crate) fn validates_root_adoption(&self, observed: &RootInventory) -> bool {
        self.validate().is_ok()
            && observed.matches_trusted_direct_attachment(self.post_revision, self.programs[0].id)
    }
}

impl std::fmt::Debug for InstallManifest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InstallManifest")
            .field("generation_present", &true)
            .field("program_count", &INSTALL_PROGRAM_COUNT)
            .field("map_count", &INSTALL_MAP_COUNT)
            .field("object_map_count", &OBJECT_MAP_COUNT)
            .field("pre_program_count", &self.pre_program_count)
            .field("revisions_verified", &true)
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
        freeze_policy: MapFreezePolicy::KernelUnsupportedSpecialField,
    }
}

fn expected_program_map_ids(
    program_index: usize,
    maps: &[ManifestMap; INSTALL_MAP_COUNT],
) -> BTreeSet<u32> {
    let mut expected = BTreeSet::new();
    let mask = PROGRAM_SCHEMAS[program_index].map_mask;
    for (index, map) in maps[..OBJECT_MAP_COUNT].iter().enumerate() {
        if mask & (1_u8 << index) != 0 {
            expected.insert(map.id);
        }
    }
    expected
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

    fn maps() -> [ManifestMap; INSTALL_MAP_COUNT] {
        std::array::from_fn(|index| {
            let schema = MAP_SCHEMAS[index];
            ManifestMap {
                name: KernelObjectName::new(schema.name).expect("stable map name"),
                id: 101 + index as u32,
                map_type: schema.map_type,
                key_size: schema.key_size,
                value_size: schema.value_size,
                max_entries: schema.max_entries,
                map_flags: schema.map_flags,
                freeze_policy: schema.freeze_policy,
            }
        })
    }

    fn programs(
        maps: &[ManifestMap; INSTALL_MAP_COUNT],
    ) -> [ManifestProgram; INSTALL_PROGRAM_COUNT] {
        std::array::from_fn(|index| {
            let schema = PROGRAM_SCHEMAS[index];
            let expected = expected_program_map_ids(index, maps);
            let mut map_ids = [0_u32; MAX_PROGRAM_MAPS];
            let mut ids = expected.into_iter().collect::<Vec<_>>();
            ids.reverse();
            map_ids[..ids.len()].copy_from_slice(&ids);
            ManifestProgram {
                name: KernelObjectName::new(schema.name).expect("stable program name"),
                id: 201 + index as u32,
                program_type: schema.program_type,
                tag: 301 + index as u64,
                map_ids,
                map_count: u32::try_from(ids.len()).expect("small map count"),
            }
        })
    }

    fn manifest() -> InstallManifest {
        let before = RootInventory::fixture(0, vec![]);
        let maps = maps();
        let programs = programs(&maps);
        InstallManifest::new(
            InstallGenerationId::new([9_u8; 16]).expect("generation"),
            [11_u8; 32],
            [13_u8; 32],
            &before,
            1,
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
    fn syscall_freeze_policy_is_exact_and_excludes_only_the_btf_lock_map() {
        let expected = manifest();
        let frozen = expected
            .maps
            .iter()
            .filter(|map| map.freeze_policy.requires_userspace_freeze())
            .map(|map| map.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(frozen, USERSPACE_FROZEN_MAP_NAMES);
        assert_eq!(
            MapFreezePolicy::for_map_name(EGRESS_FENCE_LOCK_MAP_NAME),
            Ok(MapFreezePolicy::KernelUnsupportedSpecialField)
        );
    }

    #[test]
    fn corrupt_header_identity_and_padding_fail_closed() {
        let expected = manifest();
        let encoded = expected.encode().expect("encode");
        for offset in [0, 8, 92, 100, 108, 112, 116, 120, 124, 640, 820, 836] {
            let mut mutated = encoded;
            mutated[offset] ^= 0x80;
            assert_eq!(
                InstallManifest::decode(&mutated),
                Err(ManifestError::Invalid),
                "offset {offset}"
            );
        }
        for offset in [12, 28, 60, 656] {
            let mut mutated = encoded;
            mutated[offset] ^= 1;
            let decoded = InstallManifest::decode(&mutated).unwrap_or_else(|error| {
                panic!("canonical identity mutation at {offset}: {error:?}")
            });
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
    fn program_map_freeze_and_manifest_schemas_reject_every_drift_class() {
        let expected = manifest();
        let mut mutations = Vec::new();

        let mut mutation = expected.clone();
        mutation.programs[0].name =
            KernelObjectName::new("opc_wrong_gate").expect("valid wrong name");
        mutations.push(mutation);

        let mut mutation = expected.clone();
        mutation.programs[1].program_type = BPF_PROG_TYPE_CGROUP_SKB;
        mutations.push(mutation);

        let mut mutation = expected.clone();
        mutation.programs[2].map_ids[0] = mutation.maps[OBJECT_MAP_COUNT].id;
        mutations.push(mutation);

        let mut mutation = expected.clone();
        mutation.programs[0].map_count -= 1;
        mutations.push(mutation);

        let mut mutation = expected.clone();
        mutation.maps[0].name = KernelObjectName::new("OPC_FENCE_BAD").expect("valid wrong name");
        mutations.push(mutation);

        let mut mutation = expected.clone();
        mutation.maps[1].value_size += 1;
        mutations.push(mutation);

        let mut mutation = expected.clone();
        mutation.maps[OBJECT_MAP_COUNT].map_type = BPF_MAP_TYPE_HASH;
        mutations.push(mutation);

        let mut mutation = expected.clone();
        mutation.maps[OBJECT_MAP_COUNT].max_entries = 2;
        mutations.push(mutation);

        let mut mutation = expected.clone();
        mutation.maps[OBJECT_MAP_COUNT].id = mutation.maps[0].id;
        mutations.push(mutation);

        let mut mutation = expected.clone();
        mutation.maps[0].freeze_policy = MapFreezePolicy::KernelUnsupportedSpecialField;
        mutations.push(mutation);

        let mut mutation = expected.clone();
        mutation.maps[4].freeze_policy = MapFreezePolicy::Required;
        mutations.push(mutation);

        for mutation in mutations {
            assert_eq!(mutation.encode(), Err(ManifestError::Invalid));
        }
    }

    #[test]
    fn manifest_records_exact_direct_revision_provenance_for_adoption() {
        let manifest = manifest();
        assert_eq!(manifest.pre_revision, 0);
        assert_eq!(manifest.post_revision, 1);
        assert!(manifest.validates_root_pre_attach(&RootInventory::fixture(0, vec![])));
        assert!(manifest
            .validates_root_adoption(&RootInventory::fixture(1, vec![manifest.programs[0].id])));

        for foreign_or_stale in [
            RootInventory::fixture(1, vec![]),
            RootInventory::fixture(0, vec![manifest.programs[0].id]),
        ] {
            assert!(!manifest.validates_root_pre_attach(&foreign_or_stale));
        }
        for foreign_or_stale in [
            RootInventory::fixture(0, vec![manifest.programs[0].id]),
            RootInventory::fixture(2, vec![manifest.programs[0].id]),
            RootInventory::fixture(1, vec![]),
            RootInventory::fixture(1, vec![manifest.programs[1].id]),
            RootInventory::fixture(1, vec![manifest.programs[0].id, manifest.programs[1].id]),
        ] {
            assert!(!manifest.validates_root_adoption(&foreign_or_stale));
        }

        let mut corrupt = manifest.clone();
        corrupt.pre_attach_flags = BPF_F_ALLOW_MULTI;
        assert!(!corrupt.validates_root_pre_attach(&RootInventory::fixture(0, vec![])));
    }

    #[test]
    fn prepared_recovery_accepts_exact_nonzero_empty_pre_revision() {
        let before = RootInventory::fixture(41, vec![]);
        let maps = maps();
        let manifest = InstallManifest::new(
            InstallGenerationId::new([9_u8; 16]).expect("generation"),
            [11_u8; 32],
            [13_u8; 32],
            &before,
            42,
            programs(&maps),
            maps,
        )
        .expect("manifest");

        assert!(manifest.validates_root_pre_attach(&before));
        assert!(!manifest.validates_root_pre_attach(&RootInventory::fixture(40, vec![])));
        assert!(!manifest.validates_root_pre_attach(&RootInventory::fixture(42, vec![])));
    }

    #[test]
    fn foreign_pre_attachment_cannot_be_encoded_as_direct_provenance() {
        let before = RootInventory::fixture(41, vec![99]);
        let maps = maps();
        assert_eq!(
            InstallManifest::new(
                InstallGenerationId::new([9_u8; 16]).expect("generation"),
                [11_u8; 32],
                [13_u8; 32],
                &before,
                42,
                programs(&maps),
                maps,
            ),
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
        for fragment in ["201", "101", "opc_egress_gate", "OPC_FENCE_CKS"] {
            assert!(!debug.contains(fragment));
        }
        assert!(debug.contains("program_count: 3"));
        assert!(debug.contains("map_count: 7"));
        assert!(debug.contains("object_map_count: 6"));
    }
}
