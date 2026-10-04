//! Strict profile discrimination for the separately booted nohz_full lanes.

use super::*;
use opc_gtpu_ebpf_common::{TftClassifierFilterKey, TftClassifierMeta};
use rustix::thread::{membarrier_query, MembarrierQuery};

#[derive(Debug, PartialEq, Eq)]
enum ProfileFailure {
    NoEffectiveNoHzCpu,
    QueryUnavailable,
    GlobalStillAvailable,
}

fn validate_profile(cpu_list: &str, query: MembarrierQuery) -> Result<(), ProfileFailure> {
    let cpu = |value: &str| {
        (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| value.parse::<u32>().ok())
            .flatten()
    };
    if !cpu_list.trim().split(',').all(|field| {
        let (first, last) = field.split_once('-').unwrap_or((field, field));
        matches!((cpu(first), cpu(last)), (Some(first), Some(last)) if first <= last)
    }) {
        return Err(ProfileFailure::NoEffectiveNoHzCpu);
    }
    if query.is_empty() {
        return Err(ProfileFailure::QueryUnavailable);
    }
    if query.contains(MembarrierQuery::GLOBAL) {
        return Err(ProfileFailure::GlobalStillAvailable);
    }
    Ok(())
}

/// Ordinary lanes retain their existing behavior. The separate nohz lane
/// requires these assertions and its own markers; forgetting the flag cannot
/// produce nohz qualification credit.
pub(super) fn require_requested_profile() -> bool {
    match env::var("OPC_GTPU_REQUIRE_NOHZ_FULL") {
        Err(env::VarError::NotPresent) => return false,
        Ok(value) if value == "1" => {}
        _ => panic!("invalid nohz_full qualification request"),
    }
    assert_eq!(env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    let cpu_list = fs::read_to_string("/sys/devices/system/cpu/nohz_full")
        .expect("effective nohz_full CPU mask must be readable");
    let query = membarrier_query();
    assert_eq!(
        validate_profile(&cpu_list, query),
        Ok(()),
        "nohz_full qualification requires effective CPUs and GLOBAL absent"
    );
    eprintln!(
        "nohz_full={} membarrier_query={:#x} GLOBAL=absent",
        cpu_list.trim(),
        query.bits()
    );
    eprintln!("OPC_GTPU_TFT_NOHZ_PROFILE_PROVEN");
    true
}

pub(super) fn require_aya_available(backend: &EbpfGtpuDataplaneBackend) {
    assert_eq!(
        backend.tft_uplink_classification_capability(),
        GtpuCapability::Available,
        "the production Aya adapter must offer TFT with GLOBAL absent"
    );
    assert_eq!(backend.tft_uplink_classification_unavailable_reason(), None);
    eprintln!("OPC_GTPU_TFT_NOHZ_CAPABILITY_PROVEN");
}

pub(super) fn retained_inactive_bank(pin_dir: &Path) -> u8 {
    let contents = current_map_contents(pin_dir);
    assert_eq!(contents.tft_meta.len(), 1);
    let meta = TftClassifierMeta::decode(contents.tft_meta[0].1).expect("current TFT metadata");
    let inactive = 1 - meta.active_bank();
    assert!(
        contents.tft_filters.iter().any(|(key, _)| {
            TftClassifierFilterKey::decode(*key).is_some_and(|key| key.bank() == inactive)
        }),
        "third snapshot must reclaim retained inactive rows"
    );
    inactive
}

pub(super) fn require_reused_bank(pin_dir: &Path, bank: u8) {
    let contents = current_map_contents(pin_dir);
    assert_eq!(contents.tft_meta.len(), 1);
    let meta = TftClassifierMeta::decode(contents.tft_meta[0].1).expect("current TFT metadata");
    assert_eq!(
        meta.active_bank(),
        bank,
        "third snapshot must reuse the retained bank"
    );
    eprintln!("OPC_GTPU_TFT_NOHZ_BANK_REUSE_PROVEN");
}

#[test]
fn nohz_full_qualification_refuses_empty_or_invalid_effective_cpu_mask() {
    for cpu_list in ["", " \n", "(null)", "unknown", "1-", "3-1", "1,,2"] {
        assert_eq!(
            validate_profile(cpu_list, MembarrierQuery::GLOBAL_EXPEDITED),
            Err(ProfileFailure::NoEffectiveNoHzCpu),
            "a boot argument alone does not establish an effective nohz_full CPU"
        );
    }
}

#[test]
fn nohz_full_qualification_refuses_global_or_unavailable_query() {
    assert_eq!(
        validate_profile("1", MembarrierQuery::GLOBAL),
        Err(ProfileFailure::GlobalStillAvailable)
    );
    assert_eq!(
        validate_profile("1", MembarrierQuery::empty()),
        Err(ProfileFailure::QueryUnavailable)
    );
}

#[test]
fn nohz_full_qualification_requires_effective_cpus_and_global_absent() {
    for cpu_list in ["1", "1-3", "1,3-4\n"] {
        assert_eq!(
            validate_profile(cpu_list, MembarrierQuery::GLOBAL_EXPEDITED),
            Ok(())
        );
    }
}
