//! Host-portable RED selector-authority scale evidence for #720 (Option B).
//!
//! The current host-side selector authority caps are characterized as-is; this
//! does not implement selector-v2 capacity scaling, change any durable format,
//! map, pin, object or ABI, and does not claim live proof.

use super::super::{MAX_LIVE_GROUPS, MAX_PERMANENT_GROUPS};

const REQUIRED_IDENTITIES: usize = 50_000;
const REQUIRED_ATTEMPTS: usize = 10_000;

/// Assert characterized evidence without tripping
/// `clippy::assertions_on_constants` for intentional constant bounds.
fn assert_evidence(condition: bool, evidence: &str) {
    assert!(condition, "{evidence}");
}

#[test]
fn selector_authority_caps_are_below_required_pool_scale() {
    assert_eq!(MAX_PERMANENT_GROUPS, 1_024);
    assert_eq!(MAX_LIVE_GROUPS, 512);
    assert_evidence(
        MAX_PERMANENT_GROUPS < REQUIRED_IDENTITIES,
        "current permanent selector-group cap is below the required retained identities",
    );
    assert_evidence(
        MAX_LIVE_GROUPS < REQUIRED_ATTEMPTS,
        "current live selector-group cap is below the required simultaneous attempts",
    );
    // Bounded headroom today is far under the required pool size; this RED
    // evidence is preserved until the Option A selector-v2 capacity work lands.
    assert_evidence(
        REQUIRED_IDENTITIES / MAX_PERMANENT_GROUPS > 40,
        "permanent-cap headroom is more than 40x",
    );
    assert_evidence(
        REQUIRED_ATTEMPTS / MAX_LIVE_GROUPS >= 19,
        "live-cap headroom is at least 19x",
    );
}
