//! Synthetic allocation controls for the audit-path preparation component.
//! String capacity is observed inside the real tokenizer before either return.
//! This is not allocator overhead, aggregate metadata or whole-operation proof.

use std::cell::Cell;

use super::{tokenize_audit_path, CONFIG_AUDIT_PATH_MAX_BYTES};
use crate::AuditKey;

thread_local! {
    static OBSERVED_CAPACITY: Cell<Option<usize>> = const { Cell::new(None) };
}

pub(super) fn observe_capacity(capacity: usize) {
    OBSERVED_CAPACITY
        .with(|observed| observed.set(Some(observed.get().unwrap_or(0).max(capacity))));
}

fn run(path: &str) -> (Result<String, crate::PersistError>, usize) {
    OBSERVED_CAPACITY.with(|observed| observed.set(None));
    let key = AuditKey::new([0x75; 32]).expect("synthetic audit key");
    let result = tokenize_audit_path(path, &key);
    let capacity = OBSERVED_CAPACITY
        .with(Cell::get)
        .expect("real tokenizer allocation observation reached");
    eprintln!(
        "CONFIG_CAPACITY_TOKEN_PATH input_bytes={} output_capacity={capacity}",
        path.len()
    );
    (result, capacity)
}

fn expanded_boundary_path(extra: usize) -> String {
    // Fixed public token shape: one SHA-256 HMAC as 64 hexadecimal digits.
    let expanded_predicate_bytes = "[key='hmac-sha256:']".len() + 64;
    let prefix_bytes = CONFIG_AUDIT_PATH_MAX_BYTES - expanded_predicate_bytes + extra;
    let mut path = "/".to_owned();
    path.push_str(&"x".repeat(prefix_bytes - 1));
    path.push_str("[key='x']");
    assert!(path.len() < CONFIG_AUDIT_PATH_MAX_BYTES);
    path
}

#[test]
fn config_capacity_957_token_path_at_limit_has_bounded_allocation() {
    let (result, capacity) = run(&expanded_boundary_path(0));
    let path = result.expect("the exact finalized field limit is valid");
    assert_eq!(path.len(), CONFIG_AUDIT_PATH_MAX_BYTES);
    assert!(super::audit_path_is_safe(&path));
    assert!(
        capacity <= CONFIG_AUDIT_PATH_MAX_BYTES,
        "finalized path allocation exceeds its explicit component budget"
    );
}

#[test]
fn config_capacity_957_token_path_one_over_rejects_before_extra_allocation() {
    let (result, capacity) = run(&expanded_boundary_path(1));
    assert!(result.is_err(), "one-over finalized field must reject");
    assert!(
        capacity <= CONFIG_AUDIT_PATH_MAX_BYTES,
        "one-over path allocated beyond its field budget before rejection"
    );
}

#[test]
fn config_capacity_957_many_short_predicates_do_not_expand_rejected_allocation() {
    let path = format!("/test:item{}", "[key='x']".repeat(128));
    assert!(path.len() < CONFIG_AUDIT_PATH_MAX_BYTES);
    let (result, capacity) = run(&path);
    assert!(result.is_err(), "expanded aggregate field must reject");
    assert!(
        capacity <= CONFIG_AUDIT_PATH_MAX_BYTES,
        "many short predicates allocated beyond the rejected field budget"
    );
}
