mod common;

#[path = "lint_matrix/cases.rs"]
mod cases;
#[path = "lint_matrix/harness.rs"]
mod harness;

#[test]
fn generated_key_list_matrix_has_no_copy_clone_or_partial_map_iteration() {
    let mut failures = Vec::new();
    let mut total = 0;
    for profile in cases::Profile::ALL {
        for key in cases::Key::ALL {
            let mut cases = cases::matrix(profile, key);
            if key == cases::Key::U32 {
                cases.extend(cases::canonical_constraints(profile));
            }
            total += cases.len();
            if let Err(failure) = harness::check_batch(profile, key, &cases) {
                failures.push(failure);
            }
        }
    }
    assert_eq!(total, 192 + 4, "every matrix cell must be checked");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
