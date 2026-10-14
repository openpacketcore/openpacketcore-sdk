use opc_config_model::YangPath;
use opc_mgmt_opstate::{OperationalRequest, OperationalResponse, OperationalValue};

fn matching_allocations(count: usize) -> u64 {
    let selected = (0..count)
        .map(|index| YangPath::new(format!("/ex:rows{index:04}/ex:value")).unwrap())
        .collect::<Vec<_>>();
    let request = OperationalRequest::new(selected);
    let response = OperationalResponse::new((0..count).rev().map(|index| {
        OperationalValue::new(
            YangPath::new(format!("/ex:rows{index:04}[ex:key='row']/ex:value")).unwrap(),
            "true",
        )
        .unwrap()
    }));
    allocation_counter::measure(|| {
        assert_eq!(response.validate_for_request(&request), Ok(()));
    })
    .count_total
}

#[test]
fn operational_response_matching_allocations_grow_linearly() {
    // Fixed-width names hold path lengths constant. Doubling both dimensions
    // must not multiply path parsing and its allocations by four.
    let small = matching_allocations(64);
    let large = matching_allocations(128);
    assert!(small > 0);
    assert!(
        large <= small * 3,
        "allocations grew from {small} to {large}"
    );
}
