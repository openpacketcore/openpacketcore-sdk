use super::*;

const NOW: Duration = Duration::ZERO;
const ITEM: ItemCost = ItemCost {
    emitted: true,
    payload_bytes: 10,
    retained_bytes: 20,
};
const FILTERED: ItemCost = ItemCost {
    emitted: false,
    payload_bytes: 0,
    retained_bytes: 0,
};

fn page() -> PageProgress<u64> {
    PageProgress::new(PageLimits::default(), None, InventoryTotals::default(), 64).unwrap()
}

#[test]
fn time_budget_returns_completed_items_with_an_advancing_position() {
    let mut page = page();
    page.visit(40, NOW).unwrap();
    page.complete_item(1, ITEM, 0, false).unwrap();
    assert_eq!(
        page.visit(40, Duration::from_secs(1)),
        Err(PageProgressError::WorkBudget)
    );
    let boundary = page.finish(PageEnd::Interrupted);
    assert_eq!(
        boundary,
        PageBoundary::Continue {
            after: 1,
            totals: InventoryTotals {
                items: 1,
                ..InventoryTotals::default()
            },
        }
    );
}

#[test]
fn no_finished_item_requires_retry_without_consuming_its_position() {
    let mut page = page();
    page.visit(40, NOW).unwrap();
    assert_eq!(
        page.visit(40, Duration::from_secs(2)),
        Err(PageProgressError::WorkBudget)
    );
    assert_eq!(page.after(), None);
    assert_eq!(page.finish(PageEnd::Interrupted), PageBoundary::NoProgress);
    let resumed = PageProgress::new(
        PageLimits::default(),
        Some(42),
        InventoryTotals {
            items: 5,
            ..InventoryTotals::default()
        },
        64,
    )
    .unwrap();
    assert_eq!(
        resumed.finish(PageEnd::Interrupted),
        PageBoundary::NoProgress
    );
}

#[test]
fn interruption_after_a_header_does_not_skip_the_unfinished_item() {
    let mut first = page();
    first.visit(40, NOW).unwrap();
    first.complete_item(10, ITEM, 0, false).unwrap();
    first.visit(40, NOW).unwrap();
    let PageBoundary::Continue { after, totals } = first.finish(PageEnd::Interrupted) else {
        panic!("expected partial page")
    };
    assert_eq!(after, 10);
    let mut next = PageProgress::new(PageLimits::default(), Some(after), totals, 64).unwrap();
    next.visit(40, NOW).unwrap();
    next.complete_item(11, ITEM, 1, false).unwrap();
    assert_eq!(
        next.finish(PageEnd::Exhausted),
        PageBoundary::Complete {
            after: Some(11),
            totals: InventoryTotals {
                items: 2,
                failed_items: 1,
                failures: 1,
                claims_incomplete: false
            },
        }
    );
}

#[test]
fn full_page_does_not_advance_or_change_totals() {
    let limits = PageLimits {
        rows: 1,
        ..PageLimits::default()
    };
    let mut page = PageProgress::new(limits, None, InventoryTotals::default(), 64).unwrap();
    page.complete_item(1, ITEM, 0, false).unwrap();
    assert_eq!(page.can_fit(ITEM), Err(PageProgressError::PageFull));
    assert_eq!(
        page.complete_item(2, ITEM, 2, true),
        Err(PageProgressError::PageFull)
    );
    assert_eq!(page.after(), Some(&1));
    assert_eq!(page.usage().returned_rows, 1);
    assert_eq!(
        page.finish(PageEnd::Interrupted),
        PageBoundary::Continue {
            after: 1,
            totals: InventoryTotals {
                items: 1,
                ..InventoryTotals::default()
            },
        }
    );
}

#[test]
fn payload_and_retained_budgets_include_fixed_response_overhead() {
    let limits = PageLimits {
        payload_bytes: 20,
        retained_bytes: 50,
        ..PageLimits::default()
    };
    let mut page = PageProgress::new(limits, None, InventoryTotals::default(), 10).unwrap();
    page.complete_item(1, ITEM, 0, false).unwrap();
    page.complete_item(2, ITEM, 0, false).unwrap();
    assert_eq!(page.usage().payload_bytes, 20);
    assert_eq!(page.usage().retained_bytes, 50);
    assert_eq!(page.can_fit(ITEM), Err(PageProgressError::PageFull));
    assert_eq!(page.after(), Some(&2));

    let limits = PageLimits {
        payload_bytes: 10,
        ..PageLimits::default()
    };
    let mut page = PageProgress::new(limits, None, InventoryTotals::default(), 0).unwrap();
    page.complete_item(1, ITEM, 0, false).unwrap();
    assert_eq!(page.can_fit(ITEM), Err(PageProgressError::PageFull));

    let limits = PageLimits {
        retained_bytes: 30,
        ..PageLimits::default()
    };
    let mut page = PageProgress::new(limits, None, InventoryTotals::default(), 10).unwrap();
    page.complete_item(1, ITEM, 0, false).unwrap();
    assert_eq!(page.can_fit(ITEM), Err(PageProgressError::PageFull));
}

#[test]
fn default_page_fits_the_largest_legal_child_and_row_headroom() {
    let cost = ItemCost {
        emitted: true,
        payload_bytes: 1024 * 1024 + 4096,
        retained_bytes: 1024 * 1024 + 16 * 1024,
    };
    let mut page = page();
    page.can_fit(cost).unwrap();
    page.complete_item(1, cost, 0, false).unwrap();
    assert_eq!(page.usage().returned_rows, 1);
}

#[test]
fn row_visits_include_cross_checks_and_metadata_is_bounded() {
    let limits = PageLimits {
        visits: 2,
        metadata_bytes: 100,
        ..PageLimits::default()
    };
    let mut page = PageProgress::<u64>::new(limits, None, InventoryTotals::default(), 0).unwrap();
    page.visit(40, NOW).unwrap();
    page.visit(60, NOW).unwrap();
    assert_eq!(page.visit(0, NOW), Err(PageProgressError::WorkBudget));
    assert_eq!(page.usage().visits, 2);
    assert_eq!(page.usage().metadata_bytes, 100);
    let limits = PageLimits {
        metadata_bytes: 10,
        ..PageLimits::default()
    };
    let mut page = PageProgress::<u64>::new(limits, None, InventoryTotals::default(), 0).unwrap();
    assert_eq!(page.visit(11, NOW), Err(PageProgressError::WorkBudget));
    assert_eq!(page.usage().visits, 0);
}

#[test]
fn duplicate_and_regressing_positions_are_rejected_transactionally() {
    let mut page = page();
    page.complete_item(10, ITEM, 0, false).unwrap();
    for position in [10, 9] {
        assert_eq!(
            page.complete_item(position, ITEM, 8, true),
            Err(PageProgressError::PositionNotAdvancing)
        );
        assert_eq!(page.after(), Some(&10));
        assert_eq!(page.usage().returned_rows, 1);
    }
}

#[test]
fn filtered_failure_manifest_advances_across_healthy_items_in_constant_space() {
    let mut page = page();
    for key in 1..=4095 {
        page.visit(100, NOW).unwrap();
        page.complete_item(key, FILTERED, 0, false).unwrap();
    }
    assert_eq!(page.usage().returned_rows, 0);
    assert_eq!(page.usage().retained_bytes, 64);
    page.visit(100, NOW).unwrap();
    page.complete_item(4096, ITEM, 8, true).unwrap();
    assert_eq!(page.visit(100, NOW), Err(PageProgressError::WorkBudget));
    assert_eq!(
        page.finish(PageEnd::Interrupted),
        PageBoundary::Continue {
            after: 4096,
            totals: InventoryTotals {
                items: 4096,
                failed_items: 1,
                failures: 8,
                claims_incomplete: true
            },
        }
    );
    let totals = InventoryTotals {
        items: 4096,
        failed_items: 1,
        failures: 8,
        claims_incomplete: true,
    };
    let mut next = PageProgress::new(PageLimits::default(), Some(4096), totals, 64).unwrap();
    next.complete_item(4097, FILTERED, 0, false).unwrap();
    assert_eq!(
        next.finish(PageEnd::Exhausted),
        PageBoundary::Complete {
            after: Some(4097),
            totals: InventoryTotals {
                items: 4097,
                ..totals
            },
        }
    );
}

#[test]
fn empty_completion_requires_actual_exhaustion() {
    assert_eq!(
        page().finish(PageEnd::Interrupted),
        PageBoundary::NoProgress
    );
    assert_eq!(
        page().finish(PageEnd::Exhausted),
        PageBoundary::Complete {
            after: None,
            totals: InventoryTotals::default(),
        }
    );
}

#[test]
fn count_overflow_never_consumes_the_item() {
    for totals in [
        InventoryTotals {
            items: u64::MAX,
            ..InventoryTotals::default()
        },
        InventoryTotals {
            failed_items: u64::MAX,
            ..InventoryTotals::default()
        },
        InventoryTotals {
            failures: u64::MAX,
            ..InventoryTotals::default()
        },
    ] {
        let mut page = PageProgress::new(PageLimits::default(), Some(2), totals, 0).unwrap();
        assert_eq!(
            page.complete_item(3, ITEM, 1, false),
            Err(PageProgressError::CountOverflow)
        );
        assert_eq!(page.after(), Some(&2));
        assert_eq!(page.usage().returned_rows, 0);
    }
}

#[test]
fn invalid_cost_or_failure_metadata_cannot_bypass_bounds() {
    let mut page = page();
    for cost in [
        ItemCost {
            emitted: true,
            payload_bytes: 10,
            retained_bytes: 9,
        },
        ItemCost {
            emitted: false,
            payload_bytes: 1,
            retained_bytes: 1,
        },
        ItemCost {
            emitted: true,
            payload_bytes: usize::MAX,
            retained_bytes: usize::MAX,
        },
    ] {
        assert!(page.can_fit(cost).is_err());
    }
    assert_eq!(
        page.complete_item(1, ITEM, 9, false),
        Err(PageProgressError::InvalidItem)
    );
    assert_eq!(
        page.complete_item(1, ITEM, 0, true),
        Err(PageProgressError::InvalidItem)
    );
    assert_eq!(page.after(), None);
}

#[test]
fn invalid_limits_are_refused_before_work_starts() {
    for limits in [
        PageLimits {
            rows: 0,
            ..PageLimits::default()
        },
        PageLimits {
            rows: 1025,
            ..PageLimits::default()
        },
        PageLimits {
            payload_bytes: 0,
            ..PageLimits::default()
        },
        PageLimits {
            retained_bytes: usize::MAX,
            ..PageLimits::default()
        },
        PageLimits {
            visits: 4097,
            ..PageLimits::default()
        },
        PageLimits {
            metadata_bytes: usize::MAX,
            ..PageLimits::default()
        },
    ] {
        assert!(PageProgress::<u64>::new(limits, None, InventoryTotals::default(), 0).is_err());
    }
    assert!(PageProgress::<u64>::new(
        PageLimits::default(),
        None,
        InventoryTotals::default(),
        8 * 1024 * 1024
    )
    .is_err());
}
