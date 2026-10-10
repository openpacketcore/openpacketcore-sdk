use super::*;
use std::collections::BTreeMap;

const CHILD: Key = [1; 32];
const CLAIM: Key = [2; 32];
const CUT: InventoryFloors = InventoryFloors {
    batch_revision: 20,
    birth: 10,
};

#[derive(Default)]
struct Lookup {
    children: BTreeMap<Key, ItemRead<ChildFacts>>,
    claims: BTreeMap<Key, ItemRead<ClaimFacts>>,
    visits: usize,
    interrupt_at: Option<usize>,
}

impl InventoryLookup for Lookup {
    type Interrupted = &'static str;

    fn child(&mut self, key: Key) -> Result<ItemRead<ChildFacts>, Self::Interrupted> {
        self.visit()?;
        Ok(self
            .children
            .get(&key)
            .cloned()
            .unwrap_or(ItemRead::Missing))
    }

    fn claim(&mut self, key: Key) -> Result<ItemRead<ClaimFacts>, Self::Interrupted> {
        self.visit()?;
        Ok(self.claims.get(&key).cloned().unwrap_or(ItemRead::Missing))
    }
}

impl Lookup {
    fn visit(&mut self) -> Result<(), &'static str> {
        self.visits += 1;
        if self.interrupt_at == Some(self.visits) {
            Err("work budget exhausted")
        } else {
            Ok(())
        }
    }
}

fn child() -> ChildFacts {
    ChildFacts {
        key: CHILD,
        birth: 5,
        generation: 2,
        batch_revision: 15,
        live: true,
        claims: vec![CLAIM],
    }
}

fn claim() -> ClaimFacts {
    ClaimFacts {
        key: CLAIM,
        revision: 15,
        owner: Some(ClaimHolder {
            child: CHILD,
            birth: 5,
        }),
    }
}

fn healthy_lookup() -> Lookup {
    Lookup {
        children: [(CHILD, ItemRead::Present(child()))].into(),
        claims: [(CLAIM, ItemRead::Present(claim()))].into(),
        ..Lookup::default()
    }
}

#[test]
fn corrupt_child_is_a_final_item_between_healthy_children() {
    let mut lookup = healthy_lookup();
    let inputs = [
        ItemRead::Present(child()),
        ItemRead::Corrupt(IntegrityFault::Encoding),
        ItemRead::Present(child()),
    ];
    let verdicts: Vec<_> = inputs
        .into_iter()
        .map(|row| inspect_child(Some(CHILD), row, CUT, &mut lookup).unwrap())
        .collect();
    assert_eq!(verdicts[0].disposition, ItemDisposition::LiveChild);
    assert_eq!(verdicts[1].disposition, ItemDisposition::UnrestorableChild);
    assert_eq!(verdicts[2].disposition, ItemDisposition::LiveChild);
    assert_eq!(
        verdicts[1].failures,
        [ItemFailure::Corrupt {
            kind: ItemKind::Child,
            key: Some(CHILD),
            reason: IntegrityFault::Encoding,
        }]
    );
    assert!(!verdicts[1].inventory_incomplete);
}

#[test]
fn dangling_claim_reference_is_final_and_other_claims_are_still_checked() {
    let mut row = child();
    row.claims.push([3; 32]);
    let mut lookup = Lookup::default();
    let verdict = inspect_child(Some(CHILD), ItemRead::Present(row), CUT, &mut lookup).unwrap();
    assert_eq!(verdict.disposition, ItemDisposition::UnrestorableChild);
    assert_eq!(
        verdict.failures,
        [
            ItemFailure::Missing {
                kind: ItemKind::Claim,
                key: CLAIM
            },
            ItemFailure::Missing {
                kind: ItemKind::Claim,
                key: [3; 32]
            },
        ]
    );
    assert_eq!(lookup.visits, 2);
}

#[test]
fn wrong_claim_owner_and_birth_fail_child_restore() {
    for owner in [
        None,
        Some(ClaimHolder {
            child: [9; 32],
            birth: 5,
        }),
        Some(ClaimHolder {
            child: CHILD,
            birth: 6,
        }),
    ] {
        let mut row = claim();
        row.owner = owner;
        let mut lookup = Lookup {
            claims: [(CLAIM, ItemRead::Present(row))].into(),
            ..Lookup::default()
        };
        let verdict =
            inspect_child(Some(CHILD), ItemRead::Present(child()), CUT, &mut lookup).unwrap();
        assert_eq!(verdict.disposition, ItemDisposition::UnrestorableChild);
        assert_eq!(
            verdict.failures,
            [ItemFailure::Corrupt {
                kind: ItemKind::Claim,
                key: Some(CLAIM),
                reason: IntegrityFault::Ownership,
            }]
        );
    }
}

#[test]
fn corrupt_claim_is_held_and_never_released() {
    let verdict = inspect_claim(
        Some(CLAIM),
        ItemRead::Corrupt(IntegrityFault::Encoding),
        CUT,
        &mut Lookup::default(),
    )
    .unwrap();
    assert_eq!(verdict.disposition, ItemDisposition::ClaimHeldUnknown);
    assert_eq!(
        verdict.failures,
        [ItemFailure::Corrupt {
            kind: ItemKind::Claim,
            key: Some(CLAIM),
            reason: IntegrityFault::Encoding,
        }]
    );
    assert!(!verdict.inventory_incomplete);
}

#[test]
fn missing_or_corrupt_owner_keeps_claim_held() {
    for row in [
        ItemRead::Missing,
        ItemRead::Corrupt(IntegrityFault::Encoding),
    ] {
        let expected = match row {
            ItemRead::Missing => ItemFailure::Missing {
                kind: ItemKind::Child,
                key: CHILD,
            },
            _ => ItemFailure::Corrupt {
                kind: ItemKind::Child,
                key: Some(CHILD),
                reason: IntegrityFault::Encoding,
            },
        };
        let mut lookup = Lookup {
            children: [(CHILD, row)].into(),
            ..Lookup::default()
        };
        let verdict =
            inspect_claim(Some(CLAIM), ItemRead::Present(claim()), CUT, &mut lookup).unwrap();
        assert_eq!(verdict.disposition, ItemDisposition::ClaimHeldUnknown);
        assert_eq!(verdict.failures, [expected]);
    }
}

#[test]
fn claim_requires_live_matching_birth_and_back_reference() {
    let mut dead = child();
    dead.live = false;
    dead.claims.clear();
    let mut reborn = child();
    reborn.birth += 1;
    let mut no_back_reference = child();
    no_back_reference.claims.clear();
    for row in [dead, reborn, no_back_reference] {
        let mut lookup = Lookup {
            children: [(CHILD, ItemRead::Present(row))].into(),
            ..Lookup::default()
        };
        let verdict =
            inspect_claim(Some(CLAIM), ItemRead::Present(claim()), CUT, &mut lookup).unwrap();
        assert_eq!(verdict.disposition, ItemDisposition::ClaimHeldUnknown);
        assert_eq!(
            verdict.failures,
            [ItemFailure::Corrupt {
                kind: ItemKind::Child,
                key: Some(CHILD),
                reason: IntegrityFault::Ownership,
            }]
        );
    }
    let verdict = inspect_claim(
        Some(CLAIM),
        ItemRead::Present(claim()),
        CUT,
        &mut healthy_lookup(),
    )
    .unwrap();
    assert_eq!(
        verdict.disposition,
        ItemDisposition::ClaimHeld(claim().owner.unwrap())
    );
    assert!(verdict.failures.is_empty());
}

#[test]
fn unreadable_claim_key_marks_incomplete_even_when_body_decodes() {
    let verdict =
        inspect_claim(None, ItemRead::Present(claim()), CUT, &mut healthy_lookup()).unwrap();
    assert_eq!(verdict.disposition, ItemDisposition::ClaimHeldUnknown);
    assert!(verdict.inventory_incomplete);
    assert_eq!(
        verdict.failures,
        [ItemFailure::Corrupt {
            kind: ItemKind::Claim,
            key: None,
            reason: IntegrityFault::Key,
        }]
    );
    let child_verdict =
        inspect_child(None, ItemRead::Present(child()), CUT, &mut healthy_lookup()).unwrap();
    assert_eq!(
        child_verdict.disposition,
        ItemDisposition::UnrestorableChild
    );
    assert!(!child_verdict.inventory_incomplete);
}

#[test]
fn tombstone_released_and_absent_are_distinct_final_results() {
    let mut row = child();
    row.live = false;
    row.claims.clear();
    let mut lookup = Lookup::default();
    let dead = inspect_child(Some(CHILD), ItemRead::Present(row), CUT, &mut lookup).unwrap();
    assert_eq!(dead.disposition, ItemDisposition::ChildTombstone);
    let mut row = claim();
    row.owner = None;
    let released = inspect_claim(Some(CLAIM), ItemRead::Present(row), CUT, &mut lookup).unwrap();
    assert_eq!(released.disposition, ItemDisposition::ClaimReleased);
    let missing = inspect_claim(Some(CLAIM), ItemRead::Missing, CUT, &mut lookup).unwrap();
    assert_eq!(missing.disposition, ItemDisposition::MissingAtCut);
    assert_eq!(
        missing.failures,
        [ItemFailure::Missing {
            kind: ItemKind::Claim,
            key: CLAIM
        }]
    );
    let missing = inspect_child(Some(CHILD), ItemRead::Missing, CUT, &mut lookup).unwrap();
    assert_eq!(missing.disposition, ItemDisposition::MissingAtCut);
    assert_eq!(lookup.visits, 0);
}

#[test]
fn child_header_key_revision_and_birth_must_fit_the_cut() {
    let mut invalid = Vec::new();
    let mut row = child();
    row.key = [9; 32];
    invalid.push(row);
    let mut row = child();
    row.birth = CUT.birth + 1;
    invalid.push(row);
    let mut row = child();
    row.birth = 0;
    invalid.push(row);
    let mut row = child();
    row.generation = 0;
    invalid.push(row);
    let mut row = child();
    row.generation = u64::MAX;
    invalid.push(row);
    let mut row = child();
    row.batch_revision = CUT.batch_revision + 1;
    invalid.push(row);
    let mut row = child();
    row.batch_revision = 0;
    invalid.push(row);
    let mut row = child();
    row.live = false;
    invalid.push(row);
    for row in invalid {
        let mut lookup = healthy_lookup();
        let verdict = inspect_child(Some(CHILD), ItemRead::Present(row), CUT, &mut lookup).unwrap();
        assert_eq!(verdict.disposition, ItemDisposition::UnrestorableChild);
        assert_eq!(verdict.failures.len(), 1);
        assert_eq!(lookup.visits, 0);
    }
}

#[test]
fn claim_header_key_revision_and_owner_bounds_are_conservative() {
    let mut invalid = Vec::new();
    let mut row = claim();
    row.key = [9; 32];
    invalid.push(row);
    let mut row = claim();
    row.revision = 0;
    invalid.push(row);
    let mut row = claim();
    row.revision = CUT.batch_revision + 1;
    invalid.push(row);
    let mut row = claim();
    row.owner.as_mut().unwrap().birth = 0;
    invalid.push(row);
    let mut row = claim();
    row.owner.as_mut().unwrap().birth = CUT.birth + 1;
    invalid.push(row);
    let mut row = claim();
    row.owner.as_mut().unwrap().child = [0; 32];
    invalid.push(row);
    for row in invalid {
        let mut lookup = healthy_lookup();
        let verdict = inspect_claim(Some(CLAIM), ItemRead::Present(row), CUT, &mut lookup).unwrap();
        assert_eq!(verdict.disposition, ItemDisposition::ClaimHeldUnknown);
        assert_eq!(verdict.failures.len(), 1);
        assert_eq!(lookup.visits, 0);
    }
}

#[test]
fn claim_work_and_failure_count_are_bounded_by_eight() {
    let mut row = child();
    row.claims = (2..10).map(|n| [n; 32]).collect();
    let mut lookup = Lookup::default();
    let verdict = inspect_child(
        Some(CHILD),
        ItemRead::Present(row.clone()),
        CUT,
        &mut lookup,
    )
    .unwrap();
    assert_eq!(verdict.failures.len(), 8);
    assert_eq!(lookup.visits, 8);
    row.claims.push([10; 32]);
    let mut lookup = Lookup::default();
    let verdict = inspect_child(Some(CHILD), ItemRead::Present(row), CUT, &mut lookup).unwrap();
    assert_eq!(verdict.disposition, ItemDisposition::UnrestorableChild);
    assert_eq!(verdict.failures.len(), 1);
    assert_eq!(lookup.visits, 0);
}

#[test]
fn duplicate_or_zero_claim_key_is_not_a_valid_child_claim_set() {
    for claims in [vec![CLAIM, CLAIM], vec![[0; 32]]] {
        let mut row = child();
        row.claims = claims;
        let mut lookup = healthy_lookup();
        let verdict = inspect_child(Some(CHILD), ItemRead::Present(row), CUT, &mut lookup).unwrap();
        assert_eq!(verdict.disposition, ItemDisposition::UnrestorableChild);
        assert_eq!(lookup.visits, 0);
    }
}

#[test]
fn interrupted_cross_check_does_not_emit_a_partial_final_item() {
    let mut row = child();
    row.claims.push([3; 32]);
    let mut lookup = Lookup {
        interrupt_at: Some(2),
        ..Lookup::default()
    };
    assert_eq!(
        inspect_child(Some(CHILD), ItemRead::Present(row), CUT, &mut lookup),
        Err("work budget exhausted")
    );
    let mut lookup = Lookup {
        interrupt_at: Some(1),
        ..Lookup::default()
    };
    assert_eq!(
        inspect_claim(Some(CLAIM), ItemRead::Present(claim()), CUT, &mut lookup),
        Err("work budget exhausted")
    );
}
