//! Test-only observations of work performed, independent of reservation formulas.

use super::SubtreeBudget;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Audit {
    pub(crate) phase: &'static str,
    pub(crate) admitted: usize,
    pub(crate) visits: usize,
    pub(crate) comparisons: usize,
    pub(crate) moves: usize,
}

impl Audit {
    pub(crate) fn actual(self) -> usize {
        self.visits
            .checked_add(self.comparisons)
            .and_then(|units| units.checked_add(self.moves))
            .expect("observed work overflow")
    }
}

std::thread_local! {
    static AUDITS: std::cell::RefCell<Vec<Audit>> = const { std::cell::RefCell::new(Vec::new()) };
}

pub(crate) fn take_audits() -> Vec<Audit> {
    AUDITS.with(|audits| std::mem::take(&mut *audits.borrow_mut()))
}

pub(crate) struct Scope {
    budget: SubtreeBudget,
    phase: &'static str,
    remaining: usize,
    observed: [usize; 3],
}

impl Scope {
    pub(super) fn new(budget: &SubtreeBudget, phase: &'static str) -> Self {
        Self {
            budget: budget.clone(),
            phase,
            remaining: budget.remaining(),
            observed: budget.audit_observed(),
        }
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        let observed = self.budget.audit_observed();
        let audit = Audit {
            phase: self.phase,
            admitted: self.remaining - self.budget.remaining(),
            visits: observed[0] - self.observed[0],
            comparisons: observed[1] - self.observed[1],
            moves: observed[2] - self.observed[2],
        };
        AUDITS.with(|audits| audits.borrow_mut().push(audit));
        if !std::thread::panicking() {
            assert!(audit.actual() <= audit.admitted, "{audit:?}");
        }
    }
}

#[test]
fn every_counter_detects_unreserved_work() {
    for operation in 0..3 {
        take_audits();
        let failure = std::panic::catch_unwind(|| {
            let budget = SubtreeBudget::new(1, 0).unwrap();
            let _scope = budget.audit_scope("insufficient admission");
            match operation {
                0 => budget.audit_visit(1),
                1 => {
                    budget.audit_text_cmp("a", "b");
                }
                2 => budget.audit_move(1),
                _ => unreachable!(),
            }
        });
        assert!(
            failure.is_err(),
            "counter {operation} must enforce its reservation"
        );
        let audits = take_audits();
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].admitted, 0);
        assert_eq!(audits[0].actual(), 1);
    }
}
