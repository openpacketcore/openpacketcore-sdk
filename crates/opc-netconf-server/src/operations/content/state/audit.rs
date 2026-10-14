//! Logical provider work; counters and enforcement exist only in unit tests.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use opc_mgmt_schema::subtree::{SubtreeBudget, SubtreeError};

pub(super) struct Reservation {
    #[cfg(test)]
    audit: std::cell::Cell<Audit>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Audit {
    pub(super) phase: &'static str,
    pub(super) admitted: usize,
    pub(super) visits: usize,
    pub(super) comparisons: usize,
    pub(super) bytes: usize,
    pub(super) moves: usize,
}

#[cfg(test)]
impl Audit {
    pub(super) fn actual(self) -> usize {
        [self.visits, self.comparisons, self.bytes, self.moves]
            .into_iter()
            .try_fold(0usize, usize::checked_add)
            .expect("provider work overflow")
    }
}

#[cfg(test)]
std::thread_local! {
    static AUDITS: std::cell::RefCell<Vec<Audit>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
pub(super) fn take_audits() -> Vec<Audit> {
    AUDITS.with(|audits| std::mem::take(&mut *audits.borrow_mut()))
}

#[cfg(test)]
impl Drop for Reservation {
    fn drop(&mut self) {
        let audit = self.audit.get();
        AUDITS.with(|audits| audits.borrow_mut().push(audit));
        if !std::thread::panicking() {
            assert!(audit.actual() <= audit.admitted, "{audit:?}");
        }
    }
}

impl Reservation {
    pub(super) fn admit(
        budget: &SubtreeBudget,
        units: usize,
        _phase: &'static str,
    ) -> Result<Self, SubtreeError> {
        budget.charge(units)?;
        Ok(Self {
            #[cfg(test)]
            audit: std::cell::Cell::new(Audit {
                phase: _phase,
                admitted: units,
                ..Audit::default()
            }),
        })
    }

    pub(super) fn visit(&self) {
        #[cfg(test)]
        self.audit.update(|mut audit| {
            audit.visits = audit.visits.checked_add(1).expect("visit overflow");
            audit
        });
    }

    pub(super) fn compared(&self) {
        #[cfg(test)]
        self.audit.update(|mut audit| {
            audit.comparisons = audit
                .comparisons
                .checked_add(1)
                .expect("comparison overflow");
            audit
        });
    }

    pub(super) fn moved(&self, _units: usize) {
        #[cfg(test)]
        self.audit.update(|mut audit| {
            audit.moves = audit.moves.checked_add(_units).expect("move overflow");
            audit
        });
    }

    pub(super) fn text_cmp(&self, left: &str, right: &str) -> std::cmp::Ordering {
        #[cfg(test)]
        {
            for (left, right) in left.bytes().zip(right.bytes()) {
                self.audit.update(|mut audit| {
                    audit.bytes = audit
                        .bytes
                        .checked_add(1)
                        .expect("byte comparison overflow");
                    audit
                });
                let order = left.cmp(&right);
                if !order.is_eq() {
                    return order;
                }
            }
            left.len().cmp(&right.len())
        }
        #[cfg(not(test))]
        left.cmp(right)
    }
}

#[test]
fn every_provider_counter_detects_unreserved_work() {
    for operation in 0..4 {
        take_audits();
        let failure = std::panic::catch_unwind(|| {
            let budget = SubtreeBudget::new(1, 0).unwrap();
            let reservation = Reservation::admit(&budget, 0, "insufficient admission").unwrap();
            match operation {
                0 => reservation.visit(),
                1 => reservation.compared(),
                2 => {
                    reservation.text_cmp("a", "b");
                }
                3 => reservation.moved(1),
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
