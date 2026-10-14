//! Independent observations for a single admitted operation.
//!
//! The `testkit` feature enables these observations when a server test links
//! the schema crate as a dependency. Normal builds retain an empty token.

use super::{SubtreeBudget, SubtreeError};

/// Test instrumentation for work covered by one budget deduction.
#[doc(hidden)]
pub struct AdmissionAudit {
    #[cfg(any(test, feature = "testkit"))]
    audit: std::cell::Cell<AdmissionObservation>,
}

/// Recorded logical work, without captured text or identities.
#[cfg(any(test, feature = "testkit"))]
#[derive(Clone, Copy, Debug, Default)]
#[doc(hidden)]
pub struct AdmissionObservation {
    /// Operation whose reservation was observed.
    pub phase: &'static str,
    /// Units actually deducted before the operation.
    pub admitted: usize,
    /// Independent element visits.
    pub visits: usize,
    /// Compared byte positions.
    pub bytes: usize,
    /// Elements or bytes retained by the operation.
    pub moves: usize,
}

#[cfg(any(test, feature = "testkit"))]
impl AdmissionObservation {
    /// Total independently observed logical operations.
    pub fn actual(self) -> usize {
        self.visits
            .checked_add(self.bytes)
            .and_then(|units| units.checked_add(self.moves))
            .expect("observed work overflow")
    }
}

#[cfg(any(test, feature = "testkit"))]
std::thread_local! {
    static AUDITS: std::cell::RefCell<Option<Vec<AdmissionObservation>>> = const { std::cell::RefCell::new(None) };
}

/// Drains this test thread's completed operation observations.
#[cfg(any(test, feature = "testkit"))]
#[doc(hidden)]
pub fn take_admission_observations() -> Vec<AdmissionObservation> {
    AUDITS.with(|audits| audits.borrow_mut().replace(Vec::new()).unwrap_or_default())
}

#[cfg(any(test, feature = "testkit"))]
impl Drop for AdmissionAudit {
    fn drop(&mut self) {
        let audit = self.audit.get();
        AUDITS.with(|audits| {
            if let Some(audits) = &mut *audits.borrow_mut() {
                audits.push(audit);
            }
        });
        if !std::thread::panicking() {
            assert!(audit.actual() <= audit.admitted, "{audit:?}");
        }
    }
}

impl AdmissionAudit {
    pub(super) fn measure(
        _budget: &SubtreeBudget,
        _phase: &'static str,
        charge: impl FnOnce() -> Result<(), SubtreeError>,
    ) -> Result<Self, SubtreeError> {
        #[cfg(any(test, feature = "testkit"))]
        let remaining = _budget.remaining();
        charge()?;
        Ok(Self {
            #[cfg(any(test, feature = "testkit"))]
            audit: std::cell::Cell::new(AdmissionObservation {
                phase: _phase,
                admitted: remaining - _budget.remaining(),
                ..AdmissionObservation::default()
            }),
        })
    }

    /// Observes access to one element, independently of any sizing formula.
    #[inline]
    pub fn visit(&self) {
        #[cfg(any(test, feature = "testkit"))]
        self.audit.update(|mut audit| {
            audit.visits = audit
                .visits
                .checked_add(1)
                .expect("observed visit overflow");
            audit
        });
    }

    /// Observes the actual elements or bytes written by an operation.
    #[inline]
    pub fn moved(&self, _units: usize) {
        #[cfg(any(test, feature = "testkit"))]
        self.audit.update(|mut audit| {
            audit.moves = audit
                .moves
                .checked_add(_units)
                .expect("observed move overflow");
            audit
        });
    }

    /// Visits each element when the consumer actually advances the iterator.
    #[inline]
    pub fn iter<'a, I: IntoIterator>(&'a self, input: I) -> impl Iterator<Item = I::Item> + 'a
    where
        I::IntoIter: 'a,
    {
        input.into_iter().inspect(|_| self.visit())
    }

    /// Observes text supplied to an opaque bounded operation.
    #[inline]
    pub fn bytes_read(&self, _text: &str) {
        #[cfg(any(test, feature = "testkit"))]
        self.audit.update(|mut audit| {
            audit.bytes = audit
                .bytes
                .checked_add(_text.len())
                .expect("observed byte overflow");
            audit
        });
    }

    /// Compares text while counting only the byte positions actually visited.
    #[inline]
    pub fn text_cmp(&self, left: &str, right: &str) -> std::cmp::Ordering {
        #[cfg(any(test, feature = "testkit"))]
        {
            for (left, right) in left.bytes().zip(right.bytes()) {
                self.audit.update(|mut audit| {
                    audit.bytes = audit.bytes.checked_add(1).expect("observed byte overflow");
                    audit
                });
                let order = left.cmp(&right);
                if !order.is_eq() {
                    return order;
                }
            }
            left.len().cmp(&right.len())
        }
        #[cfg(not(any(test, feature = "testkit")))]
        left.cmp(right)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn operation_observations_refuse_an_omitted_charge() {
        for operation in 0..3 {
            take_admission_observations();
            let failure = std::panic::catch_unwind(|| {
                let budget = SubtreeBudget::new(100, 0).unwrap();
                let audit = budget
                    .audit_admission("missing deduction", || Ok(()))
                    .unwrap();
                match operation {
                    0 => audit.visit(),
                    1 => {
                        audit.text_cmp("abc", "abc");
                    }
                    2 => audit.moved(3),
                    _ => unreachable!(),
                }
            });
            assert!(
                failure.is_err(),
                "operation {operation} must require admission"
            );
            let observations = take_admission_observations();
            assert_eq!(observations.len(), 1);
            assert_eq!(observations[0].admitted, 0);
            assert!(observations[0].actual() > 0);
        }
    }

    #[test]
    fn observation_overflow_cannot_turn_an_overrun_into_a_pass() {
        for repeated_move in [false, true] {
            let failure = std::panic::catch_unwind(|| {
                let budget = SubtreeBudget::new(100, 0).unwrap();
                let audit = budget.audit_admission("overflow", || Ok(())).unwrap();
                audit.moved(usize::MAX);
                if repeated_move {
                    audit.moved(1);
                } else {
                    audit.visit();
                }
            });
            assert!(failure.is_err());
        }
    }
}
