//! Controlled kernel observations through the production Linux adapter.
use super::*;
use crate::scope::IntervalClock;
use opc_linux_clock_sys::status::{STA_NANO, STA_PLL, STA_UNSYNC, TIME_ERROR, TIME_OK};
use std::sync::atomic::{AtomicBool, Ordering};

struct ControlledKernel(Arc<AtomicBool>);
impl KernelReader for ControlledKernel {
    fn sample(&self) -> KernelSample {
        let nanos = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
        let failed = self.0.load(Ordering::Acquire);
        let observation = RealtimeSnapshot {
            state: if failed { TIME_ERROR } else { TIME_OK },
            status: STA_NANO | STA_PLL | if failed { STA_UNSYNC } else { 0 },
            seconds: nanos.div_euclid(1_000_000_000),
            subsecond: nanos.rem_euclid(1_000_000_000),
            maximum_error_micros: 10_000,
            estimated_error_micros: 2_000,
            precision_micros: 1,
            tolerance_scaled_ppm: 32_768_000,
        };
        KernelSample {
            observations: [Ok(observation); 2],
            elapsed: Duration::from_micros(20),
        }
    }
}

pub(crate) struct ClockFixture {
    pub(crate) failed: Arc<AtomicBool>,
    pub(crate) source: Arc<PlatformAuthenticationTimeSource>,
    pub(crate) clock: Arc<IntervalClock>,
}
impl ClockFixture {
    pub(crate) fn new() -> Self {
        let failed = Arc::new(AtomicBool::new(false));
        let source = Arc::new(PlatformAuthenticationTimeSource::with_reader(Arc::new(
            ControlledKernel(failed.clone()),
        )));
        let clock =
            Arc::new(IntervalClock::new(source.clone(), Duration::from_millis(100)).unwrap());
        Self {
            failed,
            source,
            clock,
        }
    }
}
