/// Keep a worker's absolute deadline paired with the clock that created it.
/// Blocking SQLite callbacks must use the async caller's runtime, including
/// when a test pauses or advances that runtime's clock.
#[derive(Clone)]
pub(crate) enum SqliteWorkDeadline {
    Tokio {
        at: tokio::time::Instant,
        clock: tokio::runtime::Handle,
    },
    // Synchronous SQL oracle/guard tests have no async caller or Tokio clock.
    #[cfg(test)]
    RealTime(std::time::Instant),
}

impl SqliteWorkDeadline {
    pub(crate) fn tokio(at: tokio::time::Instant) -> Self {
        Self::Tokio {
            at,
            clock: tokio::runtime::Handle::current(),
        }
    }

    pub(crate) fn is_elapsed(&self) -> bool {
        match self {
            Self::Tokio { at, clock } => {
                // A callback can run outside the caller's entered context.
                // This guard is local and never crosses an await boundary.
                let _entered = clock.enter();
                tokio::time::Instant::now() >= *at
            }
            #[cfg(test)]
            Self::RealTime(at) => std::time::Instant::now() >= *at,
        }
    }
}
