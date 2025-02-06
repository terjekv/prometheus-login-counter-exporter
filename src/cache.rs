use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::debug;

/// A cached snapshot of our metrics.
pub struct CachedMetrics {
    pub timestamp: Instant,
    pub metrics: String,
}

impl CachedMetrics {
    /// Returns true if the cached metrics are still valid (i.e. not older than the given interval in milliseconds).
    pub fn is_valid(&self, interval_ms: u64) -> bool {
        let valid = self.timestamp.elapsed() < Duration::from_millis(interval_ms);

        debug!(
            "Checking cache: {} (elapsed) < {} (interval): {}",
            self.timestamp.elapsed().as_millis(),
            interval_ms,
            valid
        );
        valid
    }
}

/// Our cache type is a shared (Arc) Mutex containing an optional CachedMetrics.
pub type Cache = Arc<Mutex<Option<CachedMetrics>>>;

/// Helper to create a new (empty) cache.
pub fn new_cache() -> Cache {
    Arc::new(Mutex::new(None))
}
