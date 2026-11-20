use std::time::{Duration, Instant};

/// Token bucket for session joins. A real player joins a handful of servers
/// and a few mods authenticate to their backends; a rat abusing the session
/// to log the account into somewhere else hits the ceiling quickly
#[derive(Debug)]
pub struct JoinLimiter {
    capacity: f64,
    tokens: f64,
    per_token: Duration,
    last: Instant,
}

impl JoinLimiter {
    /// Burst of 8, then one join every two minutes (30 an hour)
    pub fn standard() -> Self {
        Self::new(8, Duration::from_secs(120))
    }

    pub fn new(capacity: u32, per_token: Duration) -> Self {
        Self {
            capacity: f64::from(capacity),
            tokens: f64::from(capacity),
            per_token,
            last: Instant::now(),
        }
    }

    pub fn try_take(&mut self) -> bool {
        self.try_take_at(Instant::now())
    }

    fn try_take_at(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last);
        self.last = now;
        self.tokens =
            (self.tokens + elapsed.as_secs_f64() / self.per_token.as_secs_f64()).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_a_burst_then_refills_slowly() {
        let start = Instant::now();
        let mut limiter = JoinLimiter::new(2, Duration::from_secs(60));
        limiter.last = start;

        assert!(limiter.try_take_at(start));
        assert!(limiter.try_take_at(start));
        assert!(!limiter.try_take_at(start + Duration::from_secs(30)));
        assert!(limiter.try_take_at(start + Duration::from_secs(61)));
        assert!(!limiter.try_take_at(start + Duration::from_secs(62)));
    }
}
