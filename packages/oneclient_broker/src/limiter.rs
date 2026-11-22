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
    paused: bool,
}

/// What [`JoinLimiter::try_take`] decided
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Take {
    Allowed,
    /// Refused; `first` for the first refusal since the last allowed join,
    /// so a mod retrying in a loop is reported once rather than every time
    Paused {
        first: bool,
    },
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
            paused: false,
        }
    }

    pub fn try_take(&mut self) -> Take {
        self.try_take_at(Instant::now())
    }

    fn try_take_at(&mut self, now: Instant) -> Take {
        let elapsed = now.saturating_duration_since(self.last);
        self.last = now;
        self.tokens =
            (self.tokens + elapsed.as_secs_f64() / self.per_token.as_secs_f64()).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            self.paused = false;
            Take::Allowed
        } else {
            let first = !self.paused;
            self.paused = true;
            Take::Paused { first }
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

        assert_eq!(limiter.try_take_at(start), Take::Allowed);
        assert_eq!(limiter.try_take_at(start), Take::Allowed);
        let later = |secs| start + Duration::from_secs(secs);
        assert_eq!(limiter.try_take_at(later(30)), Take::Paused { first: true });
        assert_eq!(
            limiter.try_take_at(later(31)),
            Take::Paused { first: false }
        );
        assert_eq!(limiter.try_take_at(later(61)), Take::Allowed);
        assert_eq!(limiter.try_take_at(later(62)), Take::Paused { first: true });
    }
}
