use time::OffsetDateTime;

/// A single certificate in a chain, as parsed for display and validation.
///
/// Constructed once TLS chain capture lands; unused until then.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct CertNode {
    pub subject: String,
    pub issuer: String,
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
}

#[allow(dead_code)]
impl CertNode {
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        now > self.not_after
    }

    pub fn is_not_yet_valid(&self, now: OffsetDateTime) -> bool {
        now < self.not_before
    }

    pub fn is_currently_valid(&self, now: OffsetDateTime) -> bool {
        !self.is_expired(now) && !self.is_not_yet_valid(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn sample_node() -> CertNode {
        CertNode {
            subject: "example.com".to_string(),
            issuer: "Example CA".to_string(),
            not_before: datetime!(2026-01-01 0:00 UTC),
            not_after: datetime!(2027-01-01 0:00 UTC),
        }
    }

    #[test]
    fn valid_within_window() {
        let node = sample_node();
        assert!(node.is_currently_valid(datetime!(2026-06-01 0:00 UTC)));
    }

    #[test]
    fn expired_after_not_after() {
        let node = sample_node();
        assert!(node.is_expired(datetime!(2027-06-01 0:00 UTC)));
        assert!(!node.is_currently_valid(datetime!(2027-06-01 0:00 UTC)));
    }

    #[test]
    fn not_yet_valid_before_not_before() {
        let node = sample_node();
        assert!(node.is_not_yet_valid(datetime!(2025-06-01 0:00 UTC)));
        assert!(!node.is_currently_valid(datetime!(2025-06-01 0:00 UTC)));
    }
}
