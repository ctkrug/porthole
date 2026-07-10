use time::{Duration, OffsetDateTime};

/// A single certificate in a chain, as parsed for display and validation.
///
/// `not_before`/`not_after` are `None` for a synthetic trust-anchor root
/// node, which is sourced from the system trust store rather than a full
/// presented certificate and so has no validity window to display.
#[derive(Debug, Clone)]
pub struct CertNode {
    /// Common name of the subject, falling back to the full subject DN if
    /// no CN attribute is present.
    pub subject: String,
    pub subject_dn: String,
    /// Common name of the issuer, falling back to the full issuer DN.
    pub issuer: String,
    pub issuer_dn: String,
    pub serial: String,
    pub pubkey_algorithm: String,
    pub not_before: Option<OffsetDateTime>,
    pub not_after: Option<OffsetDateTime>,
}

impl CertNode {
    pub fn is_expired(&self, now: OffsetDateTime) -> bool {
        self.not_after.is_some_and(|not_after| now > not_after)
    }

    pub fn is_not_yet_valid(&self, now: OffsetDateTime) -> bool {
        self.not_before.is_some_and(|not_before| now < not_before)
    }

    pub fn is_currently_valid(&self, now: OffsetDateTime) -> bool {
        !self.is_expired(now) && !self.is_not_yet_valid(now)
    }

    /// True if the cert is currently valid but will expire within `days`
    /// days of `now` — the "urgent" expiry window. Always false when the
    /// expiry date is unknown.
    pub fn expires_within(&self, now: OffsetDateTime, days: i64) -> bool {
        match self.not_after {
            Some(not_after) => {
                self.is_currently_valid(now) && not_after - now <= Duration::days(days)
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn sample_node() -> CertNode {
        CertNode {
            subject: "example.com".to_string(),
            subject_dn: "CN=example.com".to_string(),
            issuer: "Example CA".to_string(),
            issuer_dn: "CN=Example CA".to_string(),
            serial: "01".to_string(),
            pubkey_algorithm: "RSA".to_string(),
            not_before: Some(datetime!(2026-01-01 0:00 UTC)),
            not_after: Some(datetime!(2027-01-01 0:00 UTC)),
        }
    }

    fn sample_node_without_dates() -> CertNode {
        CertNode { not_before: None, not_after: None, ..sample_node() }
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

    #[test]
    fn expires_within_true_inside_window() {
        let node = sample_node();
        assert!(node.expires_within(datetime!(2026-12-20 0:00 UTC), 14));
    }

    #[test]
    fn expires_within_false_outside_window() {
        let node = sample_node();
        assert!(!node.expires_within(datetime!(2026-06-01 0:00 UTC), 14));
    }

    #[test]
    fn expires_within_false_at_exact_boundary_plus_one_second() {
        let node = sample_node();
        // one second beyond exactly 14 days out should not count as urgent yet
        assert!(!node.expires_within(datetime!(2026-12-17 23:59:59 UTC), 14));
    }

    #[test]
    fn expires_within_true_at_exact_boundary() {
        let node = sample_node();
        // exactly 14 days out is still within the urgent window
        assert!(node.expires_within(datetime!(2026-12-18 0:00 UTC), 14));
    }

    #[test]
    fn expires_within_false_when_already_expired() {
        let node = sample_node();
        assert!(!node.expires_within(datetime!(2027-06-01 0:00 UTC), 14));
    }

    #[test]
    fn no_dates_is_always_currently_valid_and_never_urgent() {
        let node = sample_node_without_dates();
        let now = datetime!(2026-06-01 0:00 UTC);
        assert!(node.is_currently_valid(now));
        assert!(!node.is_expired(now));
        assert!(!node.is_not_yet_valid(now));
        assert!(!node.expires_within(now, 14));
    }
}
