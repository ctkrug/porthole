/// Whether the origin opts into HTTP Strict Transport Security, and for
/// how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hsts {
    NotSet,
    MaxAge(u64),
}

/// Parse the `Strict-Transport-Security` `max-age` directive out of raw
/// HTTP response header text (one header per line, as delivered on the
/// wire before the blank line that ends the header block).
pub fn parse(headers: &str) -> Hsts {
    for line in headers.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("strict-transport-security") {
            continue;
        }
        if let Some(age) = max_age_directive(value) {
            return Hsts::MaxAge(age);
        }
    }
    Hsts::NotSet
}

fn max_age_directive(header_value: &str) -> Option<u64> {
    header_value
        .split(';')
        .map(str::trim)
        .find_map(|directive| directive.strip_prefix("max-age="))
        .and_then(|age| age.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_headers_is_not_set() {
        assert_eq!(parse(""), Hsts::NotSet);
    }

    #[test]
    fn header_absent_among_others_is_not_set() {
        let headers = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: nginx";
        assert_eq!(parse(headers), Hsts::NotSet);
    }

    #[test]
    fn simple_max_age_is_parsed() {
        let headers = "HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=31536000";
        assert_eq!(parse(headers), Hsts::MaxAge(31_536_000));
    }

    #[test]
    fn max_age_with_extra_directives_is_parsed() {
        let headers = "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload";
        assert_eq!(parse(headers), Hsts::MaxAge(63_072_000));
    }

    #[test]
    fn header_name_is_case_insensitive() {
        let headers = "strict-transport-security: max-age=100";
        assert_eq!(parse(headers), Hsts::MaxAge(100));
    }

    #[test]
    fn directive_order_does_not_matter() {
        let headers = "Strict-Transport-Security: includeSubDomains; max-age=500";
        assert_eq!(parse(headers), Hsts::MaxAge(500));
    }

    #[test]
    fn missing_max_age_directive_is_not_set() {
        let headers = "Strict-Transport-Security: includeSubDomains";
        assert_eq!(parse(headers), Hsts::NotSet);
    }

    #[test]
    fn non_numeric_max_age_is_not_set() {
        let headers = "Strict-Transport-Security: max-age=not-a-number";
        assert_eq!(parse(headers), Hsts::NotSet);
    }

    #[test]
    fn zero_max_age_is_still_a_set_value() {
        // max-age=0 is a valid, meaningful directive (it un-pins HSTS).
        let headers = "Strict-Transport-Security: max-age=0";
        assert_eq!(parse(headers), Hsts::MaxAge(0));
    }

    #[test]
    fn malformed_header_line_without_colon_is_ignored() {
        let headers = "not a real header line\r\nStrict-Transport-Security: max-age=10";
        assert_eq!(parse(headers), Hsts::MaxAge(10));
    }
}
