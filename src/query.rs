//! The pure, network-free half of a DNSBL lookup: building the query
//! name and interpreting the result. The real DNS query itself lives in
//! `main.rs`, which is the only part that needs a resolver.

use std::net::Ipv4Addr;

/// Builds the real DNSBL query name for `ip` against `zone` — e.g.
/// `1.2.3.4` against `zen.spamhaus.org` becomes
/// `4.3.2.1.zen.spamhaus.org`, per every real DNSBL's documented
/// reversed-octet convention.
pub fn dnsbl_query_name(ip: Ipv4Addr, zone: &str) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}.{zone}", o[3], o[2], o[1], o[0])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Listing {
    /// NXDOMAIN (or no A records) — the real, standard "not listed"
    /// response every DNSBL uses.
    NotListed,
    /// At least one A record came back, each in the `127.0.0.x`
    /// space DNSBLs use to encode a reason code.
    Listed(Vec<Ipv4Addr>),
}

/// Interprets the raw A-record answers a DNSBL query returned.
pub fn interpret(answers: &[Ipv4Addr]) -> Listing {
    if answers.is_empty() {
        Listing::NotListed
    } else {
        Listing::Listed(answers.to_vec())
    }
}

/// Renders one of a `Listing::Listed` result's `127.0.0.x` return codes
/// into a short human label, per Spamhaus's own publicly documented ZEN
/// return-code table — the two most common codes seen in practice.
/// Anything else is shown as the raw code rather than guessed at.
pub fn describe_code(code: Ipv4Addr) -> String {
    match code.octets() {
        [127, 0, 0, 2] => "SBL — spam source (Spamhaus Block List)".to_string(),
        [127, 0, 0, 3] => "CSS — snowshoe spam".to_string(),
        [127, 0, 0, 4] => "XBL — exploited/compromised host".to_string(),
        [127, 0, 0, n] if (10..=19).contains(&n) => {
            "PBL — policy block list (dynamic/residential range)".to_string()
        }
        other => format!(
            "listed, code {}.{}.{}.{}",
            other[0], other[1], other[2], other[3]
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_the_reversed_octet_query_name() {
        assert_eq!(
            dnsbl_query_name(Ipv4Addr::new(1, 2, 3, 4), "zen.spamhaus.org"),
            "4.3.2.1.zen.spamhaus.org"
        );
    }

    #[test]
    fn reversal_handles_the_documented_rfc5782_test_address() {
        assert_eq!(
            dnsbl_query_name(Ipv4Addr::new(127, 0, 0, 2), "zen.spamhaus.org"),
            "2.0.0.127.zen.spamhaus.org"
        );
    }

    #[test]
    fn empty_answer_set_means_not_listed() {
        assert_eq!(interpret(&[]), Listing::NotListed);
    }

    #[test]
    fn any_answer_means_listed_with_the_codes_preserved() {
        let code = Ipv4Addr::new(127, 0, 0, 2);
        assert_eq!(interpret(&[code]), Listing::Listed(vec![code]));
    }

    #[test]
    fn multiple_answers_all_preserved_in_order() {
        let a = Ipv4Addr::new(127, 0, 0, 2);
        let b = Ipv4Addr::new(127, 0, 0, 4);
        assert_eq!(interpret(&[a, b]), Listing::Listed(vec![a, b]));
    }

    #[test]
    fn describes_known_spamhaus_codes_by_name() {
        assert!(describe_code(Ipv4Addr::new(127, 0, 0, 2)).contains("SBL"));
        assert!(describe_code(Ipv4Addr::new(127, 0, 0, 4)).contains("XBL"));
        assert!(describe_code(Ipv4Addr::new(127, 0, 0, 10)).contains("PBL"));
    }

    #[test]
    fn unknown_code_falls_back_to_the_raw_address_not_a_guess() {
        let desc = describe_code(Ipv4Addr::new(127, 0, 0, 99));
        assert!(desc.contains("127.0.0.99"));
    }
}
