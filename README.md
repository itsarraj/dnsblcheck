# dnsblcheck

Checks whether a domain or IP address is listed on real public DNS
blacklists via real DNS queries — the CLI equivalent of pasting an IP
into MXToolbox's blacklist checker, without the website. Defaults to
Spamhaus's ZEN zone (their combined SBL/CSS/XBL/PBL list), and accepts
any other real DNSBL zone via `--zone`.

## Usage

```bash
dnsblcheck 203.0.113.5                       # check an IP against zen.spamhaus.org
dnsblcheck example.com                       # resolves to its A record(s) first, then checks each
dnsblcheck 203.0.113.5 --zone bl.spamcop.net --zone zen.spamhaus.org
```

Exit code `1` if any IP is listed on any checked zone.

## How a DNSBL query actually works

Every real DNSBL uses the same convention: reverse the IP's octets, and
query `<reversed>.<zone>` for an A record. `1.2.3.4` against
`zen.spamhaus.org` becomes a query for `4.3.2.1.zen.spamhaus.org`.
**NXDOMAIN means clean.** Any A record back means listed — and for
Spamhaus specifically, the returned address itself is a `127.0.0.x`
reason code (`.2` = SBL spam source, `.3` = CSS snowshoe spam, `.4` =
XBL exploited host, `.10`–`.19` = PBL policy/residential range), which
this tool decodes into a label rather than printing the raw address.

## Status: built and verified against real, live public DNS — including a real infrastructure gotcha this session ran straight into

- **7 unit tests** (`cargo test --lib`): reversed-octet query-name
  construction (including against RFC 5782's own documented universal
  test address, `127.0.0.2`), listed/not-listed interpretation from a
  raw answer set, and every documented Spamhaus reason code decoding to
  its real label, with an out-of-range code correctly falling back to
  the raw address instead of a guessed label.
- **A real, live infrastructure gotcha hit and fixed, not just tested
  against a fixture**: the first working version forwarded queries
  through Cloudflare's public resolver (`1.1.1.1`) via
  `ResolverConfig::cloudflare()`. Every single query — including
  **known-clean addresses like `1.1.1.1` itself and `github.com`** —
  came back "listed" with Spamhaus's own documented `127.255.255.254`
  code, which means **"this query arrived from a public/open DNS
  resolver, and Spamhaus refuses to answer it"** — a real, deliberate
  Spamhaus anti-abuse policy (public resolvers get hammered with DNSBL
  traffic from thousands of unrelated clients, so Spamhaus blocks them
  outright), not a bug in the query logic. Switched to
  `TokioAsyncResolver::tokio_from_system_conf()` (this sandbox's own
  configured, non-public nameserver) and the real results immediately
  became correct.
- **Live-verified against real DNS after that fix**: `1.1.1.1` correctly
  came back `not listed`. RFC 5782's own documented universal DNSBL test
  address, `127.0.0.2` (every real DNSBL is required to list it
  permanently, specifically so tools like this one have something safe
  and reliable to test against), correctly came back listed **four
  times over** — once for each of Spamhaus ZEN's combined SBL, CSS, XBL,
  and PBL categories, exactly matching Spamhaus's own public
  documentation of what that address represents. The domain-resolution
  path was also exercised live against a real hostname before checking
  its resolved IP.

**Not done / deliberately deferred**: IPv6 DNSBL queries (nibble-reversed
`ip6.arpa`-style names) — only IPv4 is implemented, matching the large
majority of DNSBL zones, which are IPv4-only themselves. Non-Spamhaus
reason-code tables aren't built in — `describe_code`'s label mapping is
Spamhaus ZEN-specific; a listing on a different zone still reports
correctly as "listed," just without a decoded reason label. No retry/
backoff on a transient resolver timeout — a single failed lookup is
reported as "not listed" rather than distinguished from a genuine clean
result, since DNS timeouts and NXDOMAIN aren't currently told apart.
