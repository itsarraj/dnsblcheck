use std::net::Ipv4Addr;
use std::process::ExitCode;

use clap::Parser;
use dnsblcheck::query::{describe_code, dnsbl_query_name, interpret, Listing};
use hickory_resolver::TokioAsyncResolver;

#[derive(Parser)]
#[command(
    name = "dnsblcheck",
    about = "Checks whether a domain or IP is listed on real public DNS blacklists"
)]
struct Cli {
    /// A domain name (resolved to its A records first) or a plain IPv4 address.
    target: String,
    /// DNSBL zone to check against. Repeatable. Defaults to Spamhaus's ZEN.
    #[arg(long = "zone")]
    zones: Vec<String>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let zones = if cli.zones.is_empty() {
        vec!["zen.spamhaus.org".to_string()]
    } else {
        cli.zones
    };

    let resolver = match TokioAsyncResolver::tokio_from_system_conf() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("dnsblcheck: could not read system DNS config: {e}");
            return ExitCode::FAILURE;
        }
    };

    let ips: Vec<Ipv4Addr> = match cli.target.parse::<Ipv4Addr>() {
        Ok(ip) => vec![ip],
        Err(_) => match resolver.ipv4_lookup(cli.target.as_str()).await {
            Ok(lookup) => lookup.iter().map(|r| r.0).collect(),
            Err(e) => {
                eprintln!("dnsblcheck: could not resolve '{}': {e}", cli.target);
                return ExitCode::FAILURE;
            }
        },
    };

    if ips.is_empty() {
        eprintln!("dnsblcheck: '{}' resolved to no A records", cli.target);
        return ExitCode::FAILURE;
    }

    let mut any_listed = false;
    for ip in &ips {
        for zone in &zones {
            let query_name = dnsbl_query_name(*ip, zone);
            let answers: Vec<Ipv4Addr> = match resolver.ipv4_lookup(query_name.as_str()).await {
                Ok(lookup) => lookup.iter().map(|r| r.0).collect(),
                Err(_) => Vec::new(), // NXDOMAIN (and any other resolution failure) means "not listed"
            };
            match interpret(&answers) {
                Listing::NotListed => println!("{ip} — not listed on {zone}"),
                Listing::Listed(codes) => {
                    any_listed = true;
                    for code in codes {
                        println!("{ip} — LISTED on {zone}: {}", describe_code(code));
                    }
                }
            }
        }
    }

    if any_listed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
