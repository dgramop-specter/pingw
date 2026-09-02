use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use pingw::{ping_via_gateway, PingOpts};

#[derive(Parser)]
#[command(
    name = "pingw",
    about = "Ping a target IP through a chosen interface + gateway without touching the routing table"
)]
struct Args {
    #[arg(short, long, help = "Interface to send from (e.g. en0, eth0)")]
    interface: String,

    #[arg(short, long, help = "Next-hop gateway IP (must be on-link to the interface)")]
    gateway: Ipv4Addr,

    #[arg(help = "Target IP to ping (e.g. 8.8.8.8)")]
    target: Ipv4Addr,

    #[arg(long, default_value_t = 1000, help = "ARP request timeout in ms")]
    arp_timeout_ms: u64,

    #[arg(long, default_value_t = 2000, help = "ICMP echo reply timeout in ms")]
    reply_timeout_ms: u64,

    #[arg(long, default_value_t = 64, help = "TTL for the outbound IP packet")]
    ttl: u8,

    #[arg(long, default_value_t = 56, help = "ICMP echo data payload size in bytes")]
    payload: usize,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let opts = PingOpts {
        arp_timeout: Duration::from_millis(args.arp_timeout_ms),
        reply_timeout: Duration::from_millis(args.reply_timeout_ms),
        payload_size: args.payload,
        ttl: args.ttl,
        identifier: None,
        sequence: 1,
    };

    match ping_via_gateway(&args.interface, args.gateway, args.target, &opts) {
        Ok(r) => {
            println!(
                "{} bytes from {} via {} ({}): icmp_seq={} ttl={} time={:.2} ms",
                r.bytes,
                args.target,
                args.gateway,
                r.gateway_mac,
                r.sequence,
                r.reply_ttl,
                r.rtt.as_secs_f64() * 1000.0,
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("pingw: {}", e);
            ExitCode::from(1)
        }
    }
}
