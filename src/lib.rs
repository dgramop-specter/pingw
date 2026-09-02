mod arp;
mod echo;

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use pnet::datalink::{self, Config};
use pnet::ipnetwork::IpNetwork;
use pnet::util::MacAddr;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct PingOpts {
    pub arp_timeout: Duration,
    pub reply_timeout: Duration,
    pub payload_size: usize,
    pub ttl: u8,
    pub identifier: Option<u16>,
    pub sequence: u16,
}

impl Default for PingOpts {
    fn default() -> Self {
        Self {
            arp_timeout: Duration::from_secs(1),
            reply_timeout: Duration::from_secs(2),
            payload_size: 56,
            ttl: 64,
            identifier: None,
            sequence: 1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PingResult {
    pub gateway_mac: MacAddr,
    pub reply_ttl: u8,
    pub rtt: Duration,
    pub bytes: usize,
    pub identifier: u16,
    pub sequence: u16,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("interface `{0}` not found")]
    InterfaceNotFound(String),
    #[error("interface `{0}` has no MAC address")]
    NoMacAddress(String),
    #[error("interface `{0}` has no IPv4 address")]
    NoIpv4Address(String),
    #[error("unsupported datalink channel type for interface `{0}` (not Ethernet)")]
    UnsupportedChannel(String),
    #[error("ARP request for {0} timed out after {1:?}")]
    ArpTimeout(Ipv4Addr, Duration),
    #[error("ICMP echo reply from {0} timed out after {1:?}")]
    EchoTimeout(Ipv4Addr, Duration),
    #[error("datalink send returned no result (interface buffer full?)")]
    SendDropped,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub fn ping_via_gateway(
    interface_name: &str,
    gateway: Ipv4Addr,
    target: Ipv4Addr,
    opts: &PingOpts,
) -> Result<PingResult, Error> {
    let iface = datalink::interfaces()
        .into_iter()
        .find(|i| i.name == interface_name)
        .ok_or_else(|| Error::InterfaceNotFound(interface_name.to_string()))?;

    let src_mac = iface
        .mac
        .ok_or_else(|| Error::NoMacAddress(interface_name.to_string()))?;

    let src_ip = iface
        .ips
        .iter()
        .find_map(|ip| match ip {
            IpNetwork::V4(v4) => Some(v4.ip()),
            _ => None,
        })
        .ok_or_else(|| Error::NoIpv4Address(interface_name.to_string()))?;

    let cfg = Config {
        read_timeout: Some(Duration::from_millis(100)),
        ..Config::default()
    };

    let (mut tx, mut rx) = match datalink::channel(&iface, cfg)? {
        datalink::Channel::Ethernet(tx, rx) => (tx, rx),
        _ => return Err(Error::UnsupportedChannel(interface_name.to_string())),
    };

    let gw_mac = arp::resolve(
        tx.as_mut(),
        rx.as_mut(),
        src_mac,
        src_ip,
        gateway,
        opts.arp_timeout,
    )?;

    let identifier = opts.identifier.unwrap_or_else(rand::random);

    let sent_at = Instant::now();
    echo::send(
        tx.as_mut(),
        src_mac,
        gw_mac,
        src_ip,
        target,
        opts.ttl,
        identifier,
        opts.sequence,
        opts.payload_size,
    )?;

    let reply = echo::wait_for_reply(
        rx.as_mut(),
        src_ip,
        target,
        identifier,
        opts.sequence,
        opts.reply_timeout,
    )?;
    let rtt = sent_at.elapsed();

    Ok(PingResult {
        gateway_mac: gw_mac,
        reply_ttl: reply.ttl,
        rtt,
        bytes: reply.bytes,
        identifier,
        sequence: opts.sequence,
    })
}
