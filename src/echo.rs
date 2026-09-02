use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use pnet::datalink::{DataLinkReceiver, DataLinkSender};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::{IcmpCode, IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Flags, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::Packet;
use pnet::util::MacAddr;

use crate::Error;

const ETH_HDR: usize = 14;
const IPV4_HDR: usize = 20;
const ICMP_ECHO_HDR: usize = 8;

pub(crate) struct EchoReply {
    pub ttl: u8,
    pub bytes: usize,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn send(
    tx: &mut dyn DataLinkSender,
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    ttl: u8,
    identifier: u16,
    sequence: u16,
    payload_size: usize,
) -> Result<(), Error> {
    let icmp_len = ICMP_ECHO_HDR + payload_size;
    let ip_total_len = IPV4_HDR + icmp_len;
    let frame_len = ETH_HDR + ip_total_len;

    let mut buf = vec![0u8; frame_len];

    {
        let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
        eth.set_destination(dst_mac);
        eth.set_source(src_mac);
        eth.set_ethertype(EtherTypes::Ipv4);
    }

    {
        let mut ip = MutableIpv4Packet::new(&mut buf[ETH_HDR..]).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_dscp(0);
        ip.set_ecn(0);
        ip.set_total_length(ip_total_len as u16);
        ip.set_identification(rand::random());
        ip.set_flags(Ipv4Flags::DontFragment);
        ip.set_fragment_offset(0);
        ip.set_ttl(ttl);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        ip.set_source(src_ip);
        ip.set_destination(dst_ip);
        ip.set_checksum(0);
        let cksum = pnet::packet::ipv4::checksum(&ip.to_immutable());
        ip.set_checksum(cksum);
    }

    let icmp_off = ETH_HDR + IPV4_HDR;
    {
        let mut echo = MutableEchoRequestPacket::new(&mut buf[icmp_off..]).unwrap();
        echo.set_icmp_type(IcmpTypes::EchoRequest);
        echo.set_icmp_code(IcmpCode(0));
        echo.set_identifier(identifier);
        echo.set_sequence_number(sequence);
        let payload: Vec<u8> = (0..payload_size).map(|i| (i & 0xff) as u8).collect();
        echo.set_payload(&payload);
        echo.set_checksum(0);
    }
    let cksum = pnet::packet::icmp::checksum(&IcmpPacket::new(&buf[icmp_off..]).unwrap());
    MutableEchoRequestPacket::new(&mut buf[icmp_off..])
        .unwrap()
        .set_checksum(cksum);

    match tx.send_to(&buf, None) {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(e.into()),
        None => Err(Error::SendDropped),
    }
}

pub(crate) fn wait_for_reply(
    rx: &mut dyn DataLinkReceiver,
    our_ip: Ipv4Addr,
    peer_ip: Ipv4Addr,
    identifier: u16,
    sequence: u16,
    timeout: Duration,
) -> Result<EchoReply, Error> {
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() >= deadline {
            return Err(Error::EchoTimeout(peer_ip, timeout));
        }
        let frame = match rx.next() {
            Ok(f) => f,
            Err(_) => continue,
        };
        let Some(eth) = EthernetPacket::new(frame) else {
            continue;
        };
        if eth.get_ethertype() != EtherTypes::Ipv4 {
            continue;
        }
        let Some(ip) = Ipv4Packet::new(eth.payload()) else {
            continue;
        };
        if ip.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
            continue;
        }
        if ip.get_source() != peer_ip {
            continue;
        }
        if ip.get_destination() != our_ip {
            continue;
        }

        let ihl = ip.get_header_length() as usize * 4;
        let icmp_len = (ip.get_total_length() as usize).saturating_sub(ihl);
        let ip_payload = ip.payload();
        let icmp_slice = &ip_payload[..icmp_len.min(ip_payload.len())];

        let Some(icmp) = IcmpPacket::new(icmp_slice) else {
            continue;
        };
        if icmp.get_icmp_type() != IcmpTypes::EchoReply {
            continue;
        }
        let Some(reply) = EchoReplyPacket::new(icmp_slice) else {
            continue;
        };
        if reply.get_identifier() != identifier {
            continue;
        }
        if reply.get_sequence_number() != sequence {
            continue;
        }
        return Ok(EchoReply {
            ttl: ip.get_ttl(),
            bytes: icmp_len,
        });
    }
}
