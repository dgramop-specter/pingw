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

struct EchoFrame {
    buf: Vec<u8>,
}

impl EchoFrame {
    const IP_OFF: usize = ETH_HDR;
    const ICMP_OFF: usize = ETH_HDR + IPV4_HDR;

    fn with_payload(payload_size: usize) -> Self {
        Self {
            buf: vec![0u8; Self::ICMP_OFF + ICMP_ECHO_HDR + payload_size],
        }
    }

    fn write_ethernet(&mut self, src: MacAddr, dst: MacAddr) {
        let mut eth = MutableEthernetPacket::new(&mut self.buf).unwrap();
        eth.set_source(src);
        eth.set_destination(dst);
        eth.set_ethertype(EtherTypes::Ipv4);
    }

    fn write_ipv4(&mut self, src: Ipv4Addr, dst: Ipv4Addr, ttl: u8) {
        let total_len = (self.buf.len() - Self::IP_OFF) as u16;
        let mut ip = MutableIpv4Packet::new(&mut self.buf[Self::IP_OFF..]).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(total_len);
        ip.set_identification(rand::random());
        ip.set_flags(Ipv4Flags::DontFragment);
        ip.set_ttl(ttl);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        ip.set_source(src);
        ip.set_destination(dst);
        ip.set_checksum(0);
        let cksum = pnet::packet::ipv4::checksum(&ip.to_immutable());
        ip.set_checksum(cksum);
    }

    fn write_icmp_echo(&mut self, id: u16, seq: u16) {
        let payload_size = self.buf.len() - Self::ICMP_OFF - ICMP_ECHO_HDR;
        {
            let mut echo =
                MutableEchoRequestPacket::new(&mut self.buf[Self::ICMP_OFF..]).unwrap();
            echo.set_icmp_type(IcmpTypes::EchoRequest);
            echo.set_icmp_code(IcmpCode(0));
            echo.set_identifier(id);
            echo.set_sequence_number(seq);
            let payload: Vec<u8> = (0..payload_size).map(|i| (i & 0xff) as u8).collect();
            echo.set_payload(&payload);
            echo.set_checksum(0);
        }
        let cksum =
            pnet::packet::icmp::checksum(&IcmpPacket::new(&self.buf[Self::ICMP_OFF..]).unwrap());
        MutableEchoRequestPacket::new(&mut self.buf[Self::ICMP_OFF..])
            .unwrap()
            .set_checksum(cksum);
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buf
    }
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
    let mut frame = EchoFrame::with_payload(payload_size);
    frame.write_ethernet(src_mac, dst_mac);
    frame.write_ipv4(src_ip, dst_ip, ttl);
    frame.write_icmp_echo(identifier, sequence);

    match tx.send_to(frame.as_bytes(), None) {
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
