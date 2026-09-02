use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use pnet::datalink::{DataLinkReceiver, DataLinkSender};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;

use crate::Error;

const ETH_HDR: usize = 14;
const ARP_LEN: usize = 28;

pub(crate) fn resolve(
    tx: &mut dyn DataLinkSender,
    rx: &mut dyn DataLinkReceiver,
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    timeout: Duration,
) -> Result<MacAddr, Error> {
    let mut buf = [0u8; ETH_HDR + ARP_LEN];
    build_request(&mut buf, src_mac, src_ip, target_ip);

    match tx.send_to(&buf, None) {
        Some(Ok(())) => {}
        Some(Err(e)) => return Err(e.into()),
        None => return Err(Error::SendDropped),
    }

    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() >= deadline {
            return Err(Error::ArpTimeout(target_ip, timeout));
        }
        let frame = match rx.next() {
            Ok(f) => f,
            Err(_) => continue,
        };
        let Some(eth) = EthernetPacket::new(frame) else {
            continue;
        };
        if eth.get_ethertype() != EtherTypes::Arp {
            continue;
        }
        let Some(arp) = ArpPacket::new(eth.payload()) else {
            continue;
        };
        if arp.get_operation() != ArpOperations::Reply {
            continue;
        }
        if arp.get_sender_proto_addr() != target_ip {
            continue;
        }
        if arp.get_target_proto_addr() != src_ip {
            continue;
        }
        return Ok(arp.get_sender_hw_addr());
    }
}

fn build_request(buf: &mut [u8], src_mac: MacAddr, src_ip: Ipv4Addr, target_ip: Ipv4Addr) {
    let mut eth = MutableEthernetPacket::new(buf).unwrap();
    eth.set_destination(MacAddr::broadcast());
    eth.set_source(src_mac);
    eth.set_ethertype(EtherTypes::Arp);

    let mut arp = MutableArpPacket::new(eth.payload_mut()).unwrap();
    arp.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp.set_protocol_type(EtherTypes::Ipv4);
    arp.set_hw_addr_len(6);
    arp.set_proto_addr_len(4);
    arp.set_operation(ArpOperations::Request);
    arp.set_sender_hw_addr(src_mac);
    arp.set_sender_proto_addr(src_ip);
    arp.set_target_hw_addr(MacAddr::zero());
    arp.set_target_proto_addr(target_ip);
}
