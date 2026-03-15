//! Static-level datatypes.
//! A data type is considered "static" if it can be inferred at or before
//! the first packet in a connection and it stays constant throughout a connection.
//! See datatypes, including foreign types, that implement [StaticData](trait.StaticData.html).

use super::StaticData;
#[allow(unused_imports)]
use iris_compiler::datatype;
use iris_core::conntrack::conn_id::FiveTuple;
use iris_core::conntrack::pdu::L4Pdu;
use pnet::datalink::MacAddr;

/// Subscribable alias for [`iris_core::FiveTuple`]
impl StaticData for FiveTuple {
    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype("name=FiveTuple,level=L4FirstPacket")
    )]
    fn new(first_pkt: &L4Pdu) -> Self {
        FiveTuple::from_ctxt(first_pkt.ctxt)
    }
}

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

// /24 and /64
const V4_MASK: u32 = u32::MAX << (32 - 24);
const V6_BYTES: usize = 8;
const V6_BYTES_LEN: usize = 16;

#[derive(Debug)]
pub struct AnonFiveTuple {
    pub data: FiveTuple,
}

impl AnonFiveTuple {
    fn hash_ip(ip: &IpAddr) -> IpAddr {
        match ip {
            IpAddr::V4(addr) => {
                let octets = addr.octets();
                let addr_u32 = u32::from_be_bytes(octets);
                let mut hasher = DefaultHasher::new();
                addr.hash(&mut hasher);
                let hash = hasher.finish() as u32;
                IpAddr::V4(Ipv4Addr::from((addr_u32 & V4_MASK) | (hash & !V4_MASK)))
            }
            IpAddr::V6(addr) => {
                let mut hasher = DefaultHasher::new();
                addr.hash(&mut hasher);
                let hash = hasher.finish().to_be_bytes();
                let mut addr = addr.octets();
                for i in V6_BYTES..V6_BYTES_LEN {
                    addr[i] = hash[i % hash.len()];
                }
                IpAddr::V6(Ipv6Addr::from(addr))
            }
        }
    }
}

impl StaticData for AnonFiveTuple {
    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype("name=AnonFiveTuple,level=L4FirstPacket")
    )]
    fn new(first_pkt: &L4Pdu) -> Self {
        let mut five_tuple = FiveTuple::from_ctxt(first_pkt.ctxt.clone());
        five_tuple.orig.set_ip(Self::hash_ip(&five_tuple.orig.ip()));
        Self { data: five_tuple }
    }
}

/// Five-tuple with LSBs cleared for anonymization.
/// This preserves subnet structure.
#[derive(Debug)]
pub struct ClearedFiveTuple {
    pub data: FiveTuple,
}

impl ClearedFiveTuple {
    fn clear(ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V4(addr) => {
                let addr = u32::from_be_bytes(addr.octets());
                IpAddr::V4(Ipv4Addr::from(addr & V4_MASK))
            }
            IpAddr::V6(addr) => {
                let mut addr = addr.octets();
                for i in 1..V6_BYTES + 1 {
                    addr[V6_BYTES_LEN - i] = 0;
                }
                IpAddr::V6(Ipv6Addr::from(addr))
            }
        }
    }
}

impl StaticData for ClearedFiveTuple {
    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype("name=ClearedFiveTuple,level=L4FirstPacket")
    )]
    fn new(first_pkt: &L4Pdu) -> Self {
        let mut five_tuple = FiveTuple::from_ctxt(first_pkt.ctxt.clone());
        five_tuple.orig.set_ip(Self::clear(five_tuple.orig.ip()));
        five_tuple.resp.set_ip(Self::clear(five_tuple.resp.ip()));
        Self { data: five_tuple }
    }
}

pub type StartTime = Instant;

impl StaticData for StartTime {
    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype("name=StartTime,level=L4FirstPacket")
    )]
    fn new(first_pkt: &L4Pdu) -> Self {
        first_pkt.ts.clone()
    }
}

use iris_core::protocols::packet::{ethernet::Ethernet, Packet};

/// Tag Control Information field on the first packet, or none
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EtherTCI(Option<u16>);

impl StaticData for EtherTCI {
    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype("name=EtherTCI,level=L4FirstPacket")
    )]
    fn new(first_pkt: &L4Pdu) -> Self {
        if let Ok(ethernet) = &Packet::parse_to::<Ethernet>(first_pkt.mbuf_ref()) {
            if let Some(tci) = ethernet.tci() {
                return EtherTCI(Some(tci));
            }
        }
        EtherTCI(None)
    }
}

/// The src/dst MAC of a connection
#[derive(Clone, Debug)]
pub struct EthAddr {
    pub src: MacAddr,
    pub dst: MacAddr,
}

impl StaticData for EthAddr {
    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype("name=EthAddr,level=L4FirstPacket")
    )]
    fn new(first_pkt: &L4Pdu) -> Self {
        if let Ok(ethernet) = &Packet::parse_to::<Ethernet>(first_pkt.mbuf_ref()) {
            Self {
                src: ethernet.src(),
                dst: ethernet.dst(),
            }
        } else {
            panic!("Non-ethernet packets not supported");
        }
    }
}
