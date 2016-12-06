extern crate pnet;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate hex_slice;
extern crate time;

use pnet::datalink::{self, NetworkInterface};

use pnet::packet::Packet;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::datalink::EthernetDataLinkReceiver;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::PacketSize;
use pnet::packet::tcp::TcpOptionNumbers::TIMESTAMPS;
use std::env;
use std::net::{SocketAddr, SocketAddrV4};
use std::collections::{HashMap, BTreeMap};
use std::num::Wrapping;
use hex_slice::AsHex;
use time::{SteadyTime, Duration};

type FlowKey = (SocketAddr, SocketAddr);

struct Flows {
    flows: HashMap<FlowKey, Flow>,
}

type TSVal = Wrapping<u32>;
#[derive(Debug)]
struct Flow {
    // this should probably be some kind of cache instead.
    observed: BTreeMap<TSVal, SteadyTime>,
    seen_value: Option<TSVal>,
    seen_echo: Option<TSVal>,
}

impl Flows {
    fn new() -> Self {
        Flows { flows: HashMap::new() }
    }

    fn now(&self) -> SteadyTime {
        SteadyTime::now()
    }

    fn process_from(&mut self, mut rx: Box<EthernetDataLinkReceiver>) {
        let mut iter = rx.iter();
        loop {
            match iter.next() {
                Ok(packet) => self.handle_packet(&packet),
                Err(e) => panic!("packetdump: unable to receive packet: {}", e),
            }
        }
    }

    fn handle_packet(&mut self, ethernet: &EthernetPacket) {
        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => {
                if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                    match ipv4.get_next_level_protocol() {
                        IpNextHeaderProtocols::Tcp => (),
                        other => {
                            warn!("Ignoring: {:?}", other);
                            return;
                        }
                    };

                    if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                        let src = SocketAddr::V4(SocketAddrV4::new(ipv4.get_source(),
                                                                   tcp.get_source()));
                        let dst = SocketAddr::V4(SocketAddrV4::new(ipv4.get_destination(),
                                                                   tcp.get_destination()));
                        let flow = (src, dst);

                        // println!("{:?}: expected sz: {:?}; len: {:?}", flow, tcp.packet_size(), ipv4.packet().len());

                        if let Some(ts) = tcp.get_options_iter()
                            .filter(|o| o.get_number() == TIMESTAMPS)
                            .next() {
                            let p = ts.payload();
                            let tsval = (p[0] as u32) << 24 | (p[1] as u32) << 16 |
                                        (p[2] as u32) << 8 |
                                        (p[3] as u32) << 0;
                            let tsecr = (p[4] as u32) << 24 | (p[5] as u32) << 16 |
                                        (p[6] as u32) << 8 |
                                        (p[7] as u32) << 0;

                            let t = self.now();
                            println!("{:?}\ttimestamps: val: {}; ecr: {}\tat: {:?}",
                                     flow,
                                     tsval,
                                     tsecr,
                                     t);

                            self.flows
                                .entry((src, dst))
                                .or_insert_with(|| Flow::new())
                                .observe_outgoing(t, tsval);
                            self.flows
                                .entry((dst, src))
                                .or_insert_with(|| Flow::new())
                                .observe_echo(t, tsecr);
                        } else {
                            // Approxmate using sequence numbers?
                        }
                    }
                }
            }
            EtherTypes::Ipv6 => {
                warn!("Ignoring ipv6");
            }
            other => {
                warn!("Ignoring: {:?}", other);
            }
        };
    }
}

const HALF_U32: TSVal = Wrapping(0x8000000);

impl Flow {
    fn new() -> Self {
        Flow {
            observed: BTreeMap::new(),
            seen_value: None,
            seen_echo: None,
        }
    }

    fn observe_outgoing(&mut self, at: SteadyTime, tsval: u32) {
        // println!("outgoing: {:?}; {:?}", self, tsval);
        let tsval = Wrapping(tsval);
        // If it's before or equal to this value, modulo
        if self.seen_value.map(|v| (tsval - v) < HALF_U32).unwrap_or(true) {
            self.observed.insert(tsval, at);
            self.seen_value = Some(tsval)
        }
    }
    fn observe_echo(&mut self, at: SteadyTime, tsecr: u32) {
        // println!("echo: {:?}; {:?}", self, tsecr);
        let tsecr = Wrapping(tsecr);
        if self.seen_echo.map(|v| (tsecr - v) < HALF_U32).unwrap_or(true) {
            if let Some(stamp) = self.observed.remove(&tsecr) {
                let delta = at - stamp;
                println!("\tRTT: {}", delta);
            }
        }
    }
}

fn main() {
    use pnet::datalink::Channel::Ethernet;
    env_logger::init().expect("env_logger");

    let iface_name = env::args().nth(1).unwrap();
    println!("Using: {:?}", iface_name);
    let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    println!("Found interfaces: {:?}", interfaces);
    let interface = interfaces.into_iter().filter(interface_names_match).next().unwrap();

    // Create a channel to receive on
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packetdump: unhandled channel type: {}"),
        Err(e) => panic!("packetdump: unable to create channel: {}", e),
    };

    let mut captor = Flows::new();

    captor.process_from(rx);
}
