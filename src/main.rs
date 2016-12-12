extern crate pnet;
extern crate pcap;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate hex_slice;
extern crate time;
extern crate hdrhistogram;

use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::tcp::TcpOptionNumbers::TIMESTAMPS;
use std::env;
use std::net::{SocketAddr, SocketAddrV4};
use std::collections::{HashMap, BTreeMap};
use std::num::Wrapping;
use time::Timespec;
use hdrhistogram::Histogram;

type FlowKey = (SocketAddr, SocketAddr);

struct Flows {
    flows: HashMap<FlowKey, Flow>,
}

type TSVal = Wrapping<u32>;
struct Flow {
    // this should probably be some kind of cache instead.
    observed: BTreeMap<TSVal, Timespec>,
    seen_value: Option<TSVal>,
    seen_echo: Option<TSVal>,
    histogram_us: Histogram,
}

impl Flows {
    fn new() -> Self {
        Flows { flows: HashMap::new() }
    }

    fn process_from(&mut self, mut rx: pcap::Capture<pcap::Active>) {
        loop {
            match rx.next() {
                Ok(packet) => self.handle_packet(&packet),
                Err(e) => panic!("packetdump: unable to receive packet: {}", e),
            }
        }
    }

    fn handle_packet(&mut self, packet: &pcap::Packet) {
        let ethernet = EthernetPacket::new(packet.data).expect("ethernet packet");
        let now = {
            let ts = packet.header.ts;
            Timespec::new(ts.tv_sec, ts.tv_usec as i32 * 1000)
        };
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

                            print!("@{}.{:09}: {:?}\tts: val: {}; ecr: {}\tseq: {}; ack: {:?} ",
                                    now.sec, now.nsec,
                                   flow,
                                   tsval,
                                   tsecr,
                                   tcp.get_sequence(),
                                   tcp.get_acknowledgement());
                            use  pnet::packet::tcp::TcpFlags::*;
                            for &(chr, flag) in &[('A', ACK), ('C', CWR), ('E', ECE), ('F', FIN),
                                                  ('N', NS), ('P', PSH), ('R', RST), ('S', SYN),
                                                  ('U', URG)] {
                                if (tcp.get_flags() & flag) != 0 {
                                    print!("{}", chr);
                                } else {
                                    print!(".");
                                }
                            }
                            print!("\t");

                            self.flows
                                .entry((src, dst))
                                .or_insert_with(|| Flow::new())
                                .observe_outgoing(now, tsval);
                            self.flows
                                .entry((dst, src))
                                .or_insert_with(|| Flow::new())
                                .observe_echo(now, tsecr);
                            println!("");
                            // println!("Flow: sd:{:?} ds:{:?}", self.flows.get(&(src, dst)), self.flows.get(&(dst, src)));
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

const HALF_U32: TSVal = Wrapping(0x80000000);
const HALF_SUB_EPSILON: TSVal = Wrapping(0x7fffffff);

impl Flow {
    fn new() -> Self {
        Flow {
            observed: BTreeMap::new(),
            seen_value: None,
            seen_echo: None,
            histogram_us: Histogram::init(1, 10_000_000, 2).expect("hdrhistogram"),
        }
    }

    fn observe_outgoing(&mut self, at: Timespec, tsval: u32) {
        let tsval = Wrapping(tsval);
        // If it's before or equal to this value, modulo
        let tsdelta = self.seen_value.map(|v| (tsval - v)).unwrap_or(HALF_SUB_EPSILON);
        // println!("");
        // println!("{:?}", self);
        // println!("val delta:{:08x}", tsdelta);
        if tsdelta < HALF_U32 {
            self.observed.insert(tsval, at);
            self.seen_value = Some(tsval)
        }
    }
    fn observe_echo(&mut self, at: Timespec, tsecr: u32) {
        let tsecr = Wrapping(tsecr);
        let tsdelta = self.seen_echo.map(|v| (tsecr - v)).unwrap_or(HALF_SUB_EPSILON);
        // println!("{:?}", self);
        // println!("ecr delta:{:08x}", tsdelta);
        if tsdelta < HALF_U32 {
            if let Some(stamp) = self.observed.remove(&tsecr) {
                let delta = at - stamp;
                print!("\tRTT: {}", delta);
                if let Some(us) = delta.num_microseconds()
                    .and_then(|v| if v > 0 { Some(v) } else { None }) {
                    self.histogram_us.record_value(us as u64);
                    print!("/{}μs", us as u64);
                    for pct in self.histogram_us.percentile_iter(1) {
                        print!(" {:.3}%:{}μs", pct.percentile, pct.value);
                    }
                }
                self.seen_echo = Some(tsecr);
            }
        }
    }
}

fn main() {
    env_logger::init().expect("env_logger");

    let iface_name = env::args().nth(1).unwrap();
    println!("Using: {:?}", iface_name);

    let rx = pcap::Capture::from_device(&*iface_name)
        .expect("device")
        .tstamp_type(pcap::TstampType::Adapter)
        .open()
        .expect("open dev");

    let mut captor = Flows::new();

    captor.process_from(rx);
}
