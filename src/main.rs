extern crate pnet;
extern crate pcap;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate hex_slice;
extern crate time;
extern crate hdrsample;
extern crate lru_time_cache;
extern crate prometheus;
extern crate protobuf;

use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::tcp::TcpOptionNumbers::TIMESTAMPS;
use std::env;
use std::net::{SocketAddr, SocketAddrV4};
use std::collections::BTreeMap;
use std::num::Wrapping;
use time::{Timespec, SteadyTime, Duration};
use hdrsample::Histogram;
use std::sync::mpsc;
use std::thread;
use std::fmt;
use std::cmp::{Ordering, max};

#[derive(Clone,Eq,PartialEq,Hash)]
struct FlowKey(SocketAddr, SocketAddr);

impl PartialOrd for FlowKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        (self.0.ip(), self.0.port(), self.1.ip(), self.1.port())
            .partial_cmp(&(other.0.ip(), other.0.port(), other.1.ip(), other.1.port()))
    }
}

impl Ord for FlowKey {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.0.ip(), self.0.port(), self.1.ip(), self.1.port())
            .cmp(&(other.0.ip(), other.0.port(), other.1.ip(), other.1.port()))
    }
}

use lru_time_cache::LruCache;

struct Tracker {
    flows: LruCache<FlowKey, Flow>,
    stats: mpsc::SyncSender<StatUpdate>,
}

struct StatsTracker {
    rx: mpsc::Receiver<StatUpdate>,
    stats: LruCache<FlowKey, FlowStat>,
}

type TSVal = Wrapping<u32>;
struct Flow {
    // this should probably be some kind of cache instead.
    observed: BTreeMap<TSVal, Timespec>,
    seen_value: Option<TSVal>,
    seen_echo: Option<TSVal>,
}

struct FlowStat {
    histogram_us: Histogram<u64>,
}

#[derive(Debug,Clone)]
enum StatUpdate {
    TstampVals(SocketAddr, SocketAddr, Duration),
}

impl Tracker {
    fn new(rx: mpsc::SyncSender<StatUpdate>) -> Self {
        Tracker {
            flows: LruCache::with_capacity(1024),
            stats: rx,
        }
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

                            self.flows
                                .entry(FlowKey(src, dst))
                                .or_insert_with(|| Flow::new())
                                .observe_outgoing(now, tsval);
                            let obs = self.flows
                                .entry(FlowKey(dst, src))
                                .or_insert_with(|| Flow::new())
                                .observe_echo(now, tsecr);

                            use  pnet::packet::tcp::TcpFlags::*;
                            trace!("{}:{};\tts: val: {}; ecr: {}\tseq: {}; ack: {:?} \
                                    flags: {}; rtt:{:?}",
                                   src,
                                   dst,
                                   tsval,
                                   tsecr,
                                   tcp.get_sequence(),
                                   tcp.get_acknowledgement(),

                                   &[('A', ACK), ('C', CWR), ('E', ECE), ('F', FIN), ('N', NS),
                                     ('P', PSH), ('R', RST), ('S', SYN), ('U', URG)]
                                       .iter()
                                       .cloned()
                                       .filter_map(|(chr, flag)| {
                                    if (tcp.get_flags() & flag) != 0 {
                                        Some(chr)
                                    } else {
                                        None
                                    }
                                })
                                       .collect::<String>(),
                                   obs);

                            if let Some(obs) = obs {
                                match self.stats.try_send(StatUpdate::TstampVals(src, dst, obs)) {
                                    Ok(_) => (),
                                    Err(mpsc::TrySendError::Full(e)) => warn!("Drop for {:?}", e),
                                    Err(e) => panic!("Unexpected: {:?}", e),
                                }
                            }
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

impl StatsTracker {
    fn new(rx: mpsc::Receiver<StatUpdate>) -> Self {
        StatsTracker {
            rx: rx,
            stats: LruCache::with_capacity(1024),
        }
    }
    fn process_all(&mut self) {
        let mut next_deadline = SteadyTime::now() + Duration::seconds(1);
        loop {
            let now = SteadyTime::now();
            if next_deadline <= now {
                next_deadline = SteadyTime::now() + Duration::seconds(1);
                self.dump_stats();
            }

            let delta = max(next_deadline - now, Duration::seconds(0));
            match self.rx
                .recv_timeout(delta.to_std().expect("std::time")) {
                Ok(StatUpdate::TstampVals(src, dst, delta)) => {
                    let mut ent = self.stats
                        .entry(FlowKey(dst, src))
                        .or_insert_with(|| FlowStat::new());
                    ent.record(delta);
                    debug!("Record: {}:{}; {}", src, dst, ent);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            }
        }
    }
    fn dump_stats(&mut self) {
        use protobuf::RepeatedField;
        use prometheus::{TextEncoder, Encoder};
        use prometheus::proto;
        use std::io::{self, Write};
        let mut metric_families = Vec::new();
        for (&FlowKey(src, dst), stat) in self.stats.iter() {
            info!("{}:{}: {}", src, dst, stat);
            let mut h = proto::Histogram::new();

            let mut cumulative = 0;
            let mut sum = 0f64;
            let mut buckets = Vec::new();
            for (value, _percentile, count, _nsamples) in stat.histogram_us.iter_percentiles(1) {
                cumulative += count;
                sum += value as f64;
                let mut b = proto::Bucket::new();
                b.set_cumulative_count(cumulative);
                b.set_upper_bound(value as f64);
                buckets.push(b);
            }
            h.set_bucket(RepeatedField::from_vec(buckets));
            h.set_sample_sum(sum);
            h.set_sample_count(cumulative);

            let mut metric = proto::Metric::new();
            metric.set_label(RepeatedField::from_vec(vec![
                        ("src_ip", format!("{}", src.ip())),
                        ("dst_ip", format!("{}", dst.ip())),
                        ("src_port", format!("{}", src.port())),
                        ("dst_port", format!("{}", dst.port())),
                            ]
                .into_iter()
                .map(|(k, v)| {
                    let mut lp = proto::LabelPair::new();
                    lp.set_name(k.to_string());
                    lp.set_value(v);
                    lp
                })
                .collect()));
            metric.set_histogram(h);

            let mut mf = proto::MetricFamily::new();
            mf.set_name("tcp_rtt".to_string());
            mf.set_help("TCP Timestamp RTT".to_string());
            mf.set_field_type(proto::MetricType::HISTOGRAM);
            mf.set_metric(RepeatedField::from_vec(vec![metric]));
            metric_families.push(mf)
        }
        let mut buffer = Vec::new();
        let encoder = TextEncoder::new();
        encoder.encode(&metric_families, &mut buffer).expect("encode");
        io::stdout().write_all(&buffer).expect("write");
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
    fn observe_echo(&mut self, at: Timespec, tsecr: u32) -> Option<Duration> {
        let tsecr = Wrapping(tsecr);
        let tsdelta = self.seen_echo.map(|v| (tsecr - v)).unwrap_or(HALF_SUB_EPSILON);
        // println!("{:?}", self);
        // println!("ecr delta:{:08x}", tsdelta);
        if tsdelta < HALF_U32 {
            if let Some(stamp) = self.observed.remove(&tsecr) {
                let delta = at - stamp;

                self.seen_echo = Some(tsecr);
                return Some(delta);
            }
        }
        None
    }
}
impl FlowStat {
    fn new() -> Self {
        FlowStat { histogram_us: Histogram::new(3).expect("hdrhistogram") }
    }

    fn record(&mut self, delta: Duration) {
        if let Some(us) = delta.num_microseconds()
            .and_then(|v| if v > 0 { Some(v) } else { None }) {
            self.histogram_us.record(us).expect("record");
        }
    }
}

impl fmt::Display for FlowStat {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        for (value, percentile, count, _nsamples) in self.histogram_us.iter_percentiles(1) {
            try!(write!(fmt, " {:.3}%/{}:{}μs", percentile, count, value));
        }
        Ok(())
    }
}

fn main() {
    env_logger::init().expect("env_logger");

    let mut args = env::args().skip(1);
    let iface_name = args.next().expect("device name");
    println!("Using: {:?}", iface_name);
    let mut program = String::new();
    for a in args {
        program.push_str(&a);
        program.push(' ');
    }

    let mut pcap = pcap::Capture::from_device(&*iface_name)
        .expect("device")
        .tstamp_type(pcap::TstampType::Adapter)
        .open()
        .expect("open dev");
    if !program.is_empty() {
        pcap.filter(&program).expect("bpf filter");
        println!("Using program: {}", program);
    }

    let (tx, rx) = mpsc::sync_channel(1024);
    let mut captor = Tracker::new(tx);
    let mut stats = StatsTracker::new(rx);
    thread::Builder::new()
        .name("stats".to_string())
        .spawn(move || stats.process_all())
        .expect("thread spawn");

    captor.process_from(pcap);
}
