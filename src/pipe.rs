use std::{
    fmt::Display,
    sync::{atomic::AtomicBool, Arc},
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime},
};

use anyhow::Result;

use crate::{
    channel::{Rx, Tx},
    input::Packet,
    output::PacketWriter,
};
// Stats contains statistics about processed packets
pub struct Stats {
    pub packets: u64,
    pub bytes: u64,
    pub start: Instant,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            start: Instant::now(),
            packets: Default::default(),
            bytes: Default::default(),
        }
    }
}

impl Display for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let elapsed = self.start.elapsed();
        let pps = self.packets as f64 / elapsed.as_secs_f64();
        let bps = (self.bytes as f64 * 8_f64) / elapsed.as_secs_f64();
        let mbps = (self.bytes as f64 / (1024 * 1024) as f64) / elapsed.as_secs_f64();

        write!(
            f,
            "{} packets, {} bytes in {}ms / {:.3}pps, {:.3}bps ({:.3} MBps)",
            self.packets,
            self.bytes,
            elapsed.as_millis(),
            pps,
            bps,
            mbps
        )
    }
}

//Pipe can be used to process packets from packet iterator to output
pub struct Pipe {
    wr_handle: JoinHandle<Result<Stats>>,
}

impl Pipe {
    pub fn wait(self) -> Result<Stats> {
        let wr_stat = self.wr_handle.join().unwrap()?;
        trace!("Writer terminated, processed: {}", wr_stat);
        Ok(wr_stat)
    }
}

//Read packets from given input and send them using given Sender
pub fn read_packets_to(
    input: impl Iterator<Item = Packet>,
    tx: &Tx,
    mut stats: Stats,
    terminate: Arc<AtomicBool>,
) -> Result<Stats> {
    for pkt in input {
        stats.packets += 1;
        stats.bytes += pkt.data.len() as u64;
        tx.write_packet(pkt)?;
        if terminate.load(std::sync::atomic::Ordering::Relaxed) {
            error!("terminated!");
            break;
        }
    }

    Ok(stats)
}

// delayer is used to determine how long to delay packet before sending it
trait Delayer {
    // initialize delayer
    fn init(&mut self);
    // how long to wait before writing this packet
    // None to write immediately
    fn wait_time_for(&mut self, pkt: &Packet) -> Option<Duration>;
}

//NoDelay is delayer which will cause every packet to be sent immediately
struct NoDelay {}
impl Delayer for NoDelay {
    fn init(&mut self) {}

    fn wait_time_for(&mut self, _pkt: &Packet) -> Option<Duration> {
        None
    }
}

struct BpsDelay {
    start: Instant,
    bits_sent: u64,
    bps: u64,
}

impl BpsDelay {
    fn new(bps: u64) -> Self {
        BpsDelay {
            start: Instant::now(),
            bits_sent: 0,
            bps,
        }
    }
}

impl Delayer for BpsDelay {
    fn init(&mut self) {
        self.start = Instant::now();
    }

    fn wait_time_for(&mut self, pkt: &Packet) -> Option<Duration> {
        let estimated = Duration::from_micros((self.bits_sent * 1_000_000) / self.bps);
        let elapsed = self.start.elapsed();
        self.bits_sent += pkt.data.len() as u64 * 8;
        if elapsed < estimated {
            Some(estimated - elapsed)
        } else {
            None
        }
    }
}

struct PpsDelay {
    start: Instant,
    packets: u64,
    pps: u64,
}

impl PpsDelay {
    fn new(pps: u32) -> Self {
        PpsDelay {
            start: Instant::now(),
            packets: 0,
            pps: u64::from(pps),
        }
    }
}

impl Delayer for PpsDelay {
    fn init(&mut self) {
        self.start = Instant::now();
    }

    fn wait_time_for(&mut self, _pkt: &Packet) -> Option<Duration> {
        if self.packets == 0 {
            self.packets += 1;
            return None;
        }
        let elapsed = self.start.elapsed();
        // calculate how log it should have taken us to send this many
        // packets.
        let estimated = Duration::from_micros((self.packets * 1_000_000) / self.pps);
        self.packets += 1;
        if estimated > elapsed {
            Some(estimated - elapsed)
        } else {
            // we have not been fast enough, do not wait
            None
        }
    }
}

struct PacketRateDelay {
    last_packet: Option<SystemTime>,
}

impl PacketRateDelay {
    fn new() -> PacketRateDelay {
        PacketRateDelay { last_packet: None }
    }
}

impl Delayer for PacketRateDelay {
    fn init(&mut self) {}

    fn wait_time_for(&mut self, pkt: &Packet) -> Option<Duration> {
        let ret = self
            .last_packet
            .and_then(|t| pkt.when.duration_since(t).ok());
        self.last_packet = Some(pkt.when);
        ret
    }
}

fn write_packets(rx: Rx, mut output: impl PacketWriter, mut delay: impl Delayer) -> Result<Stats> {
    let mut stats: Stats = Default::default();
    delay.init();
    for pkt in rx {
        if let Some(wait_time) = delay.wait_time_for(&pkt) {
            trace!("sleeping {}us before write", wait_time.as_micros());
            thread::sleep(wait_time);
        }
        match output.write_packet(pkt) {
            Ok(len) => {
                stats.packets += 1;
                stats.bytes += len as u64;
            }
            Err(e) => warn!("Unable to write packet: {}", e),
        }
    }
    Ok(stats)
}

fn create_pipe_for(
    rx: Rx,
    output: impl PacketWriter + Send + 'static,
    delayer: impl Delayer + Send + 'static,
) -> Result<Pipe> {
    let wr_handle = thread::Builder::new()
        .name("pkt-writer".to_string())
        .spawn(|| write_packets(rx, output, delayer))?;
    Ok(Pipe { wr_handle })
}

// delaying creates a pipe writing packets from given Rx to given output. The
// packets are written with original rate they were recorded.
pub fn delaying(rx: Rx, output: impl PacketWriter + Send + 'static) -> Result<Pipe> {
    create_pipe_for(rx, output, PacketRateDelay::new())
}

// fullspeed creates a pipe writing packets from given Rx to given output, the
// packets are written out as fast as they are read with no delay between
pub fn fullspeed(rx: Rx, output: impl PacketWriter + Send + 'static) -> Result<Pipe> {
    create_pipe_for(rx, output, NoDelay {})
}

// pps creates a pipe writing packets at constant rate of given number of packets
// per second.
pub fn pps(rx: Rx, output: impl PacketWriter + Send + 'static, pps: u32) -> Result<Pipe> {
    create_pipe_for(rx, output, PpsDelay::new(pps))
}

pub fn bps(rx: Rx, output: impl PacketWriter + Send + 'static, bps: u64) -> Result<Pipe> {
    create_pipe_for(rx, output, BpsDelay::new(bps))
}
