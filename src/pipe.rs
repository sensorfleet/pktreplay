//! Pipe can be used to write packets to outputs at given rate.
use std::{
    fmt::Display,
    sync::mpsc::{self, Receiver},
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime},
};

use anyhow::Result;

use crate::{
    channel::{Rx, Tx},
    input::Packet,
    output::PacketWriter,
};
/// Statistics about processed packets.
pub struct Stats {
    /// Number of packets processed since start or last reset
    packets: u64,
    /// Number of bytes processed since start or last reset.
    bytes: u64,
    /// Number of packets which we were not able to send.
    invalid: u64,
    /// When packet processing has started.
    start: Instant,
    /// Interval for producing stats
    interval: Option<Duration>,
    /// When stats were last produced
    last_stat: Instant,
    /// [mpsc::Sender] for sending stats summary
    sender: Option<mpsc::Sender<String>>,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            start: Instant::now(),
            last_stat: Instant::now(),
            packets: Default::default(),
            bytes: Default::default(),
            invalid: Default::default(),
            sender: None,
            interval: None,
        }
    }
}

impl Stats {
    /// Updates the statistics with a packet containing given number of bytes.
    /// If `bytes` is 0, this is to indicate that packet was not sent and
    /// should increase the "invalid" packet count.
    ///
    /// Sends summary of statistics if it is time to send them.
    fn update(&mut self, bytes: u64) {
        if bytes == 0 {
            self.invalid += 1
        } else {
            self.packets += 1;
        }
        self.bytes += bytes;
        if let Some(val) = self.interval {
            if self.last_stat.elapsed() > val {
                if let Err(e) = self
                    .sender
                    .as_ref()
                    .unwrap()
                    .send(self.summary(Instant::now()))
                {
                    tracing::warn!("Error while sending stat summary: {}", e)
                }
                self.last_stat = Instant::now();
            }
        }
    }

    /// Returns [String] containing summary of statistics.
    fn summary(&self, when: Instant) -> String {
        let elapsed = when.duration_since(self.start);
        let pps = self.packets as f64 / elapsed.as_secs_f64();
        let bps = (self.bytes as f64 * 8_f64) / elapsed.as_secs_f64();
        let mbps = (self.bytes as f64 / (1024 * 1024) as f64) / elapsed.as_secs_f64();

        let packet_count = match self.invalid {
            0 => format!("{} packets", self.packets),
            _ => format!("{} packets ({} not sent)", self.packets, self.invalid),
        };

        format!(
            "{}, {} bytes in {}ms / {:.3}pps, {:.3}bps ({:.3} MBps)",
            packet_count,
            self.bytes,
            elapsed.as_millis(),
            pps,
            bps,
            mbps
        )
    }

    /// Reset statistics
    fn reset(&mut self) {
        self.bytes = 0;
        self.packets = 0;
        self.invalid = 0;
        self.start = Instant::now();
    }

    /// Creates [Stats] which will send summary with given `period` to
    /// returned receiver.
    pub fn periodic(period: Duration) -> (Stats, Receiver<String>) {
        let (sender, receiver) = mpsc::channel();
        (
            Stats {
                sender: Some(sender),
                interval: Some(period),
                ..Default::default()
            },
            receiver,
        )
    }
}

impl Display for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.summary(Instant::now()))
    }
}

/// Pipe can be used to process packets from packet iterator to output
pub struct Pipe {
    /// Handle for writer thread.
    wr_handle: JoinHandle<Result<Stats>>,
}

impl Pipe {
    /// Waits until packet processor thread for this [Pipe] has stopped.
    pub fn wait(self) -> Result<Stats> {
        let wr_stat = self.wr_handle.join().unwrap()?;
        tracing::trace!("Writer terminated, processed: {}", wr_stat);
        Ok(wr_stat)
    }
}

/// Reads packets from given input and sends them using given Sender
///
/// Given [Stats] are updated with statistics about processed packets.
pub fn read_packets_to(input: impl Iterator<Item = Packet>, tx: &Tx) -> Result<()> {
    for pkt in input {
        tx.write_packet(pkt)?;
    }
    tracing::info!("packet reader terminated");
    Ok(())
}

/// Delayer is used to determine how long to delay packet before sending it
trait Delayer {
    /// Initializes this delayer.
    fn init(&mut self);
    /// Returns how long to wait before writing given [Packet].
    fn wait_time_for(&mut self, pkt: &Packet) -> Option<Duration>;
}

/// [Delayer] which will cause every packet to be sent immediately
struct NoDelay {}
impl Delayer for NoDelay {
    fn init(&mut self) {}

    fn wait_time_for(&mut self, _pkt: &Packet) -> Option<Duration> {
        None
    }
}

/// [Delayer] which will cause to write packets to be written with given
/// bits per second speed.
struct BpsDelay {
    start: Instant,
    bits_sent: u64,
    bps: u64,
}

impl BpsDelay {
    /// Creates new [BpsDelay] with given speed (as in bits per second).
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

/// [Delayer] which will cause to write packets to be written with given
/// packets per second speed.
struct PpsDelay {
    start: Instant,
    packets: u64,
    pps: u64,
}

impl PpsDelay {
    /// Creates new [PpsDelay] with given speed (as in packets per second).
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

/// [Delayer] which will delay packets according to delay on their original
/// timestamps.
///
/// This [Delayer] can be used when reading packets from a pcap -file and
/// it is desired to write them at the same speed as they were captured.
struct PacketRateDelay {
    last_packet: Option<SystemTime>,
}

impl PacketRateDelay {
    /// Returns new [PacketRateDelay]
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

/// Writes packets from `Rx` to `output` using `delay` to manage the speed
/// in which packets are written.
fn write_packets(
    rx: Rx,
    mut output: impl PacketWriter,
    mut delay: impl Delayer,
    mut stats: Stats,
) -> Result<Stats> {
    stats.reset();
    delay.init();
    for pkt in rx {
        if let Some(wait_time) = delay.wait_time_for(&pkt) {
            tracing::trace!("sleeping {}us before write", wait_time.as_micros());
            thread::sleep(wait_time);
        }
        match output.write_packet(pkt) {
            Ok(len) => {
                stats.update(len as u64);
            }
            Err(e) => {
                tracing::error!("Unable to write packet: {}", e);
                break;
            }
        }
    }
    Ok(stats)
}

/// Returns a [Pipe] writing packets from `rx` to `output` using `delayer`.
fn create_pipe_for(
    rx: Rx,
    output: impl PacketWriter + Send + 'static,
    delayer: impl Delayer + Send + 'static,
    stats: Stats,
) -> Result<Pipe> {
    let wr_handle = thread::Builder::new()
        .name("pkt-writer".to_string())
        .spawn(|| write_packets(rx, output, delayer, stats))?;
    Ok(Pipe { wr_handle })
}

/// creates a pipe writing packets from `rx` to `output``.
///
/// The packets are written with original rate they were recorded.
pub fn delaying(rx: Rx, output: impl PacketWriter + Send + 'static, stats: Stats) -> Result<Pipe> {
    create_pipe_for(rx, output, PacketRateDelay::new(), stats)
}

/// Creates a pipe writing packets from `rx` to `output`.
///
/// The packets are written out as fast as they are read with no delay between
pub fn fullspeed(rx: Rx, output: impl PacketWriter + Send + 'static, stats: Stats) -> Result<Pipe> {
    create_pipe_for(rx, output, NoDelay {}, stats)
}

/// Creates a pipe writing packets from `rx` to `output`.
///
/// The packets are written at constant rate of given number of packets
/// per second.
pub fn pps(
    rx: Rx,
    output: impl PacketWriter + Send + 'static,
    pps: u32,
    stats: Stats,
) -> Result<Pipe> {
    create_pipe_for(rx, output, PpsDelay::new(pps), stats)
}

/// Creates a pipe writing packets from `rx` to `output`.
///
/// The packets are written at constant rate of given number of bits
/// per second.
pub fn bps(
    rx: Rx,
    output: impl PacketWriter + Send + 'static,
    bps: u64,
    stats: Stats,
) -> Result<Pipe> {
    create_pipe_for(rx, output, BpsDelay::new(bps), stats)
}
