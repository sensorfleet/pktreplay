use anyhow::Result;
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::flag;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use clap::{Args, Parser};

mod channel;
mod input;
mod output;
mod pipe;

/// Method to read packets
enum InputMethod {
    /// Read packets from pcap -file
    File(String),
    /// Read packets from interface.
    Interface(String),
}

impl InputMethod {
    /// Creates [input::PcapInput] for this input method.
    fn to_pcap_input(&self) -> Result<input::PcapInput> {
        match self {
            InputMethod::File(fname) => Ok(input::pcap_file(fname)?),
            InputMethod::Interface(ifname) => Ok(input::pcap_interface(ifname)?),
        }
    }
}

/// Packet rate for writing packets
enum Rate {
    /// Write as fast as possible
    Full,
    /// Write with set packet per second
    Pps(u32),
    /// Write given megabits per second.
    Mbps(u64),
    /// Write packets with a delay implied by their timestamps. This is used
    /// when reding from a pcap file and we want to output packets in same
    /// rate as they were saved to the file.
    Delayed,
}

/// Starts task for printing statistics to stdout. Returns [thread::JoinHandle]
/// for created task.
fn start_printer_task(receiver: Receiver<String>) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("stat-reader".to_string())
        .spawn(move || {
            for line in receiver {
                println!("{}", line)
            }
        })
        .unwrap()
}

/// Starts thread to read packets using given [InputMethod].
///
/// Packets read are sent to `tx` and `pipe` should be the [pipe::Pipe] consuming
/// packets.
/// Returns once all packets are read or termination is requested by setting the
/// `terminate` to true
fn input_task(
    method: InputMethod,
    loop_file: bool,
    pipe: pipe::Pipe,
    tx: channel::Tx,
    terminate: Arc<AtomicBool>,
    limit: Option<usize>,
) -> i32 {
    let stop = terminate.clone();
    let rd_handle: thread::JoinHandle<anyhow::Result<()>> = thread::Builder::new()
        .name("pcap-reader".to_string())
        .spawn(move || {
            // set this to true if we are looping and have been able to read
            // the file at least once.
            let mut opened: bool = false;
            loop {
                let input = match method.to_pcap_input() {
                    Ok(input) => {
                        if loop_file {
                            opened = true
                        }
                        Some(input)
                    }
                    Err(err) => {
                        if loop_file && opened {
                            // we have been able to open this file at least
                            // once, thus just terminate the looping if
                            // file has been removed
                            tracing::info!(?err, "looping and file removed?, terminating");
                            None
                        } else {
                            return Err(err);
                        }
                    }
                };
                let Some(inp) = input else {
                    // Input not opened, but do not return error
                    break;
                };

                let it = match limit {
                    Some(n) => Box::new(inp.packets(&stop)?.take(n))
                        as Box<dyn Iterator<Item = input::Packet>>,
                    None => Box::new(inp.packets(&stop)?),
                };
                pipe::read_packets_to(it, &tx)?;
                if !loop_file || stop.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                tracing::info!("pcap file iteration complete");
            }
            Ok(())
        })
        .unwrap();
    let mut ret = 0;
    if let Err(err) = rd_handle.join().unwrap() {
        // if we have received signal indicating we should stop, discard
        // reader errors as the packet writer might have terminated
        // already and reader just complains about closed channel.
        if !terminate.load(std::sync::atomic::Ordering::Relaxed) {
            tracing::error!("Error while reading packets: {}", err);
            ret = -1;
        }
    }
    tracing::trace!("Reader terminated");
    match pipe.wait() {
        Ok(stats) => println!("Write complete: {}", stats),
        Err(err) => {
            tracing::error!("Error while writing packets: {}", err);
            ret = -1
        }
    }
    ret
}

/// Creates a [pipe::Pipe] with given parameters.
fn create_pipe(
    rate: Rate,
    rx: channel::Rx,
    output: impl output::PacketWriter + Send + 'static,
    stats: pipe::Stats,
) -> anyhow::Result<pipe::Pipe> {
    match rate {
        Rate::Full => pipe::fullspeed(rx, output, stats),
        Rate::Delayed => pipe::delaying(rx, output, stats),
        Rate::Mbps(bps) => pipe::bps(rx, output, bps, stats),
        Rate::Pps(pps) => pipe::pps(rx, output, pps, stats),
    }
}

/// Command line parameters for selecting input
#[derive(Args)]
#[group(required = true, multiple = false)]
struct InputParam {
    /// Name of the pcap file to read
    #[arg(long, short = 'f')]
    file: Option<String>,
    /// Read packets from given interface instead of a file
    #[arg[short, long ]]
    interface: Option<String>,
}

impl InputParam {
    /// Returns input method selected
    fn method(&self) -> InputMethod {
        if let Some(ref fname) = self.file {
            InputMethod::File(fname.clone())
        } else if let Some(ref ifname) = self.interface {
            InputMethod::Interface(ifname.clone())
        } else {
            unreachable!()
        }
    }
}

/// Command line parameters for selecting output rate
#[derive(Args)]
#[group(required = false, multiple = false)]
struct RateParam {
    #[arg(short, long)]
    /// Replay packets with given rate of packets per second
    pps: Option<u32>,
    /// Replay packets with given megabits per second
    #[arg(short = 'M', long)]
    mbps: Option<f32>,
    /// Write packets as fast as possible
    #[arg(short = 'F', long)]
    fullspeed: bool,
}

impl RateParam {
    /// Returns proper [Rate] defined by these options.
    fn get_rate(&self) -> Rate {
        if let Some(pps) = self.pps {
            Rate::Pps(pps)
        } else if let Some(mbps) = self.mbps {
            Rate::Mbps((mbps * 1_000_000_f32) as u64)
        } else if self.fullspeed {
            Rate::Full
        } else {
            Rate::Delayed
        }
    }
}

/// Command line parameters
#[derive(Parser)]
#[command(author, version)]
struct Params {
    #[command[flatten]]
    input: InputParam,
    #[command(flatten)]
    rate: RateParam,
    /// Name of the interface to inject packets into. If not given, packets
    /// are written into /dev/null
    #[arg(short, long)]
    output: Option<String>,
    /// Loop pcap file instead of stopping when all packets are read
    #[arg[short, long="loop"]]
    looping: bool,
    /// Low watermark for packet buffer
    #[arg[short = 'L', long]]
    low: Option<u64>,
    /// High watermark for packet buffer
    #[arg(short = 'H', long)]
    high: Option<u64>,
    /// Stop replaying after given number of packets have been replayed
    #[arg[short, long]]
    count: Option<usize>,
    /// Print statistics with interval of given number of seconds
    #[arg[short='S', long]]
    stats: Option<u64>,
}

fn main() {
    tracing_subscriber::fmt::init();
    let params = Params::parse();
    let method = params.input.method();
    let mut rate = params.rate.get_rate();

    let ch_hi: u64 = params.high.unwrap_or(100);
    let ch_low = params.low.unwrap_or(ch_hi / 2);
    if ch_low >= ch_hi {
        tracing::error!("packet buffer low watermark can not be larger than high");
        std::process::exit(-1);
    }

    let terminate = Arc::new(AtomicBool::from(false));
    if let Err(e) = flag::register(SIGINT, Arc::clone(&terminate)) {
        tracing::error!("Unable to register signal handler: {e}");
        std::process::exit(-1);
    }
    if let Err(e) = flag::register(SIGTERM, Arc::clone(&terminate)) {
        tracing::error!("Unable to register signal handler: {e}");
        std::process::exit(-1);
    }

    if matches!(method, InputMethod::Interface(_)) && matches!(rate, Rate::Delayed) {
        // if no pps or bps options are defined and we are reading from interface
        // force the --full which causes packets to be written to the output
        // interface as soon as they are received, which is probably what
        // users would expect.
        rate = Rate::Full;
    }

    let (tx, rx) = channel::create(ch_hi, ch_low, terminate.clone());
    let stat_period = params.stats.map(Duration::from_secs);
    let (stats, stat_printer) = if let Some(period) = stat_period {
        let (s, r) = pipe::Stats::periodic(period);
        (s, Some(start_printer_task(r)))
    } else {
        (pipe::Stats::default(), None)
    };
    let p = if let Some(ref ifname) = params.output {
        output::interface(ifname).and_then(|o| create_pipe(rate, rx, o, stats))
    } else {
        output::sink().and_then(|o| create_pipe(rate, rx, o, stats))
    };

    let ret = match p {
        Ok(pipe) => input_task(method, params.looping, pipe, tx, terminate, params.count),
        Err(e) => {
            tracing::error!("{}", e);
            -1
        }
    };
    // wait for stat printer to terminate
    if let Some(handle) = stat_printer {
        handle.join().unwrap();
    }
    std::process::exit(ret);
}
