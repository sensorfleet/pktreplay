use anyhow::Result;
use signal_hook::consts::SIGINT;
use signal_hook::flag;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

mod channel;
mod input;
mod output;
mod pipe;

// Defines the method to read packets.
enum InputMethod {
    File(String),
    Interface(String),
}

impl InputMethod {
    // create PcapInput for this method
    fn to_pcap_input(&self) -> Result<input::PcapInput> {
        match self {
            InputMethod::File(fname) => Ok(input::pcap_file(fname)?),
            InputMethod::Interface(ifname) => Ok(input::pcap_interface(ifname)?),
        }
    }
}

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

// starts thread to read packets using given input method.
// Packets read are sent using `tx` and `pipe` should be the pipe consuming
// packets.
// Returns once all packets are read or termination is requested by setting the
// `terminate` to true
fn input_task(
    method: InputMethod,
    loop_file: bool,
    pipe: pipe::Pipe,
    tx: channel::Tx,
    terminate: Arc<AtomicBool>,
    limit: Option<usize>,
) -> Result<()> {
    let rd_handle: thread::JoinHandle<anyhow::Result<pipe::Stats>> = thread::Builder::new()
        .name("pcap-reader".to_string())
        .spawn(move || {
            let mut stats = Default::default();
            loop {
                let inp = method.to_pcap_input()?;
                let it = match limit {
                    Some(n) => {
                        Box::new(inp.packets().take(n)) as Box<dyn Iterator<Item = input::Packet>>
                    }
                    None => Box::new(inp.packets()),
                };
                stats = pipe::read_packets_to(it, &tx, stats, Arc::clone(&terminate))?;
                if !loop_file || terminate.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                tracing::info!("pcap file iteration complete: {}", stats)
            }
            Ok(stats)
        })
        .unwrap();
    rd_handle.join().unwrap()?;
    tracing::trace!("Reader terminated");

    let s = pipe.wait()?;
    println!("Write complete: {}", s);
    Ok(())
}

fn create_pipe(
    full: bool,
    pps: Option<u32>,
    bps: Option<u64>,
    rx: channel::Rx,
    outp: impl output::PacketWriter + Send + 'static,
    stats: pipe::Stats,
) -> anyhow::Result<pipe::Pipe> {
    if let Some(p) = pps {
        pipe::pps(rx, outp, p, stats)
    } else if let Some(b) = bps {
        pipe::bps(rx, outp, b, stats)
    } else if full {
        pipe::fullspeed(rx, outp, stats)
    } else {
        pipe::delaying(rx, outp, stats)
    }
}

fn main() {
    tracing_subscriber::fmt::init();
    let matches = clap::App::new("pktreply")
        .version("v0.1.0")
        .arg(clap::arg!(-f --file <FILE> "Name of the pcap file to read").required(false))
        .arg(
            clap::arg!(-o --output <INFAME> "Name of the interface to inject packets to")
                .required(false),
        )
        .arg(clap::arg!(-l --loop "Loop pcap file"))
        .arg(clap::arg!(-F --fullspeed "Write packets as fast as possible"))
        .arg(
            clap::arg!(-L --low <VALUE> "Low watermark for packet buffer")
                .validator(|v| v.parse::<u64>())
                .required(false),
        )
        .arg(
            clap::arg!(-H --hi <VALUE> "High watermark for packet buffer")
                .validator(|v| v.parse::<u64>())
                .required(false),
        )
        .arg(
            clap::arg!(-p --pps <VALUE> "Replay packets at rate of <VALUE> packets per second")
                .validator(|v| v.parse::<u32>())
                .required(false),
        )
        .arg(
            clap::arg!(-M --mbps <VALUE> "Replay packets at rate of <VALUE> Mbits per second")
                .validator(|v| v.parse::<f32>())
                .required(false),
        )
        .arg(
            clap::arg!(-c --count <VALUE> "Send up to <VALUE> packets from the file")
                .validator(|v| v.parse::<usize>())
                .required(false),
        )
        .arg(
            clap::arg!(-i --interface <IFNAME> "Name of the interface to read packets from")
                .required(false),
        )
        .arg(
            clap::arg!(-S --stats <VALUE> "Print statistics every <VALUE> seconds")
                .validator(|v| v.parse::<u64>())
                .required(false),
        )
        .get_matches();

    if matches.is_present("file") && matches.is_present("interface") {
        tracing::error!("Both --file and --interface inputs can not be defined at the same time");
        return;
    }
    let method = if matches.is_present("file") {
        InputMethod::File(matches.value_of("file").unwrap().to_string())
    } else if matches.is_present("interface") {
        InputMethod::Interface(matches.value_of("interface").unwrap().to_string())
    } else {
        tracing::error!("No input defined. Either --file or --interface is required");
        return;
    };

    let loop_file = matches.is_present("loop");

    let mut full = matches.is_present("fullspeed");
    if full && (matches.is_present("pps") || matches.is_present("mbps"))
        || !full && (matches.is_present("pps") && matches.is_present("mbps"))
    {
        tracing::error!("Only one of --full, --pps, --bps options can be present");
        return;
    }

    let pps = if matches.is_present("pps") {
        Some::<u32>(matches.value_of_t("pps").unwrap())
    } else {
        None
    };

    let bps = if matches.is_present("mbps") {
        Some::<u64>((matches.value_of_t::<f32>("mbps").unwrap() * 1_000_000_f32) as u64)
    // convert to bits/sec
    } else {
        None
    };

    let ch_hi: u64 = if matches.is_present("hi") {
        matches.value_of_t("hi").unwrap()
    } else {
        100
    };
    let ch_low: u64 = if matches.is_present("low") {
        matches.value_of_t("low").unwrap()
    } else {
        ch_hi / 2
    };
    if ch_low >= ch_hi {
        tracing::error!("packet buffer low watermark can not be larger than high");
        return;
    }
    let limit = if matches.is_present("count") {
        Some(matches.value_of_t::<usize>("count").unwrap())
    } else {
        None
    };

    let stat_period = if matches.is_present("stats") {
        Some(Duration::from_secs(matches.value_of_t("stats").unwrap()))
    } else {
        None
    };

    let terminate = Arc::new(AtomicBool::from(false));
    if let Err(e) = flag::register(SIGINT, Arc::clone(&terminate)) {
        tracing::error!("Unable to register signal handler: {e}");
        return;
    }

    if matches!(method, InputMethod::Interface(_)) && pps.is_none() && bps.is_none() {
        // if no pps or bps options are defined and we are reading from interface
        // force the --full which causes packets to be written to the output
        // interface as soon as they are received, which is probably what
        // users would expect.
        full = true;
    }

    let (tx, rx) = channel::create(ch_hi, ch_low);
    let (stats, stat_printer) = if let Some(period) = stat_period {
        let (s, r) = pipe::Stats::periodic(period);
        (s, Some(start_printer_task(r)))
    } else {
        (pipe::Stats::default(), None)
    };
    let p = if let Some(ifname) = matches.value_of("output") {
        output::interface(ifname).and_then(|o| create_pipe(full, pps, bps, rx, o, stats))
    } else {
        output::sink().and_then(|o| create_pipe(full, pps, bps, rx, o, stats))
    };
    match p {
        Ok(pipe) => {
            if let Err(e) = input_task(method, loop_file, pipe, tx, terminate, limit) {
                tracing::error!("Error while processing packets: {}", e);
            }
        }
        Err(e) => tracing::error!("{}", e),
    }
    // wait for stat printer to terminate
    if let Some(handle) = stat_printer {
        handle.join().unwrap();
    }
}
