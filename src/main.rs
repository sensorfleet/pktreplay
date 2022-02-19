#[macro_use]
extern crate log;

use anyhow::Result;
use signal_hook::consts::SIGINT;
use signal_hook::flag;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;

mod channel;
mod input;
mod output;
mod pipe;

fn read_from_file_to(
    fname: String,
    loop_file: bool,
    pipe: pipe::Pipe,
    tx: channel::Tx,
    terminate: Arc<AtomicBool>,
) -> Result<()> {
    let rd_handle: thread::JoinHandle<anyhow::Result<pipe::Stats>> = thread::Builder::new()
        .name("pcap-reader".to_string())
        .spawn(move || {
            let mut stats = Default::default();
            loop {
                let inp = input::pcap_file(&fname)?;
                stats = pipe::read_packets_to(inp.packets(), &tx, stats, Arc::clone(&terminate))?;
                if !loop_file || terminate.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                info!("pcap file iteration complete: {}", stats)
            }
            Ok(stats)
        })
        .unwrap();
    rd_handle.join().unwrap()?;
    trace!("Reader terminated");

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
) -> anyhow::Result<pipe::Pipe> {
    if let Some(p) = pps {
        pipe::pps(rx, outp, p)
    } else if let Some(b) = bps {
        pipe::bps(rx, outp, b)
    } else if full {
        pipe::fullspeed(rx, outp)
    } else {
        pipe::delaying(rx, outp)
    }
}

fn main() {
    env_logger::init();
    let matches = clap::App::new("pktreply")
        .version("v0.1.0")
        .arg(clap::arg!(-f --file <FILE> "Name of the pcap file to read"))
        .arg(
            clap::arg!(-o --output <INFAME> "Name of the interface to inject packets to")
                .required(false),
        )
        .arg(clap::arg!(-l --loop "Loop pcap file"))
        .arg(clap::arg!(-F --fullspeed "Write packets as fast as possible"))
        .arg(
            clap::arg!(-L --low <VALUE> "Minimum watermark for packet buffe")
                .validator(|v| v.parse::<u64>())
                .required(false),
        )
        .arg(
            clap::arg!(-H --hi <VALUE> "Hi watermark for packet buffer")
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
        .get_matches();

    let loop_file = matches.is_present("loop");
    let full = matches.is_present("fullspeed");
    if full && (matches.is_present("pps") || matches.is_present("mbps"))
        || !full && (matches.is_present("pps") && matches.is_present("mbps"))
    {
        error!("Only one of --full, --pps, --bps options can be present");
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

    let fname = matches.value_of("file").unwrap().to_string();
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
        error!("packet buffer low watermark can not be larger than hi");
        return;
    }

    let terminate = Arc::new(AtomicBool::from(false));
    if let Err(e) = flag::register(SIGINT, Arc::clone(&terminate)) {
        error!("Unable to register signal handler: {e}");
        return;
    }

    let (tx, rx) = channel::create(ch_hi, ch_low);
    let p = if let Some(ifname) = matches.value_of("output") {
        output::interface(ifname).and_then(|o| create_pipe(full, pps, bps, rx, o))
    } else {
        output::sink().and_then(|o| create_pipe(full, pps, bps, rx, o))
    };
    match p {
        Ok(pipe) => {
            if let Err(e) = read_from_file_to(fname, loop_file, pipe, tx, terminate) {
                error!("Error while processing packets: {}", e);
            }
        }
        Err(e) => error!("{}", e),
    }
}
