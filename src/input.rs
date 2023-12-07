use std::{path::Path, time::SystemTime};

use anyhow::Result;
use luomu_libpcap::Packet as LibpcapPacket;
use luomu_libpcap::Pcap;

// Raw packet read from input
pub struct Packet {
    pub data: Vec<u8>,
    pub when: SystemTime,
}

pub struct PcapInput {
    handle: Pcap,
}

// Creates Input for reading packets from given pcap file
pub fn pcap_file<P>(file: P) -> Result<PcapInput>
where
    P: AsRef<Path>,
{
    let pcap = Pcap::offline(file)?;
    Ok(PcapInput { handle: pcap })
}

// Creates input for reading packets from given interface
pub fn pcap_interface(ifname: &str) -> Result<PcapInput> {
    let builder = Pcap::builder(ifname)?
        .set_buffer_size(65535)?
        .set_promiscuous(true)?
        .set_immediate(true)?;
    Ok(PcapInput {
        handle: builder.activate()?,
    })
}

impl PcapInput {
    pub fn packets(&self) -> impl Iterator<Item = Packet> + '_ {
        return self.handle.capture().map(|p| Packet {
            when: p.timestamp(),
            data: p.to_vec(),
        });
    }
}
