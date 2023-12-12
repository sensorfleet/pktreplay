//! Inputs for reading packets
//!
//! Packets can be read from network interface or pcap -file.
use std::{path::Path, time::SystemTime};

use anyhow::Result;
use luomu_libpcap::Packet as LibpcapPacket;
use luomu_libpcap::Pcap;

/// Raw packet read from input
pub struct Packet {
    /// Packet data
    pub data: Vec<u8>,
    /// Timestamp for the packet.
    ///
    /// When reading from interface, this is the time packet was received,
    /// when reading from pcap -file, this is the timestamp when packet
    /// was captured.
    pub when: SystemTime,
}

/// Input for reading packets.
pub struct PcapInput {
    /// Handle for packet capture reader.
    handle: Pcap,
}

/// Creates [PcapInput] for reading packets from given pcap -file
pub fn pcap_file<P>(file: P) -> Result<PcapInput>
where
    P: AsRef<Path>,
{
    let pcap = Pcap::offline(file)?;
    Ok(PcapInput { handle: pcap })
}

// Creates [PcapInput] for reading packets from interface with given name
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
    /// Returns [Iterator] for reading captured packets.
    pub fn packets(&self) -> impl Iterator<Item = Packet> + '_ {
        return self.handle.capture().map(|p| Packet {
            when: p.timestamp(),
            data: p.to_vec(),
        });
    }
}
