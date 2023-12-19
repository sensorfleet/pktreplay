//! Inputs for reading packets
//!
//! Packets can be read from network interface or pcap -file.
use std::sync::atomic::AtomicBool;
use std::time::Duration;
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
    read_timeout: Option<Duration>,
}

/// Creates [PcapInput] for reading packets from given pcap -file
pub fn pcap_file<P>(file: P) -> Result<PcapInput>
where
    P: AsRef<Path>,
{
    let pcap = Pcap::offline(file)?;
    Ok(PcapInput {
        handle: pcap,
        read_timeout: None,
    })
}

// Creates [PcapInput] for reading packets from interface with given name
pub fn pcap_interface(ifname: &str) -> Result<PcapInput> {
    let builder = Pcap::builder(ifname)?
        .set_promiscuous(true)?
        .set_immediate(true)?;
    Ok(PcapInput {
        handle: builder.activate()?,
        read_timeout: Some(Duration::from_millis(100)),
    })
}

/// [Iterator] for reading packets using [luomu_libpcap::NonBlockingIter].
struct TimeoutIter<'a, 'b> {
    iter: luomu_libpcap::NonBlockingIter<'a>,
    sig: &'b AtomicBool,
}

impl Iterator for TimeoutIter<'_, '_> {
    type Item = Packet;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.iter.next() {
                Some(Err(_)) => return None,
                Some(Ok(pkt)) => {
                    return Some(Packet {
                        when: pkt.timestamp(),
                        data: pkt.to_vec(),
                    })
                }
                None => {
                    if self.sig.load(std::sync::atomic::Ordering::Relaxed) {
                        return None;
                    }
                }
            }
        }
    }
}

/// [Iterator] for reading packets using [luomu_libpcap::PcapIter].
struct PacketIter<'a, 'b> {
    iter: luomu_libpcap::PcapIter<'a>,
    sig: &'b AtomicBool,
}

impl Iterator for PacketIter<'_, '_> {
    type Item = Packet;

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter.next() {
            None => None,
            Some(pkt) => {
                if self.sig.load(std::sync::atomic::Ordering::Relaxed) {
                    None
                } else {
                    Some(Packet {
                        when: pkt.timestamp(),
                        data: pkt.to_vec(),
                    })
                }
            }
        }
    }
}

impl PcapInput {
    /// Returns [Iterator] for reading captured packets.
    ///
    /// Iterator terminates (returns [None]) when there are no more packets to
    /// read (from file) or `sig` is set to `true`.
    pub fn packets<'a>(
        &'a self,
        sig: &'a AtomicBool,
    ) -> Result<Box<dyn Iterator<Item = Packet> + '_>> {
        match self.read_timeout {
            None => {
                let iter = self.handle.capture();
                Ok(Box::new(PacketIter { iter, sig }))
            }
            Some(timeout) => {
                let iter = self.handle.capture_nonblocking(timeout)?;
                Ok(Box::new(TimeoutIter { iter, sig }))
            }
        }
    }
}
