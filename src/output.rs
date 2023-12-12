//! Outputs for writing packets
use crate::input::Packet;
use anyhow::Result;
use luomu_libpcap::Pcap;
use std::{
    fs::{File, OpenOptions},
    io::Write,
};

/// PacketWriter can be used to write Packets or raw packet data.
pub trait PacketWriter {
    /// Writes raw packet data returning number of bytes written.
    fn write_raw(&mut self, buf: &[u8]) -> Result<usize>;
    /// Writes given [Packet] returning number of bytes written.
    fn write_packet(&mut self, packet: Packet) -> Result<usize> {
        self.write_raw(&packet.data)
    }
}

/// Sink consuming all packets written to it.
struct Sink(File);

impl PacketWriter for Sink {
    fn write_raw(&mut self, buf: &[u8]) -> Result<usize> {
        let Sink(f) = self;
        Ok(f.write(buf)?)
    }
}

/// Returns PacketWriter which just consumes the packets
pub fn sink() -> Result<impl PacketWriter> {
    let f = OpenOptions::new().write(true).open("/dev/null")?;
    Ok(Sink(f))
}

/// [Interface] allows writing packets to network interface
struct Interface(Pcap);

impl PacketWriter for Interface {
    fn write_raw(&mut self, buf: &[u8]) -> Result<usize> {
        Ok(self.0.inject(buf)?)
    }
}

/// Returns [PacketWriter] for writing packets to given interface.
pub fn interface(name: &str) -> Result<impl PacketWriter> {
    let p = Pcap::new(name)?;
    p.activate()?;
    Ok(Interface(p))
}
