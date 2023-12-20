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
        match self.0.inject(buf) {
            Ok(ret) => Ok(ret),
            Err(err) => {
                tracing::warn!(?err, len = ?buf.len(), "error while trying to write");
                // we do not want to stop writing if we get error indicating that
                // packet was too large to write.
                if let luomu_libpcap::Error::PcapError(ref msg) = err {
                    if msg.contains("Message too") && buf.len() > 1500 {
                        // this is a stupid way to detect such errors, but there
                        // is no other way currently, as the only thing we get
                        // is error message from libpcap and it can contain at
                        // least "Message too long" and "Message too large"
                        // depending on the Linux distribution of choice.
                        Ok(0)
                    } else {
                        Err(err.into())
                    }
                } else {
                    Err(err.into())
                }
            }
        }
    }
}

/// Returns [PacketWriter] for writing packets to given interface.
pub fn interface(name: &str) -> Result<impl PacketWriter> {
    let p = Pcap::new(name)?;
    p.activate()?;
    Ok(Interface(p))
}
