//! Channel which can be used to buffer packets
use std::{
    fmt::Display,
    sync::{
        atomic::AtomicBool,
        mpsc::{self, Receiver, SendError, Sender},
        Arc, Condvar, Mutex,
    },
};

use crate::input::Packet;
/// Error returned by channel operations
#[derive(Debug)]
pub enum ChannelError {
    Send(SendError<Packet>),
}

impl std::error::Error for ChannelError {}

impl Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            ChannelError::Send(se) => write!(f, "{}", se),
        }
    }
}

impl From<SendError<Packet>> for ChannelError {
    fn from(se: SendError<Packet>) -> Self {
        ChannelError::Send(se)
    }
}

/// Context for channel
struct ChannelContext {
    /// number of packets waiting on channel
    packets: u64,
    /// should the producer be paused
    paused: bool,
}

/// Receiver side of channel.
///
/// Rx can be used as iterator to read packets from channel.
pub struct Rx {
    recv: Receiver<Packet>,
    ctx: Arc<(Mutex<ChannelContext>, Condvar)>,
    watermark_lo: u64,
    stop: Arc<AtomicBool>,
}

/// Iterator for reading packets.
pub struct IntoRxIter {
    /// Receiver for channel
    rx: Rx,
}

impl Iterator for IntoRxIter {
    type Item = Packet;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rx.stop.load(std::sync::atomic::Ordering::Relaxed) {
            return None;
        }
        let (mux, cvar) = &*self.rx.ctx;
        let packet = self.rx.recv.recv().ok();
        if packet.is_some() {
            let mut ctx = mux.lock().unwrap();
            ctx.packets -= 1;
            if ctx.packets < self.rx.watermark_lo && ctx.paused {
                ctx.paused = false;
                tracing::trace!("waking packet reader");
                cvar.notify_one();
            }
            tracing::trace!("rx complete, packets in channel: {}", ctx.packets);
        }
        packet
    }
}

impl IntoIterator for Rx {
    type Item = Packet;

    type IntoIter = IntoRxIter;

    fn into_iter(self) -> Self::IntoIter {
        IntoRxIter { rx: self }
    }
}

impl Drop for Rx {
    fn drop(&mut self) {
        let (mux, cvar) = &*self.ctx;
        let mut ctx = mux.lock().unwrap();
        // ensure any sender will not be paused anymore.
        ctx.packets = 0;
        if ctx.paused {
            ctx.paused = false;
            cvar.notify_all();
        }
    }
}

/// Sender side of channel
pub struct Tx {
    sender: Sender<Packet>,
    watermark_hi: u64,
    ctx: Arc<(Mutex<ChannelContext>, Condvar)>,
}

impl Tx {
    /// Writes a packet to channel.
    ///
    /// If channel already is full, then this method blocks until the low
    /// packet threshold is reached.
    pub fn write_packet(&self, pkt: Packet) -> Result<(), ChannelError> {
        let (mux, cvar) = &*self.ctx;
        let mut ctx = mux.lock().unwrap();
        if ctx.packets >= self.watermark_hi {
            ctx.paused = true;
        }
        while ctx.paused {
            tracing::trace!("Packet reading paused");
            ctx = cvar.wait(ctx).unwrap();
        }
        self.sender.send(pkt)?;
        ctx.packets += 1;
        tracing::trace!("tx complete, packets in channel: {}", ctx.packets);
        Ok(())
    }
}

/// Creates a channel, returning [Tx] and [Rx] for a channel that allows
/// `hi` number of packets to be queued. `stop` can be used to signal that
/// [Rx] should terminate immediately instead of draining the buffer.
///
/// When hi number of packets are queued, the [Tx::write_packet()] will
/// block until packets are consumed from channel and only `lo` number of
/// packets are left.
pub fn create(hi: u64, lo: u64, stop: Arc<AtomicBool>) -> (Tx, Rx) {
    let (sender, recv) = mpsc::channel();
    let ctx = Arc::new((
        Mutex::new(ChannelContext {
            packets: 0,
            paused: false,
        }),
        Condvar::new(),
    ));
    let ctx2 = Arc::clone(&ctx);
    (
        Tx {
            sender,
            ctx,
            watermark_hi: hi,
        },
        Rx {
            recv,
            ctx: ctx2,
            watermark_lo: lo,
            stop,
        },
    )
}
