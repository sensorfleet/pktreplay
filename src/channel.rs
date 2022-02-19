use std::{
    fmt::Display,
    sync::{Arc, Condvar, Mutex},
};

use crossbeam_channel::{Receiver, SendError, Sender};

use crate::input::Packet;
#[derive(Debug)]
pub enum ChannelError {
    // Generic(),
    Send(SendError<Packet>),
}

impl std::error::Error for ChannelError {}

impl Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            // ChannelError::Generic() => write!(f, "Error in channel"),
            ChannelError::Send(se) => write!(f, "{}", se),
        }
    }
}

impl From<SendError<Packet>> for ChannelError {
    fn from(se: SendError<Packet>) -> Self {
        ChannelError::Send(se)
    }
}

struct ChannelContext {
    // number of packets waiting on channel
    packets: u64,
    // should the producer be paused
    paused: bool,
}

//Receiver side of channel
// Rx can be used as iterator to read packets from channel.
pub struct Rx {
    recv: Receiver<Packet>,
    ctx: Arc<(Mutex<ChannelContext>, Condvar)>,
    watermark_lo: u64,
}

pub struct IntoRxIter {
    rx: Rx,
}

impl Iterator for IntoRxIter {
    type Item = Packet;

    fn next(&mut self) -> Option<Self::Item> {
        let (mux, cvar) = &*self.rx.ctx;
        let packet = self.rx.recv.recv().ok();
        if packet.is_some() {
            let mut ctx = mux.lock().unwrap();
            ctx.packets -= 1;
            if ctx.packets < self.rx.watermark_lo && ctx.paused {
                ctx.paused = false;
                trace!("waking packet reader");
                cvar.notify_one();
            }
            trace!("rx complete, packets in channel: {}", ctx.packets);
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

// Sender side of channel
pub struct Tx {
    sender: Sender<Packet>,
    watermark_hi: u64,
    ctx: Arc<(Mutex<ChannelContext>, Condvar)>,
}

impl Tx {
    // write a packet to channel. If channel already is full, then
    // this method blocks until the low packet treshold is reached.
    pub fn write_packet(&self, pkt: Packet) -> Result<(), ChannelError> {
        let (mux, cvar) = &*self.ctx;
        let mut ctx = mux.lock().unwrap();
        if ctx.packets >= self.watermark_hi {
            ctx.paused = true;
        }
        while ctx.paused {
            trace!("Packet reading paused");
            ctx = cvar.wait(ctx).unwrap();
        }
        self.sender.send(pkt)?;
        ctx.packets += 1;
        trace!("tx complete, packets in channel: {}", ctx.packets);
        Ok(())
    }
}

// Returns Tx and Rx for a channel that allows `hi` number of packets to be
// queued. When hi number of packets are queued, the `Tx::write_packet()` will
// block until packets are consumed from channel and only `lo` number of
// packets are left.
pub fn create(hi: u64, lo: u64) -> (Tx, Rx) {
    let (sender, recv) = crossbeam_channel::unbounded();
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
        },
    )
}
