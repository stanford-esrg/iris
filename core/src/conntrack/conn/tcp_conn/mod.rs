pub mod reassembly;

use self::reassembly::TcpFlow;
use crate::conntrack::conn::conn_info::ConnInfo;
use crate::conntrack::pdu::{L4Context, L4Pdu};
use crate::protocols::packet::tcp::{ACK, SYN};
use crate::protocols::packet::tcp::{FIN, RST};
use crate::protocols::stream::ParserRegistry;
use crate::subscription::{Subscription, Trackable};

pub(crate) struct TcpConn {
    pub(crate) ctos: TcpFlow,
    pub(crate) stoc: TcpFlow,
    handshake_done: bool,
}

impl TcpConn {
    pub(crate) fn new_on_syn(ctxt: L4Context, max_ooo: usize) -> Self {
        let flags = ctxt.flags;
        let next_seq = ctxt.seq_no.wrapping_add(1 + ctxt.length as u32);
        let ack = ctxt.ack_no;
        TcpConn {
            ctos: TcpFlow::new(max_ooo, next_seq, flags, ack),
            stoc: TcpFlow::default(max_ooo),
            handshake_done: false,
        }
    }

    /// Insert TCP segment ordered into ctos or stoc flow
    #[inline]
    pub(crate) fn reassemble<T: Trackable>(
        &mut self,
        segment: L4Pdu,
        info: &mut ConnInfo<T>,
        subscription: &Subscription<T::Subscribed>,
        registry: &ParserRegistry,
    ) {
        if segment.dir {
            self.ctos
                .insert_segment::<T>(segment, info, subscription, registry);
        } else {
            self.stoc
                .insert_segment::<T>(segment, info, subscription, registry);
        }
        if self.handshake_done() {
            self.handshake_done = true;
            info.handshake_done(subscription);
        }
    }

    /// Returns true if the PDU currently being processed is the last
    /// packet in the TCP handshake.
    /// Note: we define this pretty loosely -- we just require that both sides have sent SYNs and ACKs,
    /// but we don't check the sequence numbers of those SYNs/ACKs.
    #[inline]
    pub(crate) fn handshake_done(&self) -> bool {
        !self.handshake_done
            && self.ctos.consumed_flags & (SYN | ACK) != 0
            && self.stoc.consumed_flags & (SYN | ACK) != 0
    }

    #[inline]
    pub(crate) fn flow_len(&self, dir: bool) -> usize {
        if dir {
            self.ctos.observed
        } else {
            self.stoc.observed
        }
    }

    #[inline]
    pub(crate) fn total_len(&self) -> usize {
        self.ctos.observed + self.stoc.observed
    }

    /// Returns `true` if the connection should be terminated
    #[inline]
    pub(crate) fn is_terminated(&self) -> bool {
        // Both sides have sent, reassembled, and acknowledged FIN, or RST has been sent
        (self.ctos.consumed_flags & self.stoc.consumed_flags & FIN != 0
            && self.ctos.last_ack == self.stoc.next_seq
            && self.stoc.last_ack == self.ctos.next_seq)
            || (self.ctos.consumed_flags & RST | self.stoc.consumed_flags & RST) != 0
    }

    /// Returns the correct inactivity timeout
    /// (reassembly timeout if there are out-of-order segments, default otherwise)
    #[inline]
    pub(crate) fn inactivity_timeout(
        &self,
        default_inactivity_timeout: usize,
        reassembly_timeout: usize,
    ) -> usize {
        match self.ctos.ooo_buf.is_empty() && self.stoc.ooo_buf.is_empty() {
            true => default_inactivity_timeout,
            false => reassembly_timeout,
        }
    }

    /// Updates connection termination flags
    // Useful if desired to track TCP connections without reassembly
    #[inline]
    pub(super) fn update_flags(&mut self, flags: u8, dir: bool) {
        if dir {
            self.ctos.consumed_flags |= flags;
        } else {
            self.stoc.consumed_flags |= flags;
        }
    }
}
