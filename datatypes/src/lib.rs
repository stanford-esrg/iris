#[allow(unused_imports)]
use iris_compiler::cache_file;
use iris_core::{protocols::Session, L4Pdu, Mbuf};

pub mod conn_fts;
pub use conn_fts::*;

pub mod connection;
pub use connection::ConnRecord;

pub mod dns_transaction;
pub use dns_transaction::DnsTransaction;

pub mod http_transaction;
pub use http_transaction::HttpTransaction;

pub mod packet_list;
pub use packet_list::*;

pub mod packet;
pub use packet::{Payload, ZcFrame};

pub mod quic_stream;
pub use quic_stream::QuicStream;

pub mod ssh_handshake;
pub use ssh_handshake::SshHandshake;

pub mod static_type;
pub use static_type::*;

pub mod tls_handshake;
pub use tls_handshake::TlsHandshake;

/// No-op function to invoke macro
/// TODO can we do this more cleanly?
#[cfg_attr(
    not(feature = "skip_expand"),
    cache_file("$IRIS_HOME/datatypes/data.txt")
)]
fn _cache_file() {}

/// Need to define traits in this crate to avoid
/// "cannot define inherent `impl` for foreign type" and
/// "only traits defined in the current crate can be implemented
/// for types defined outside of the crate" errors.
/// Convenience method to convert a `Session` into a datatype that
/// can be subscribed to. Datatypes implementing this trait are
/// automatically Level=L7EndHdrs.
pub trait FromSession {
    /// Build Self from a parsed session, or return None if impossible.
    /// Invoked when the session is fully matched, parsed, and ready to
    /// be delivered to a callback.
    fn from_session(session: &Session) -> Option<&Self>;
}

/// Convenience method to convert an `Mbuf` into a datatype that
/// can be subscribed to. Datatypes implementing this trait
/// are automatically Level=Packet.
pub trait FromMbuf {
    fn new(mbuf: &Mbuf) -> Option<&Self>;
}

/// Trait implemented by datatypes that are constant throughout
/// a connection and inferrable at first packet (level is L4FirstPacket).
pub trait StaticData {
    fn new(first_pkt: &L4Pdu) -> Self;
}
