//! A Quic stream.
//! Subscribable alias for [`iris_core::protocols::stream::quic::QuicConn`]

use crate::FromSession;
#[allow(unused_imports)]
use iris_compiler::{datatype, datatype_group};
use iris_core::protocols::stream::quic::QuicConn;
use iris_core::protocols::stream::{Session, SessionData};

#[cfg_attr(not(feature = "skip_expand"), datatype("L7EndHdrs,parsers=quic"))]
pub type QuicStream = Box<QuicConn>;

impl FromSession for QuicStream {
    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype_group("QuicStream,level=L7EndHdrs")
    )]
    fn from_session(session: &Session) -> Option<&Self> {
        if let SessionData::Quic(quic) = &session.data {
            return Some(quic);
        }
        None
    }
}
