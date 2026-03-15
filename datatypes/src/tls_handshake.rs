//! A TLS handshake.
//! Subscribable alias for [`iris_core::protocols::stream::tls::Tls`]

use crate::FromSession;
#[allow(unused_imports)]
use iris_compiler::{datatype, datatype_group};
use iris_core::protocols::stream::tls::Tls;
use iris_core::protocols::stream::{Session, SessionData};

#[cfg_attr(not(feature = "skip_expand"), datatype("L7EndHdrs,parsers=tls"))]
pub type TlsHandshake = Box<Tls>;

impl FromSession for TlsHandshake {
    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype_group("TlsHandshake,level=L7EndHdrs")
    )]
    fn from_session(session: &Session) -> Option<&Self> {
        if let SessionData::Tls(tls) = &session.data {
            return Some(tls);
        }
        None
    }
}
