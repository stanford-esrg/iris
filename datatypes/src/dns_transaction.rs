//! A DNS transaction.
//! Subscribable alias for [`iris_core::protocols::stream::dns::Dns`]

use crate::FromSession;
#[allow(unused_imports)]
use iris_compiler::{datatype, datatype_group};
use iris_core::protocols::stream::dns::Dns;
use iris_core::protocols::stream::{Session, SessionData};

#[cfg_attr(not(feature = "skip_expand"), datatype("L7EndHdrs,parsers=dns"))]
pub type DnsTransaction = Box<Dns>;

impl FromSession for DnsTransaction {
    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype_group("DnsTransaction,level=L7EndHdrs")
    )]
    fn from_session(session: &Session) -> Option<&Self> {
        if let SessionData::Dns(dns) = &session.data {
            return Some(dns);
        }
        None
    }
}
