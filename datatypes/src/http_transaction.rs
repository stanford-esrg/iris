//! An Http transaction.
//! Subscribable alias for [`iris_core::protocols::stream::http::Http`]

use crate::FromSession;
#[allow(unused_imports)]
use iris_compiler::{datatype, datatype_group};
use iris_core::protocols::stream::http::Http;
use iris_core::protocols::stream::{Session, SessionData};

#[cfg_attr(not(feature = "skip_expand"), datatype("L7EndHdrs,parsers=http"))]
pub type HttpTransaction = Box<Http>;

impl FromSession for HttpTransaction {
    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype_group("HttpTransaction,level=L7EndHdrs")
    )]
    fn from_session(session: &Session) -> Option<&Self> {
        if let SessionData::Http(http) = &session.data {
            return Some(http);
        }
        None
    }
}
