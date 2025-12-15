use crate::entities::v2::negotiate::request::ParseError;

/// The SMB2_NETNAME_NEGOTIATE_CONTEXT_ID context is specified in an SMB2 NEGOTIATE request to
/// indicate the server name the client connects to. The format of the data in the Data field of this
/// SMB2_NEGOTIATE_CONTEXT is as follows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetNameNegotiateContextId<'a> {
    pub value: &'a str,
}

impl<'a> NetNameNegotiateContextId<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<Self, ParseError> {
        Ok(Self {
            value: std::str::from_utf8(buf)?,
        })
    }
}
