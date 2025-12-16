use crate::entities::v2::negotiate::request::{EncodeError, ParseError};

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

#[derive(Clone, Debug)]
pub struct NetNameNegotiateContextIdBuilder {
    pub value: String,
}

impl NetNameNegotiateContextIdBuilder {
    pub fn new(value: String) -> Self {
        Self { value }
    }

    pub fn encode<W: std::io::Write>(&self, buf: &mut W) -> Result<(), EncodeError> {
        buf.write(self.value.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::BufWriter;

    #[test]
    fn should_encode_and_parse() {
        let mut buf = BufWriter::new(Vec::with_capacity(1024));
        super::NetNameNegotiateContextIdBuilder::new(String::from("hello world"))
            .encode(&mut buf)
            .unwrap();
        let buf = buf.into_inner().unwrap();
        let cap = super::NetNameNegotiateContextId::parse(&buf).unwrap();
        assert_eq!(cap.value, "hello world");
    }
}
