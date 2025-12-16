use crate::entities::u32_from_le_bytes;
use crate::entities::v2::negotiate::request::{EncodeError, ParseError};

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct TransportFlags: u32 {
        /// Transport security is offered to skip SMB2 encryption on this connection.
        const SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY = 0x01;
    }
}

/// The SMB2_TRANSPORT_CAPABILITIES context is specified in an SMB2 NEGOTIATE request to indicate
/// transport capabilities over which the connection is made. The format of the data in the Data field of this
/// SMB2_NEGOTIATE_CONTEXT is as follows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportCapabilities {
    pub flags: TransportFlags,
}

impl TransportCapabilities {
    pub fn parse(buf: &[u8]) -> Result<Self, ParseError> {
        let flags = buf.get(0..4).ok_or(ParseError::BufferTooShort)?;
        let flags = TransportFlags::from_bits(u32_from_le_bytes(flags))
            .ok_or(ParseError::UnknownTransportFlags)?;

        Ok(Self { flags })
    }
}

pub type TransportCapabilitiesBuilder = TransportCapabilities;

impl TransportCapabilitiesBuilder {
    pub fn new(flags: TransportFlags) -> Self {
        Self { flags }
    }

    pub fn encode<W: std::io::Write>(&self, buf: &mut W) -> Result<(), EncodeError> {
        buf.write(&self.flags.bits().to_le_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn should_parse() {
        let cap = super::TransportCapabilities::parse(&[0, 0, 0, 0]).unwrap();
        assert!(cap.flags.is_empty());
        let cap = super::TransportCapabilities::parse(&[1, 0, 0, 0]).unwrap();
        assert!(
            cap.flags
                .contains(super::TransportFlags::SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY)
        );
    }

    #[test]
    fn should_fail_parse_too_small() {
        let err = super::TransportCapabilities::parse(&[0, 0, 0]).unwrap_err();
        assert_eq!(err, super::ParseError::BufferTooShort);
    }
}
