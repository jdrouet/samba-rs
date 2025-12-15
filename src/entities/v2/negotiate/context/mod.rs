use crate::entities::BufferIterator;
use crate::entities::v2::negotiate::request::ParseError;

pub mod compression;
pub mod encryption;
pub mod net_name;
pub mod preauth_integrity;
pub mod rdma_transform;
pub mod signing;
pub mod transport;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum NegotiateContextType {
    /// The Data field contains a list of preauthentication integrity hash functions
    /// as well as an optional salt value, as specified in section 2.2.3.1.1.
    PreauthIntegrityCapabilities = 0x0001,
    /// The Data field contains a list of encryption algorithms, as specified in section 2.2.3.1.2.
    EncryptionCapabilities = 0x0002,
    /// The Data field contains a list of compression algorithms, as specified in section 2.2.3.1.3.
    CompressionCapabilities = 0x0003,
    /// The Data field contains the server name to which the client connects.
    NetNameNegotiateContextId = 0x0005,
    /// The Data field contains transport capabilities, as specified in section 2.2.3.1.5.
    TransportCapabilities = 0x0006,
    /// The Data field contains a list of RDMA transforms, as specified in section 2.2.3.1.6.
    RDMATransformCapabilities = 0x0007,
    /// The Data field contains a list of signing algorithms, as specified in section 2.2.3.1.7.
    SigningCapabilities = 0x0008,
    /// This value MUST be reserved and MUST be ignored on receipt.
    ContextTypeReserved = 0x0100,
}

impl TryFrom<u16> for NegotiateContextType {
    type Error = u16;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(match value {
            0x0001 => Self::PreauthIntegrityCapabilities,
            0x0002 => Self::EncryptionCapabilities,
            0x0003 => Self::CompressionCapabilities,
            0x0005 => Self::NetNameNegotiateContextId,
            0x0006 => Self::TransportCapabilities,
            0x0007 => Self::RDMATransformCapabilities,
            0x0008 => Self::SigningCapabilities,
            0x1000 => Self::ContextTypeReserved,
            other => return Err(other),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NegotiateContext<'a> {
    PreauthIntegrityCapabilities(preauth_integrity::PreauthIntegrityCapabilities<'a>),
    EncryptionCapabilities(encryption::EncryptionCapabilities<'a>),
    CompressionCapabilities(compression::CompressionCapabilities<'a>),
    NetNameNegotiateContextId(net_name::NetNameNegotiateContextId<'a>),
    TransportCapabilities(transport::TransportCapabilities),
    RDMATransformCapabilities(rdma_transform::RDMATransformCapabilities<'a>),
    SigningCapabilities(signing::SigningCapabilities<'a>),
    ContextTypeReserved(&'a [u8]),
}

impl<'a> NegotiateContext<'a> {
    pub(super) fn parse(it: &mut BufferIterator<'a>) -> Result<Self, ParseError> {
        let context_type = it.next_u16().ok_or(ParseError::BufferTooShort)?;
        let context_type =
            NegotiateContextType::try_from(context_type).map_err(ParseError::InvalidContextType)?;

        let data_length = it.next_u16().ok_or(ParseError::BufferTooShort)?;
        // skip reserved
        it.next(4).ok_or(ParseError::BufferTooShort)?;
        let buf = it
            .next(data_length as usize)
            .ok_or(ParseError::BufferTooShort)?;
        match context_type {
            NegotiateContextType::PreauthIntegrityCapabilities => {
                preauth_integrity::PreauthIntegrityCapabilities::parse(buf)
                    .map(NegotiateContext::PreauthIntegrityCapabilities)
            }
            NegotiateContextType::EncryptionCapabilities => {
                encryption::EncryptionCapabilities::parse(buf)
                    .map(NegotiateContext::EncryptionCapabilities)
            }
            NegotiateContextType::CompressionCapabilities => {
                compression::CompressionCapabilities::parse(buf)
                    .map(NegotiateContext::CompressionCapabilities)
            }
            NegotiateContextType::NetNameNegotiateContextId => {
                net_name::NetNameNegotiateContextId::parse(buf)
                    .map(NegotiateContext::NetNameNegotiateContextId)
            }
            NegotiateContextType::TransportCapabilities => {
                transport::TransportCapabilities::parse(buf)
                    .map(NegotiateContext::TransportCapabilities)
            }
            NegotiateContextType::RDMATransformCapabilities => {
                rdma_transform::RDMATransformCapabilities::parse(buf)
                    .map(NegotiateContext::RDMATransformCapabilities)
            }
            NegotiateContextType::SigningCapabilities => {
                signing::SigningCapabilities::parse(buf).map(NegotiateContext::SigningCapabilities)
            }
            NegotiateContextType::ContextTypeReserved => {
                Ok(NegotiateContext::ContextTypeReserved(buf))
            }
        }
    }
}

pub struct NegotiateContextIterator<'a>(BufferIterator<'a>);

impl<'a> NegotiateContextIterator<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self(BufferIterator(buf))
    }

    pub fn try_next(&mut self) -> Result<Option<super::context::NegotiateContext<'a>>, ParseError> {
        if self.0.0.is_empty() {
            return Ok(None);
        }

        super::context::NegotiateContext::parse(&mut self.0).map(Some)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn should_parse_negotiate_context() {
        let buf: [u8; _] = [
            6, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 4, 0, 0, 0, 0, 0, 1, 0, 0, 0,
        ];
        let mut it = super::NegotiateContextIterator::new(&buf);
        let first = it.try_next().unwrap().unwrap();
        assert!(matches!(
            first,
            super::NegotiateContext::TransportCapabilities(_)
        ));
        let second = it.try_next().unwrap().unwrap();
        assert!(matches!(
            second,
            super::NegotiateContext::SigningCapabilities(_)
        ));
        assert_eq!(it.try_next(), Ok(None));
    }
}
