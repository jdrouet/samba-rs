use crate::entities::BufferIterator;
use crate::entities::v2::negotiate::request::{EncodeError, ParseError};

pub mod compression;
pub mod encryption;
pub mod net_name;
pub mod preauth_integrity;
pub mod rdma_transform;
pub mod signing;
pub mod transport;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

#[derive(Clone, Debug, derive_more::From)]
pub enum NegotiateContextBuilder {
    PreauthIntegrityCapabilities(preauth_integrity::PreauthIntegrityCapabilitiesBuilder),
    EncryptionCapabilities(encryption::EncryptionCapabilitiesBuilder),
    CompressionCapabilities(compression::CompressionCapabilitiesBuilder),
    NetNameNegotiateContextId(net_name::NetNameNegotiateContextIdBuilder),
    TransportCapabilities(transport::TransportCapabilitiesBuilder),
    RDMATransformCapabilities(rdma_transform::RDMATransformCapabilitiesBuilder),
    SigningCapabilities(signing::SigningCapabilitiesBuilder),
    ContextTypeReserved(Vec<u8>),
}

impl NegotiateContextBuilder {
    fn inner_size(&self) -> usize {
        match self {
            Self::PreauthIntegrityCapabilities(inner) => inner.size(),
            Self::EncryptionCapabilities(inner) => inner.size(),
            Self::CompressionCapabilities(inner) => inner.size(),
            Self::NetNameNegotiateContextId(inner) => inner.size(),
            Self::TransportCapabilities(inner) => inner.size(),
            Self::RDMATransformCapabilities(inner) => inner.size(),
            Self::SigningCapabilities(inner) => inner.size(),
            Self::ContextTypeReserved(inner) => inner.len(),
        }
    }

    pub fn size(&self) -> usize {
        // context_type (2) + data_length (2) + gap (4)
        self.inner_size() + 8
    }

    const fn to_u16(&self) -> u16 {
        match self {
            Self::PreauthIntegrityCapabilities(_) => 0x0001,
            Self::EncryptionCapabilities(_) => 0x0002,
            Self::CompressionCapabilities(_) => 0x0003,
            Self::NetNameNegotiateContextId(_) => 0x0005,
            Self::TransportCapabilities(_) => 0x0006,
            Self::RDMATransformCapabilities(_) => 0x0007,
            Self::SigningCapabilities(_) => 0x0008,
            Self::ContextTypeReserved(_) => 0x1000,
        }
    }

    pub fn encode<W: std::io::Write>(&self, buf: &mut W) -> Result<(), EncodeError> {
        buf.write_all(&self.to_u16().to_le_bytes())?;
        let data_length =
            u16::try_from(self.inner_size()).map_err(|_| EncodeError::NumberOutOfBound)?;
        buf.write_all(&data_length.to_le_bytes())?;
        buf.write_all(&[0, 0, 0, 0])?;
        match self {
            Self::PreauthIntegrityCapabilities(inner) => inner.encode(buf),
            Self::EncryptionCapabilities(inner) => inner.encode(buf),
            Self::CompressionCapabilities(inner) => inner.encode(buf),
            Self::NetNameNegotiateContextId(inner) => inner.encode(buf),
            Self::TransportCapabilities(inner) => inner.encode(buf),
            Self::RDMATransformCapabilities(inner) => inner.encode(buf),
            Self::SigningCapabilities(inner) => inner.encode(buf),
            Self::ContextTypeReserved(inner) => {
                buf.write_all(inner).map(|_| ()).map_err(EncodeError::from)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::entities::BufferIterator;

    #[test]
    fn should_fail_parsing_unsupported_context_type() {
        assert_eq!(
            super::NegotiateContextType::try_from(0x1234).unwrap_err(),
            0x1234
        );
    }

    #[test]
    fn should_compute_size() {
        let cap = super::compression::CompressionCapabilitiesBuilder::new(
            super::compression::CompressionFlags::Chained,
        )
        .with_algorithm(super::compression::CompressionAlgorithm::LZ77);
        let size = super::NegotiateContextBuilder::CompressionCapabilities(cap).size();
        assert_eq!(size, 18);

        let cap = super::transport::TransportCapabilitiesBuilder::new(
            super::transport::TransportFlags::SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY,
        );
        let size = super::NegotiateContextBuilder::TransportCapabilities(cap).size();
        assert_eq!(size, 12);
    }

    #[test]
    fn should_encode_and_decode_compression() {
        let cap = super::compression::CompressionCapabilitiesBuilder::new(
            super::compression::CompressionFlags::Chained,
        )
        .with_algorithm(super::compression::CompressionAlgorithm::LZ77);
        let cap = super::NegotiateContextBuilder::CompressionCapabilities(cap);
        let mut buf = Vec::with_capacity(256);
        cap.encode(&mut buf).unwrap();
        let decoded = super::NegotiateContext::parse(&mut BufferIterator(&buf)).unwrap();
        assert!(matches!(
            decoded,
            super::NegotiateContext::CompressionCapabilities(_)
        ));
    }

    #[test]
    fn should_encode_and_decode_encryption() {
        let cap = super::encryption::EncryptionCapabilitiesBuilder::default()
            .with_encryption_cipher(super::encryption::EncryptionCipher::Aes128Ccm);
        let cap = super::NegotiateContextBuilder::from(cap);
        let mut buf = Vec::with_capacity(256);
        cap.encode(&mut buf).unwrap();
        let decoded = super::NegotiateContext::parse(&mut BufferIterator(&buf)).unwrap();
        assert!(matches!(
            decoded,
            super::NegotiateContext::EncryptionCapabilities(_)
        ));
    }

    #[test]
    fn should_encode_and_decode_net_name() {
        let cap =
            super::net_name::NetNameNegotiateContextIdBuilder::new(String::from("hello world"));
        let cap = super::NegotiateContextBuilder::from(cap);
        let mut buf = Vec::with_capacity(256);
        cap.encode(&mut buf).unwrap();
        let decoded = super::NegotiateContext::parse(&mut BufferIterator(&buf)).unwrap();
        assert!(matches!(
            decoded,
            super::NegotiateContext::NetNameNegotiateContextId(_)
        ));
    }

    #[test]
    fn should_encode_and_decode_preauth_integrity() {
        let cap = super::preauth_integrity::PreauthIntegrityCapabilitiesBuilder::default()
            .with_hash_algorithm(super::preauth_integrity::HashAlgorithm::Sha512)
            .with_salt(vec![0; 4]);
        let cap = super::NegotiateContextBuilder::from(cap);
        let mut buf = Vec::with_capacity(256);
        cap.encode(&mut buf).unwrap();
        let decoded = super::NegotiateContext::parse(&mut BufferIterator(&buf)).unwrap();
        assert!(matches!(
            decoded,
            super::NegotiateContext::PreauthIntegrityCapabilities(_)
        ));
    }

    #[test]
    fn should_encode_and_decode_rdma_transform() {
        let cap = super::rdma_transform::RDMATransformCapabilitiesBuilder::default()
            .with_transform_id(super::rdma_transform::RDMATransformId::Encryption);
        let cap = super::NegotiateContextBuilder::from(cap);
        let mut buf = Vec::with_capacity(256);
        cap.encode(&mut buf).unwrap();
        let decoded = super::NegotiateContext::parse(&mut BufferIterator(&buf)).unwrap();
        assert!(matches!(
            decoded,
            super::NegotiateContext::RDMATransformCapabilities(_)
        ));
    }

    #[test]
    fn should_encode_and_decode_context_type_reserved() {
        let cap = super::NegotiateContextBuilder::ContextTypeReserved(vec![0, 1, 2, 3]);
        let mut buf = Vec::with_capacity(256);
        cap.encode(&mut buf).unwrap();
        let decoded = super::NegotiateContext::parse(&mut BufferIterator(&buf)).unwrap();
        assert!(matches!(
            decoded,
            super::NegotiateContext::ContextTypeReserved(_)
        ));
    }

    #[test]
    fn should_encode_and_decode_transport() {
        let cap = super::transport::TransportCapabilitiesBuilder::new(
            super::transport::TransportFlags::SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY,
        );
        let cap = super::NegotiateContextBuilder::TransportCapabilities(cap);
        let mut buf = Vec::with_capacity(256);
        cap.encode(&mut buf).unwrap();
        let decoded = super::NegotiateContext::parse(&mut BufferIterator(&buf)).unwrap();
        assert!(matches!(
            decoded,
            super::NegotiateContext::TransportCapabilities(_)
        ));
    }

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
