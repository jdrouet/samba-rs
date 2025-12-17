use crate::entities::u16_from_le_bytes;
use crate::entities::v2::negotiate::request::{EncodeError, ParseError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RDMATransformId {
    /// SMB2_RDMA_TRANSFORM_NONE
    ///
    /// 0x0000
    None,
    /// SMB2_RDMA_TRANSFORM_ENCRYPTION
    ///
    /// 0x0001
    ///
    /// Encryption of data sent over RDMA.
    Encryption,
    /// SMB2_RDMA_TRANSFORM_SIGNING
    ///
    /// 0x0002
    ///
    /// Signing of data sent over RDMA.
    Signing,
}

impl TryFrom<u16> for RDMATransformId {
    type Error = u16;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(match value {
            0x0000 => Self::None,
            0x0001 => Self::Encryption,
            0x0002 => Self::Signing,
            other => return Err(other),
        })
    }
}

impl RDMATransformId {
    pub const fn to_u16(&self) -> u16 {
        match self {
            Self::None => 0x0000,
            Self::Encryption => 0x0001,
            Self::Signing => 0x0002,
        }
    }

    pub fn encode<W: std::io::Write>(&self, buf: &mut W) -> std::io::Result<()> {
        buf.write(&self.to_u16().to_le_bytes()).map(|_| ())
    }
}

/// The SMB2_RDMA_TRANSFORM_CAPABILITIES context is specified in an SMB2 NEGOTIATE request by
/// the client to indicate the transforms supported when data is sent over RDMA.
/// The format of the data in the Data field of this SMB2_NEGOTIATE_CONTEXT is as follows
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RDMATransformCapabilities<'a> {
    /// TransformCount (2 bytes)
    ///
    /// The number of elements in RDMATransformIds array. This value MUST be greater than 0.
    pub transform_count: u16,
    /// RDMATransformIds (variable)
    ///
    /// An array of 16-bit integer IDs specifying the supported RDMA transforms.
    /// The following IDs are defined.
    pub transform_ids: &'a [u8],
}

impl<'a> RDMATransformCapabilities<'a> {
    pub fn transform_ids(&self) -> impl Iterator<Item = Result<RDMATransformId, ParseError>> {
        self.transform_ids
            .chunks(2)
            .map(u16_from_le_bytes)
            .map(|value| RDMATransformId::try_from(value).map_err(ParseError::InvalidTransformId))
    }
}

impl<'a> RDMATransformCapabilities<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<Self, ParseError> {
        let transform_count = buf.get(0..2).ok_or(ParseError::BufferTooShort)?;
        let transform_count = u16_from_le_bytes(transform_count);

        if transform_count == 0 {
            return Err(ParseError::NoRDMATransformProvided);
        }

        let end = 8 + (transform_count as usize) * 2;
        let transform_ids = buf.get(8..end).ok_or(ParseError::BufferTooShort)?;

        Ok(Self {
            transform_count,
            transform_ids,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct RDMATransformCapabilitiesBuilder {
    pub transform_ids: Vec<RDMATransformId>,
}

impl RDMATransformCapabilitiesBuilder {
    pub fn with_transform_id(mut self, item: RDMATransformId) -> Self {
        self.transform_ids.push(item);
        self
    }

    pub fn size(&self) -> usize {
        8 + self.transform_ids.len() * 2
    }

    pub fn encode<W: std::io::Write>(&self, buf: &mut W) -> Result<(), EncodeError> {
        if self.transform_ids.is_empty() {
            return Err(EncodeError::NoRDMATransformProvided);
        }

        let length =
            u16::try_from(self.transform_ids.len()).map_err(|_| EncodeError::NumberOutOfBound)?;
        buf.write(&length.to_le_bytes())?;
        buf.write(&[0, 0, 0, 0, 0, 0u8])?;
        for item in &self.transform_ids {
            item.encode(buf)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::BufWriter;

    #[test]
    fn should_convert_transform_to_u16() {
        assert_eq!(super::RDMATransformId::None.to_u16(), 0);
        assert_eq!(super::RDMATransformId::Encryption.to_u16(), 1);
        assert_eq!(super::RDMATransformId::Signing.to_u16(), 2);
    }

    #[test]
    fn should_compute_size() {
        let item = super::RDMATransformCapabilitiesBuilder::default();
        assert_eq!(item.size(), 8);
        let item = item.with_transform_id(super::RDMATransformId::None);
        assert_eq!(item.size(), 10);
        let item = item.with_transform_id(super::RDMATransformId::Encryption);
        assert_eq!(item.size(), 12);
    }

    #[test]
    fn should_fail_encoding_empty() {
        let cap = super::RDMATransformCapabilitiesBuilder::default();
        let mut buf_writer = BufWriter::new(Vec::with_capacity(1024));
        let err = cap.encode(&mut buf_writer).unwrap_err();
        assert!(matches!(err, super::EncodeError::NoRDMATransformProvided));
    }

    #[test]
    fn should_encode_and_decode() {
        let cap = super::RDMATransformCapabilitiesBuilder::default()
            .with_transform_id(super::RDMATransformId::Encryption);
        let mut buf_writer = BufWriter::new(Vec::with_capacity(1024));
        cap.encode(&mut buf_writer).unwrap();
        let buffer = buf_writer.into_inner().unwrap();
        let value = super::RDMATransformCapabilities::parse(&buffer).unwrap();
        assert_eq!(value.transform_count, 1);
    }

    #[test]
    fn should_fail_parse_invalid_id() {
        let cap = super::RDMATransformCapabilities::parse(&[1, 0, 0, 0, 0, 0, 0, 0, 8, 0]).unwrap();
        let err = cap.transform_ids().next().unwrap().unwrap_err();
        assert_eq!(err, super::ParseError::InvalidTransformId(8));
    }

    #[test]
    fn should_fail_parse_buffer_too_small() {
        let err = super::RDMATransformCapabilities::parse(&[1]).unwrap_err();
        assert_eq!(err, super::ParseError::BufferTooShort);
        let err = super::RDMATransformCapabilities::parse(&[1, 0, 0]).unwrap_err();
        assert_eq!(err, super::ParseError::BufferTooShort);
    }

    #[test]
    fn should_fail_parse_empty() {
        let err = super::RDMATransformCapabilities::parse(&[0, 0, 0, 0, 0, 0, 0, 0]).unwrap_err();
        assert_eq!(err, super::ParseError::NoRDMATransformProvided);
    }

    #[test]
    fn should_parse() {
        let cap = super::RDMATransformCapabilities::parse(&[1, 0, 0, 0, 0, 0, 0, 0, 1, 0]).unwrap();
        let _ = cap.transform_ids().collect::<Vec<_>>();
    }
}
