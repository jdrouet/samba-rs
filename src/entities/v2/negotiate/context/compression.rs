use crate::entities::v2::negotiate::request::{EncodeError, ParseError};
use crate::entities::{u16_from_le_bytes, u32_from_le_bytes};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompressionFlags {
    /// SMB2_COMPRESSION_CAPABILITIES_FLAG_NONE: Chained compression is not supported.
    None,
    /// SMB2_COMPRESSION_CAPABILITIES_FLAG_CHAINED: Chained compression is supported on this connection.
    Chained,
}

impl TryFrom<u32> for CompressionFlags {
    type Error = u32;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Ok(match value {
            0x00 => Self::None,
            0x01 => Self::Chained,
            other => return Err(other),
        })
    }
}

impl CompressionFlags {
    pub const fn to_u32(&self) -> u32 {
        match self {
            Self::None => 0x00,
            Self::Chained => 0x01,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompressionAlgorithm {
    /// No compression
    None,
    /// LZNT1 compression algorithm
    LZNT1,
    /// LZ77 compression algorithm
    LZ77,
    /// LZ77+Huffman compression algorithm
    LZ77Huffman,
    /// Pattern Scanning algorithm
    PatternV1,
    /// LZ4 compression algorithm
    LZ4,
}

impl TryFrom<u16> for CompressionAlgorithm {
    type Error = u16;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(match value {
            0x0000 => Self::None,
            0x0001 => Self::LZNT1,
            0x0002 => Self::LZ77,
            0x0003 => Self::LZ77Huffman,
            0x0004 => Self::PatternV1,
            0x0005 => Self::LZ4,
            other => return Err(other),
        })
    }
}

impl CompressionAlgorithm {
    pub const fn to_u16(&self) -> u16 {
        match self {
            Self::None => 0x0000,
            Self::LZNT1 => 0x0001,
            Self::LZ77 => 0x0002,
            Self::LZ77Huffman => 0x0003,
            Self::PatternV1 => 0x0004,
            Self::LZ4 => 0x0005,
        }
    }
}

/// The SMB2_COMPRESSION_CAPABILITIES context is specified in an SMB2 NEGOTIATE request by the
/// client to indicate which compression algorithms the client supports. The format of the data in the Data
/// field of this SMB2_NEGOTIATE_CONTEXT is as follows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompressionCapabilities<'a> {
    /// CompressionAlgorithmCount (2 bytes)
    ///
    /// The number of elements in CompressionAlgorithms array.
    pub compression_algorithm_count: u16,
    /// Flags (4 bytes)
    ///
    /// This field MUST be set to one of the following values
    pub flags: CompressionFlags,
    /// CompressionAlgorithms (variable)
    ///
    /// An array of 16-bit integer IDs specifying the supported compression algorithms.
    /// These IDs MUST be in order of preference from most to least. The following IDs are defined.
    pub compression_algorithms: &'a [u8],
}

impl<'a> CompressionCapabilities<'a> {
    pub fn compression_algorithms(
        &self,
    ) -> impl Iterator<Item = Result<CompressionAlgorithm, ParseError>> {
        self.compression_algorithms
            .chunks(2)
            .map(u16_from_le_bytes)
            .map(|value| {
                CompressionAlgorithm::try_from(value)
                    .map_err(ParseError::InvalidCompressionAlgorithm)
            })
    }
}

impl<'a> CompressionCapabilities<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<Self, ParseError> {
        let compression_algorithm_count = buf
            .get(0..2)
            .map(u16_from_le_bytes)
            .ok_or(ParseError::BufferTooShort)?;
        // padding
        let flags = buf.get(4..8).ok_or(ParseError::BufferTooShort)?;
        let flags = CompressionFlags::try_from(u32_from_le_bytes(flags))
            .map_err(ParseError::InvalidCompressionFlag)?;

        let end = 8 + (compression_algorithm_count as usize) * 2;
        let compression_algorithms = &buf.get(8..end).ok_or(ParseError::BufferTooShort)?;

        Ok(Self {
            compression_algorithm_count,
            flags,
            compression_algorithms,
        })
    }
}

#[derive(Clone, Debug)]
pub struct CompressionCapabilitiesBuilder {
    pub flags: CompressionFlags,
    pub compression_algorithms: Vec<CompressionAlgorithm>,
}

impl CompressionCapabilitiesBuilder {
    pub fn new(flags: CompressionFlags) -> Self {
        Self {
            flags,
            compression_algorithms: Default::default(),
        }
    }

    pub fn with_algorithm(mut self, value: CompressionAlgorithm) -> Self {
        self.compression_algorithms.push(value);
        self
    }

    pub fn encode<W: std::io::Write>(&self, buf: &mut W) -> Result<(), EncodeError> {
        let length = u16::try_from(self.compression_algorithms.len())
            .map_err(|_| EncodeError::NumberOutOfBound)?;
        buf.write(&length.to_le_bytes())?;
        buf.write(&[0, 0u8])?;
        buf.write(&self.flags.to_u32().to_le_bytes())?;
        for item in &self.compression_algorithms {
            buf.write(&item.to_u16().to_le_bytes())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::BufWriter;

    #[test]
    fn should_encode_and_parse() {
        let mut buf = BufWriter::new(Vec::with_capacity(1024));
        super::CompressionCapabilitiesBuilder::new(super::CompressionFlags::None)
            .with_algorithm(super::CompressionAlgorithm::LZ77Huffman)
            .with_algorithm(super::CompressionAlgorithm::LZNT1)
            .encode(&mut buf)
            .unwrap();
        let buf = buf.into_inner().unwrap();
        let res = super::CompressionCapabilities::parse(&buf).unwrap();
        assert_eq!(res.compression_algorithm_count, 2);
    }

    #[test]
    fn should_parse() {
        let cap = super::CompressionCapabilities::parse(&[0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert!(cap.compression_algorithms().next().is_none());
        let cap = super::CompressionCapabilities::parse(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(
            cap.compression_algorithms().next().unwrap().unwrap(),
            super::CompressionAlgorithm::None
        );
    }

    #[test]
    fn should_fail_parse_with_invalid_size() {
        let err = super::CompressionCapabilities::parse(&[0]).unwrap_err();
        assert_eq!(err, super::ParseError::BufferTooShort);
        let err = super::CompressionCapabilities::parse(&[0, 0, 0]).unwrap_err();
        assert_eq!(err, super::ParseError::BufferTooShort);
        let err = super::CompressionCapabilities::parse(&[0, 0, 0, 0, 0]).unwrap_err();
        assert_eq!(err, super::ParseError::BufferTooShort);
        let err = super::CompressionCapabilities::parse(&[0, 0, 0, 0, 0]).unwrap_err();
        assert_eq!(err, super::ParseError::BufferTooShort);
        let err =
            super::CompressionCapabilities::parse(&[2, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap_err();
        assert_eq!(err, super::ParseError::BufferTooShort);
    }

    #[test]
    fn should_fail_parse_with_invalid_flags() {
        let err = super::CompressionCapabilities::parse(&[0, 0, 0, 0, 2, 0, 0, 0]).unwrap_err();
        assert_eq!(err, super::ParseError::InvalidCompressionFlag(2));
    }

    #[test]
    fn should_fail_parse_with_invalid_algorithm() {
        let cap = super::CompressionCapabilities::parse(&[1, 0, 0, 0, 0, 0, 0, 0, 6, 0]).unwrap();
        let err = cap.compression_algorithms().next().unwrap().unwrap_err();
        assert_eq!(err, super::ParseError::InvalidCompressionAlgorithm(6));
    }
}
