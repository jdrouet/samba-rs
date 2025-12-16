use crate::entities::u16_from_le_bytes;
use crate::entities::v2::negotiate::request::{EncodeError, ParseError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningAlgorithm {
    /// 0x0000 HMAC-SHA256
    HmacSha256,
    /// 0x0001 AES-CMAC
    AesCmac,
    /// 0x0002 AES-GMAC
    AesGmac,
}

impl TryFrom<u16> for SigningAlgorithm {
    type Error = u16;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(match value {
            0x0000 => Self::HmacSha256,
            0x0001 => Self::AesCmac,
            0x0002 => Self::AesGmac,
            other => return Err(other),
        })
    }
}

impl SigningAlgorithm {
    pub const fn to_u16(&self) -> u16 {
        match self {
            Self::HmacSha256 => 0x0000,
            Self::AesCmac => 0x0001,
            Self::AesGmac => 0x0002,
        }
    }

    pub fn encode<W: std::io::Write>(&self, buf: &mut W) -> std::io::Result<()> {
        buf.write(&self.to_u16().to_le_bytes()).map(|_| ())
    }
}

/// The SMB2_SIGNING_CAPABILITIES context is specified in an SMB2 NEGOTIATE request by
/// the client to indicate which signing algorithms the client supports. The format of
/// the data in the Data field of this SMB2_NEGOTIATE_CONTEXT is as follows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigningCapabilities<'a> {
    /// SigningAlgorithmCount (2 bytes)
    /// The number of signing algorithms in the SigningAlgorithms array.
    /// This value MUST be greater than zero.
    pub signing_algorithm_count: u16,
    /// SigningAlgorithms (variable)
    ///
    /// An array of 16-bit integer IDs specifying the supported signing algorithms.
    /// These IDs MUST be in an order such that the most preferred signing algorithm
    /// MUST be at the beginning of the array and least preferred signing algorithm
    /// at the end of the array. The following IDs are defined.
    pub signing_algorithms: &'a [u8],
}

impl<'a> SigningCapabilities<'a> {
    pub fn signing_algorithms(&self) -> impl Iterator<Item = Result<SigningAlgorithm, ParseError>> {
        self.signing_algorithms
            .chunks(2)
            .map(u16_from_le_bytes)
            .map(|value| {
                SigningAlgorithm::try_from(value).map_err(ParseError::InvalidSigningAlgorithm)
            })
    }
}

impl<'a> SigningCapabilities<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<Self, ParseError> {
        let signing_algorithm_count = buf.get(0..2).ok_or(ParseError::BufferTooShort)?;
        let signing_algorithm_count = u16_from_le_bytes(signing_algorithm_count);

        if signing_algorithm_count == 0 {
            return Err(ParseError::NoSigningAlgorithmProvided);
        }

        let end = 2 + (signing_algorithm_count as usize) * 2;
        let signing_algorithms = buf.get(2..end).ok_or(ParseError::BufferTooShort)?;

        Ok(Self {
            signing_algorithm_count,
            signing_algorithms,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct SigningCapabilitiesBuilder {
    pub signing_algorithms: Vec<SigningAlgorithm>,
}

impl SigningCapabilitiesBuilder {
    pub fn with_signing_algorithm(mut self, item: SigningAlgorithm) -> Self {
        self.signing_algorithms.push(item);
        self
    }

    pub fn encode<W: std::io::Write>(&self, buf: &mut W) -> Result<(), EncodeError> {
        if self.signing_algorithms.is_empty() {
            return Err(EncodeError::NoSigningAlgorithmProvided);
        }

        let length = u16::try_from(self.signing_algorithms.len())
            .map_err(|_| EncodeError::NumberOutOfBound)?;
        buf.write(&length.to_le_bytes())?;
        for item in &self.signing_algorithms {
            item.encode(buf)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::BufWriter;

    #[test]
    fn should_fail_encoding_empty() {
        let cap = super::SigningCapabilitiesBuilder::default();
        let mut buf_writer = BufWriter::new(Vec::with_capacity(1024));
        let err = cap.encode(&mut buf_writer).unwrap_err();
        assert!(matches!(
            err,
            super::EncodeError::NoSigningAlgorithmProvided
        ));
    }

    #[test]
    fn should_encode_and_decode() {
        let cap = super::SigningCapabilitiesBuilder::default()
            .with_signing_algorithm(super::SigningAlgorithm::HmacSha256);
        let mut buf_writer = BufWriter::new(Vec::with_capacity(1024));
        cap.encode(&mut buf_writer).unwrap();
        let buffer = buf_writer.into_inner().unwrap();
        let value = super::SigningCapabilities::parse(&buffer).unwrap();
        assert_eq!(value.signing_algorithm_count, 1);
    }

    #[test]
    fn should_fail_parse_invalid_algorithm() {
        let cap = super::SigningCapabilities::parse(&[1, 0, 42, 0]).unwrap();
        let err = cap.signing_algorithms().next().unwrap().unwrap_err();
        assert_eq!(err, super::ParseError::InvalidSigningAlgorithm(42));
    }
    #[test]
    fn should_fail_parse_empty() {
        let err = super::SigningCapabilities::parse(&[0, 0]).unwrap_err();
        assert_eq!(err, super::ParseError::NoSigningAlgorithmProvided);
    }
    #[test]
    fn should_fail_parse_invalid_size() {
        let err = super::SigningCapabilities::parse(&[0]).unwrap_err();
        assert_eq!(err, super::ParseError::BufferTooShort);
        let err = super::SigningCapabilities::parse(&[1, 0, 0]).unwrap_err();
        assert_eq!(err, super::ParseError::BufferTooShort);
    }
    #[test]
    fn should_parse() {
        let cap = super::SigningCapabilities::parse(&[1, 0, 0, 0]).unwrap();
        let _ = cap.signing_algorithms().collect::<Vec<_>>();
    }
}
