use crate::entities::u16_from_le_bytes;
use crate::entities::v2::negotiate::request::{EncodeError, ParseError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-512 as specified in [FIPS180-4]
    Sha512,
}

impl TryFrom<u16> for HashAlgorithm {
    type Error = u16;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(match value {
            0x0001 => Self::Sha512,
            other => return Err(other),
        })
    }
}

impl HashAlgorithm {
    pub const fn to_u16(&self) -> u16 {
        // match self {
        //     Self::Sha512 => 0x0001,
        // }
        1
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreauthIntegrityCapabilities<'a> {
    /// HashAlgorithmCount (2 bytes)
    ///
    /// The number of hash algorithms in the HashAlgorithms array. This value MUST be greater than zero.
    pub hash_algorithm_count: u16,
    /// SaltLength (2 bytes)
    ///
    /// The size, in bytes, of the Salt field.
    pub salt_length: u16,
    /// HashAlgorithms (variable)
    ///
    /// An array of HashAlgorithmCount 16-bit integer IDs specifying the supported preauthentication
    /// integrity hash functions. The following IDs are defined.
    pub hash_algorithms: &'a [u8],
    /// Salt (variable)
    ///
    /// A buffer containing the salt value of the hash.
    pub salt: &'a [u8],
}

impl<'a> PreauthIntegrityCapabilities<'a> {
    pub fn hash_algorithms(&self) -> impl Iterator<Item = Result<HashAlgorithm, ParseError>> {
        self.hash_algorithms
            .chunks(2)
            .map(u16_from_le_bytes)
            .map(|value| HashAlgorithm::try_from(value).map_err(ParseError::InvalidHashAlgorithm))
    }
}

impl<'a> PreauthIntegrityCapabilities<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<Self, ParseError> {
        let hash_algorithm_count = buf
            .get(0..2)
            .map(u16_from_le_bytes)
            .ok_or(ParseError::BufferTooShort)?;
        if hash_algorithm_count == 0 {
            return Err(ParseError::NoHashAlgorithmProvided);
        }

        let salt_length = buf
            .get(2..4)
            .map(u16_from_le_bytes)
            .ok_or(ParseError::BufferTooShort)?;

        let hash_algorithms_end = (4 + hash_algorithm_count * 2) as usize;
        let hash_algorithms = buf
            .get(4..hash_algorithms_end)
            .ok_or(ParseError::BufferTooShort)?;

        let salt_end = hash_algorithms_end + (salt_length as usize);
        let salt = buf
            .get(hash_algorithms_end..salt_end)
            .ok_or(ParseError::BufferTooShort)?;

        Ok(Self {
            hash_algorithm_count,
            salt_length,
            hash_algorithms,
            salt,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct PreauthIntegrityCapabilitiesBuilder {
    pub salt: Vec<u8>,
    pub hash_algorithms: Vec<HashAlgorithm>,
}

impl PreauthIntegrityCapabilitiesBuilder {
    pub fn with_hash_algorithm(mut self, value: HashAlgorithm) -> Self {
        self.hash_algorithms.push(value);
        self
    }

    pub fn with_salt(mut self, value: Vec<u8>) -> Self {
        self.salt = value;
        self
    }

    pub fn size(&self) -> usize {
        // hash_algorithm_count(2) + salt_length(2) + hash_algorithm_count * 2 + salt_length
        4 + self.hash_algorithms.len() * 2 + self.salt.len()
    }

    pub fn encode<W: std::io::Write>(&self, buf: &mut W) -> Result<(), EncodeError> {
        if self.hash_algorithms.is_empty() {
            return Err(EncodeError::NoHashAlgorithmProvided);
        }

        let hash_algorithm_count =
            u16::try_from(self.hash_algorithms.len()).map_err(|_| EncodeError::NumberOutOfBound)?;
        let salt_length =
            u16::try_from(self.salt.len()).map_err(|_| EncodeError::NumberOutOfBound)?;

        buf.write_all(&hash_algorithm_count.to_le_bytes())?;
        buf.write_all(&salt_length.to_le_bytes())?;
        for algorithm in &self.hash_algorithms {
            buf.write_all(&algorithm.to_u16().to_le_bytes())?;
        }
        buf.write_all(self.salt.as_slice())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::BufWriter;

    #[test]
    fn should_convert_to_u16() {
        assert_eq!(super::HashAlgorithm::Sha512.to_u16(), 0x0001);
    }

    #[test]
    fn should_compute_size() {
        let size = super::PreauthIntegrityCapabilitiesBuilder::default().size();
        assert_eq!(size, 4);
        let size = super::PreauthIntegrityCapabilitiesBuilder::default()
            .with_hash_algorithm(super::HashAlgorithm::Sha512)
            .size();
        assert_eq!(size, 6);
        let size = super::PreauthIntegrityCapabilitiesBuilder::default()
            .with_hash_algorithm(super::HashAlgorithm::Sha512)
            .with_salt(vec![0, 1, 2, 3, 4, 5])
            .size();
        assert_eq!(size, 12);
    }

    #[test]
    fn should_encode_and_parse() {
        let mut buf = BufWriter::new(Vec::with_capacity(1024));
        super::PreauthIntegrityCapabilitiesBuilder::default()
            .with_hash_algorithm(super::HashAlgorithm::Sha512)
            .with_salt(vec![1, 2, 3, 4])
            .encode(&mut buf)
            .unwrap();
        let buf = buf.into_inner().unwrap();
        let cap = super::PreauthIntegrityCapabilities::parse(&buf).unwrap();
        assert_eq!(cap.hash_algorithm_count, 1);
        assert_eq!(cap.salt_length, 4);
        assert_eq!(cap.salt, &[1, 2, 3, 4]);
    }

    #[test]
    fn should_parse() {
        let cap = super::PreauthIntegrityCapabilities::parse(&[1, 0, 0, 0, 1, 0]).unwrap();
        let _ = cap.hash_algorithms.iter().collect::<Vec<_>>();
    }

    #[test]
    fn should_fail_parse_small_buffer() {
        let err = super::PreauthIntegrityCapabilities::parse(&[1]).unwrap_err();
        assert_eq!(err, super::ParseError::BufferTooShort);
        let err = super::PreauthIntegrityCapabilities::parse(&[1, 0, 0]).unwrap_err();
        assert_eq!(err, super::ParseError::BufferTooShort);
        let err = super::PreauthIntegrityCapabilities::parse(&[1, 0, 0, 0]).unwrap_err();
        assert_eq!(err, super::ParseError::BufferTooShort);
        let err = super::PreauthIntegrityCapabilities::parse(&[1, 0, 1, 0, 1]).unwrap_err();
        assert_eq!(err, super::ParseError::BufferTooShort);
        let err = super::PreauthIntegrityCapabilities::parse(&[1, 0, 2, 0, 1, 0]).unwrap_err();
        assert_eq!(err, super::ParseError::BufferTooShort);
    }

    #[test]
    fn should_fail_parse_without_hash_algorithm() {
        let err = super::PreauthIntegrityCapabilities::parse(&[0, 0, 0, 0]).unwrap_err();
        assert_eq!(err, super::ParseError::NoHashAlgorithmProvided);
    }

    #[test]
    fn should_fail_parse_with_invalid_hash_algorithm() {
        let value = super::PreauthIntegrityCapabilities::parse(&[1, 0, 0, 0, 4, 0]).unwrap();
        let err = value.hash_algorithms().next().unwrap().unwrap_err();
        assert_eq!(err, super::ParseError::InvalidHashAlgorithm(4));
    }
}
