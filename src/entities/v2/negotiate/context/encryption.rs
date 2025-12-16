use crate::entities::u16_from_le_bytes;
use crate::entities::v2::negotiate::request::{EncodeError, ParseError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncryptionCipher {
    Aes128Ccm,
    Aes128Gcm,
    Aes256Ccm,
    Aes256Gcm,
}

impl TryFrom<u16> for EncryptionCipher {
    type Error = u16;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(match value {
            0x0001 => Self::Aes128Ccm,
            0x0002 => Self::Aes128Gcm,
            0x0003 => Self::Aes256Ccm,
            0x0004 => Self::Aes256Gcm,
            other => return Err(other),
        })
    }
}

impl EncryptionCipher {
    pub const fn to_u16(&self) -> u16 {
        match self {
            Self::Aes128Ccm => 0x0001,
            Self::Aes128Gcm => 0x0002,
            Self::Aes256Ccm => 0x0003,
            Self::Aes256Gcm => 0x0004,
        }
    }
}

/// The SMB2_ENCRYPTION_CAPABILITIES context is specified in an SMB2 NEGOTIATE request by the client to
/// indicate which encryption algorithms the client supports. The format of the data in the Data field of this
// SMB2_NEGOTIATE_CONTEXT is as follows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncryptionCapabilities<'a> {
    pub cipher_count: u16,
    pub ciphers: &'a [u8],
}

impl<'a> EncryptionCapabilities<'a> {
    pub fn ciphers(&self) -> impl Iterator<Item = Result<EncryptionCipher, ParseError>> {
        self.ciphers.chunks(2).map(u16_from_le_bytes).map(|value| {
            EncryptionCipher::try_from(value).map_err(ParseError::InvalidEncryptionCipher)
        })
    }
}

impl<'a> EncryptionCapabilities<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<Self, ParseError> {
        let cipher_count = buf
            .get(0..2)
            .map(u16_from_le_bytes)
            .ok_or(ParseError::BufferTooShort)?;
        if cipher_count == 0 {
            return Err(ParseError::NoEncryptionCipherProvided);
        }

        let ciphers_end = 2 + (cipher_count * 2) as usize;
        let ciphers = buf.get(2..ciphers_end).ok_or(ParseError::BufferTooShort)?;
        Ok(Self {
            cipher_count,
            ciphers,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct EncryptionCapabilitiesBuilder {
    pub ciphers: Vec<EncryptionCipher>,
}

impl EncryptionCapabilitiesBuilder {
    pub fn with_encryption_cipher(mut self, item: EncryptionCipher) -> Self {
        self.ciphers.push(item);
        self
    }

    pub fn encode<W: std::io::Write>(&self, buf: &mut W) -> Result<(), EncodeError> {
        let length =
            u16::try_from(self.ciphers.len()).map_err(|_| EncodeError::NumberOutOfBound)?;
        buf.write(&length.to_le_bytes())?;
        for item in &self.ciphers {
            buf.write(&item.to_u16().to_le_bytes())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::BufWriter;

    #[test]
    fn should_encode_decode() {
        let mut buf = BufWriter::new(Vec::with_capacity(1024));
        super::EncryptionCapabilitiesBuilder::default()
            .with_encryption_cipher(super::EncryptionCipher::Aes128Ccm)
            .encode(&mut buf)
            .unwrap();
        let buf = buf.into_inner().unwrap();
        let cap = super::EncryptionCapabilities::parse(&buf).unwrap();
        assert_eq!(cap.cipher_count, 1);
        let _ = cap.ciphers().collect::<Vec<_>>();
    }

    #[test]
    fn should_parse() {
        let cap = super::EncryptionCapabilities::parse(&[1, 0, 1, 0]).unwrap();
        let _ = cap.ciphers().collect::<Vec<_>>();
    }

    #[test]
    fn should_fail_parse_invalid_size() {
        let err = super::EncryptionCapabilities::parse(&[]).unwrap_err();
        assert_eq!(err, super::ParseError::BufferTooShort);
        let err = super::EncryptionCapabilities::parse(&[1, 0, 0]).unwrap_err();
        assert_eq!(err, super::ParseError::BufferTooShort);
        let err = super::EncryptionCapabilities::parse(&[2, 0, 0]).unwrap_err();
        assert_eq!(err, super::ParseError::BufferTooShort);
        let err = super::EncryptionCapabilities::parse(&[2, 0, 0, 0]).unwrap_err();
        assert_eq!(err, super::ParseError::BufferTooShort);
        let err = super::EncryptionCapabilities::parse(&[2, 0, 0, 0, 0]).unwrap_err();
        assert_eq!(err, super::ParseError::BufferTooShort);
    }

    #[test]
    fn should_fail_parse_empty() {
        let err = super::EncryptionCapabilities::parse(&[0, 0]).unwrap_err();
        assert_eq!(err, super::ParseError::NoEncryptionCipherProvided);
    }

    #[test]
    fn should_parse_cipher() {
        for cipher in [
            super::EncryptionCipher::Aes128Ccm,
            super::EncryptionCipher::Aes128Gcm,
            super::EncryptionCipher::Aes256Ccm,
            super::EncryptionCipher::Aes256Gcm,
        ] {
            assert_eq!(
                cipher,
                super::EncryptionCipher::try_from(cipher.to_u16()).unwrap()
            );
        }
    }

    #[test]
    fn should_fail_parse_unknown_cipher() {
        assert_eq!(0, super::EncryptionCipher::try_from(0).unwrap_err());
        for value in 5u16..=u16::MAX {
            assert_eq!(value, super::EncryptionCipher::try_from(value).unwrap_err());
        }
    }
}
