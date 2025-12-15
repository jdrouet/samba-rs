use crate::entities::u16_from_le_bytes;
use crate::entities::v2::negotiate::request::ParseError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum EncryptionCipher {
    Aes128Ccm = 0x0001,
    Aes128Gcm = 0x0002,
    Aes256Ccm = 0x0003,
    Aes256Gcm = 0x0004,
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
    #[inline]
    pub const fn to_u16(&self) -> u16 {
        *self as u16
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

#[cfg(test)]
mod tests {
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
