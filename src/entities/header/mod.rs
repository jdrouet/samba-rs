pub mod v1;
pub mod v2;

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("buffer too short")]
    BufferTooShort,
    #[error("unknown protocol")]
    UnknownProtocol,
    #[error(transparent)]
    V1(v1::ParseError),
    #[error(transparent)]
    V2(v2::ParseError),
}

#[derive(Debug)]
pub enum Header {
    V1(v1::Header),
    V2(v2::Header),
}

impl Header {
    pub fn parse(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < 4 {
            return Err(ParseError::BufferTooShort);
        }
        if buf.starts_with(&v1::PROTOCOL_ID) {
            v1::Header::parse(buf).map(Self::V1).map_err(ParseError::V1)
        } else if buf.starts_with(&v2::PROTOCOL_ID) {
            v2::Header::parse(buf).map(Self::V2).map_err(ParseError::V2)
        } else {
            Err(ParseError::UnknownProtocol)
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn should_fail_with_small_buffer() {
        for i in 0..4 {
            assert!(matches!(
                super::Header::parse(&vec![0u8; i]).unwrap_err(),
                super::ParseError::BufferTooShort
            ));
        }
    }

    #[test]
    fn should_fail_with_invalid_protocol() {
        for buf in (0..255)
            .zip(0..255)
            .zip(0..255)
            .zip(0..255)
            .map(|(((a, b), c), d)| [a, b, c, d])
            .filter(|item| !super::v1::PROTOCOL_ID.eq(item) && !super::v2::PROTOCOL_ID.eq(item))
        {
            assert!(matches!(
                super::Header::parse(&buf).unwrap_err(),
                super::ParseError::UnknownProtocol
            ));
        }
    }
}
