pub const PROTOCOL_ID: [u8; 4] = [0xFE, b'S', b'M', b'B'];

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("buffer too short")]
    BufferTooShort,
}

#[derive(Debug)]
pub struct Header {}

impl Header {
    pub fn parse(buffer: &[u8]) -> Result<Self, ParseError> {
        if buffer.len() < 64 {
            return Err(ParseError::BufferTooShort);
        }

        Ok(Self {})
    }
}
