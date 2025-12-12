#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("buffer too short")]
    BufferTooShort,
    #[error("invalid header")]
    InvalidHeader,
}

#[derive(Debug)]
/// NetBios Header
///
/// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/1dfacde4-b5c7-4494-8a14-a09d3ab4cc83
pub struct Header {
    // StreamProtocolLength (3 bytes): The length, in bytes, of the SMB2Message in network byte order.
    // This field does not include the 4-byte Direct TCP transport packet header;
    // rather, it is only the length of the enclosed SMB2Message.
    length: u32,
}

impl Header {
    pub fn length(&self) -> u32 {
        self.length
    }
}

impl Header {
    pub fn parse(buffer: &[u8]) -> Result<Self, ParseError> {
        if buffer.len() < 4 {
            return Err(ParseError::BufferTooShort);
        }
        // The first byte of the Direct TCP transport packet header MUST be zero (0x00).
        if buffer[0] != 0 {
            return Err(ParseError::InvalidHeader);
        }

        let mut buf = [0u8; 4];
        buf.copy_from_slice(&buffer[0..4]);
        Ok(Self {
            length: u32::from_be_bytes(buf),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BuilderError {
    #[error("length too big for header")]
    LengthTooBig,
}

impl Header {
    pub fn new(value: u32) -> Result<Self, BuilderError> {
        if value >= 0x01_00_00_00 {
            return Err(BuilderError::LengthTooBig);
        }
        Ok(Self { length: value })
    }

    pub fn encode(&self) -> [u8; 4] {
        self.length.to_be_bytes()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn should_parse_netbios() {
        for i in 0..24 {
            let value = 1u32 << i;
            let buffer = value.to_be_bytes();
            let header = super::Header::parse(&buffer).unwrap();
            assert_eq!(header.length(), value);
        }
    }

    #[test]
    fn should_fail_parse_netbios_if_doesnt_start_with_0() {
        for h in 0..8 {
            let head = 1u8 << h;
            for i in 0..24 {
                let value = 1u32 << i;
                let mut buffer = value.to_be_bytes();
                buffer[0] = head;
                let err = super::Header::parse(&buffer).unwrap_err();
                assert!(matches!(err, super::ParseError::InvalidHeader));
            }
        }
    }

    #[test]
    fn should_fail_parse_netbios_if_too_short() {
        let buffer = [0u8; 3];
        let err = super::Header::parse(&buffer).unwrap_err();
        assert!(matches!(err, super::ParseError::BufferTooShort));
    }

    #[test]
    fn should_encode_properly() {
        for i in 0..0x01_00_00_00 {
            let header = super::Header::new(i).unwrap();
            assert_eq!(header.encode(), i.to_be_bytes());
        }
    }

    #[test]
    fn should_fail_building_header() {
        for h in 0..8 {
            let head = 1u8 << h;
            for i in 0..24 {
                let value = 1u32 << i;
                let mut buffer = value.to_be_bytes();
                buffer[0] = head;
                let value = u32::from_be_bytes(buffer);
                let err = super::Header::new(value).unwrap_err();
                assert!(matches!(err, super::BuilderError::LengthTooBig));
            }
        }
    }
}
