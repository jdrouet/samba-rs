use crate::entities::BufferReader;
use std::str::Utf8Error;

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum ParseError {
    #[error("buffer too short")]
    BufferTooShort,
    #[error("invalid utf8 in dialect string")]
    InvalidUtf8(#[from] Utf8Error),
    #[error("invalid dialect format")]
    InvalidDialectFormat,
    #[error("missing null terminator")]
    MissingNullTerminator,
}

#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("number ouf of bound")]
    NumberOutOfBound,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Request<'a> {
    data: &'a [u8],
}

impl<'a> Request<'a> {
    pub fn parse(buf: &mut BufferReader<'a>) -> Result<Self, ParseError> {
        let byte_count = buf.next_u16().ok_or(ParseError::BufferTooShort)?;
        if byte_count == 0 {
            return Ok(Self { data: &[] });
        }
        let data = buf
            .next(byte_count as usize)
            .ok_or(ParseError::BufferTooShort)?;
        Ok(Self { data })
    }

    pub fn dialects(&self) -> impl Iterator<Item = Result<&'a str, ParseError>> {
        self.data
            .chunk_by(|a, b| *a != b'\0' && *b != 0x02)
            .map(|item| {
                let Some((head, item)) = item.split_first() else {
                    return Err(ParseError::BufferTooShort);
                };
                if *head != 0x02 {
                    return Err(ParseError::InvalidDialectFormat);
                }
                let Some((tail, item)) = item.split_last() else {
                    return Err(ParseError::BufferTooShort);
                };
                if *tail != b'\0' {
                    return Err(ParseError::MissingNullTerminator);
                }

                std::str::from_utf8(item).map_err(ParseError::InvalidUtf8)
            })
    }
}

#[derive(Debug, Default)]
pub struct RequestBuilder {
    dialects: Vec<String>,
}

impl RequestBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_dialect(mut self, dialect: &str) -> Self {
        self.dialects.push(dialect.to_string());
        self
    }

    fn buffer_size(&self) -> usize {
        self.dialects.iter().map(|item| item.len() + 2).sum()
    }

    pub fn encode<W: std::io::Write>(&self, buf: &mut W) -> Result<(), EncodeError> {
        let mut dialects_data = Vec::with_capacity(self.buffer_size());
        for dialect in &self.dialects {
            dialects_data.push(0x02);
            dialects_data.extend_from_slice(dialect.as_bytes());
            dialects_data.push(0x00);
        }

        let byte_count =
            u16::try_from(dialects_data.len()).map_err(|_| EncodeError::NumberOutOfBound)?;

        buf.write_all(&byte_count.to_le_bytes())?;
        buf.write_all(&dialects_data)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::entities::BufferReader;
    use crate::entities::v1::negotiate::request::{EncodeError, ParseError, RequestBuilder};

    #[test]
    fn should_encode_and_parse_request() {
        let builder = RequestBuilder::new();
        assert_eq!(builder.buffer_size(), 0);
        let builder = builder.with_dialect("NT LM 0.12");
        assert_eq!(builder.buffer_size(), 12);
        let builder = builder.with_dialect("SMB 2.002");
        assert_eq!(builder.buffer_size(), 23);

        let mut encoded = Vec::new();
        builder.encode(&mut encoded).unwrap();

        let mut reader = BufferReader::new(&encoded);
        let req = super::Request::parse(&mut reader).unwrap();
        let dialects: Vec<_> = req.dialects().collect::<Result<_, _>>().unwrap();

        assert_eq!(dialects, &["NT LM 0.12", "SMB 2.002"]);
    }

    #[test]
    fn should_encode_and_parse_empty_request() {
        let builder = RequestBuilder::new();
        let mut encoded = Vec::new();
        builder.encode(&mut encoded).unwrap();

        assert_eq!(encoded, &[0x00, 0x00]);

        let mut reader = BufferReader::new(&encoded);
        let req = super::Request::parse(&mut reader).unwrap();

        assert_eq!(req.dialects().count(), 0);
    }

    #[test]
    fn should_encode_and_parse_single_dialect() {
        let builder = RequestBuilder::new().with_dialect("MYDIALECT");
        let mut encoded = Vec::new();
        builder.encode(&mut encoded).unwrap();

        let mut reader = BufferReader::new(&encoded);
        let req = super::Request::parse(&mut reader).unwrap();
        let dialects: Vec<_> = req.dialects().collect::<Result<_, _>>().unwrap();

        assert_eq!(dialects, &["MYDIALECT"]);
    }

    #[test]
    fn should_encode_and_parse_empty_dialect() {
        let builder = RequestBuilder::new().with_dialect("");
        let mut encoded = Vec::new();
        builder.encode(&mut encoded).unwrap();

        let mut reader = BufferReader::new(&encoded);
        let req = super::Request::parse(&mut reader).unwrap();
        let dialects: Vec<_> = req.dialects().collect::<Result<_, _>>().unwrap();

        assert_eq!(dialects, &[""]);
    }

    #[test]
    fn encode_should_fail_with_too_much_data() {
        let long_dialect = "a".repeat(100);
        let mut builder = RequestBuilder::new();
        for _ in 0..700 {
            // 700 * (100 + 2 for format/null) > 65535
            builder = builder.with_dialect(&long_dialect);
        }
        let mut encoded = Vec::new();
        let err = builder.encode(&mut encoded).unwrap_err();
        assert!(matches!(err, EncodeError::NumberOutOfBound));
    }

    #[test]
    fn should_parse_negotiate_request() {
        let data = [
            0x22, 0x00, // ByteCount
            0x02, b'N', b'T', b' ', b'L', b'M', b' ', b'0', b'.', b'1', b'2', 0x00, 0x02, b'S',
            b'M', b'B', b' ', b'2', b'.', b'0', b'0', b'2', 0x00, 0x02, b'S', b'M', b'B', b' ',
            b'2', b'.', b'?', b'?', b'?', 0x00,
        ];
        let mut reader = BufferReader::new(&data);
        let req = super::Request::parse(&mut reader).unwrap();
        let dialects: Vec<_> = req.dialects().collect::<Result<_, _>>().unwrap();
        assert_eq!(dialects, &["NT LM 0.12", "SMB 2.002", "SMB 2.???"]);
        assert!(reader.0.is_empty());
    }

    #[test]
    fn should_parse_other_dialect() {
        let data = [
            0x0c, 0x00, // ByteCount
            0x02, b'M', b'Y', b' ', b'D', b'I', b'A', b'L', b'E', b'C', b'T', 0x00,
        ];
        let mut reader = BufferReader::new(&data);
        let req = super::Request::parse(&mut reader).unwrap();
        let dialects: Vec<_> = req.dialects().collect::<Result<_, _>>().unwrap();
        assert_eq!(dialects, &["MY DIALECT"]);
    }

    #[test]
    fn should_handle_zero_byte_count() {
        let data = [0x00, 0x00];
        let mut reader = BufferReader::new(&data);
        let req = super::Request::parse(&mut reader).unwrap();
        assert_eq!(req.dialects().count(), 0);
        assert!(reader.0.is_empty());
    }

    #[test]
    fn should_fail_parsing_with_short_buffer_for_byte_count() {
        let data = [0x00];
        let mut reader = BufferReader::new(&data);
        let err = super::Request::parse(&mut reader).unwrap_err();
        assert!(matches!(err, ParseError::BufferTooShort));
    }

    #[test]
    fn should_fail_parsing_with_short_buffer_for_data() {
        let data = [0x10, 0x00, 0x01, 0x02];
        let mut reader = BufferReader::new(&data);
        let err = super::Request::parse(&mut reader).unwrap_err();
        assert!(matches!(err, ParseError::BufferTooShort));
    }

    #[test]
    fn iterator_should_fail_with_invalid_buffer_format() {
        let data = [
            0x07, 0x00, // ByteCount
            0x02, b'O', b'K', 0x00, 0x03, b'N', b'G',
        ];
        let mut reader = BufferReader::new(&data);
        let req = super::Request::parse(&mut reader).unwrap();
        let mut dialects_it = req.dialects();
        assert_eq!(dialects_it.next().unwrap().unwrap(), "OK");
        assert!(matches!(
            dialects_it.next().unwrap().unwrap_err(),
            ParseError::InvalidDialectFormat
        ));
        assert!(dialects_it.next().is_none());
    }

    #[test]
    fn iterator_should_fail_with_missing_null_terminator() {
        let data = [0x03, 0x00, 0x02, b'A', b'B'];
        let mut reader = BufferReader::new(&data);
        let req = super::Request::parse(&mut reader).unwrap();
        let mut dialects_it = req.dialects();
        assert!(matches!(
            dialects_it.next().unwrap().unwrap_err(),
            ParseError::MissingNullTerminator
        ));
        assert!(dialects_it.next().is_none());
    }

    #[test]
    fn iterator_should_fail_with_invalid_utf8() {
        let data = [0x04, 0x00, 0x02, 0xff, 0xfe, 0x00];
        let mut reader = BufferReader::new(&data);
        let req = super::Request::parse(&mut reader).unwrap();
        let mut dialects_it = req.dialects();
        assert!(matches!(
            dialects_it.next().unwrap().unwrap_err(),
            ParseError::InvalidUtf8(_)
        ));
    }

    #[test]
    fn should_have_correct_length_encoding() {
        let builder = RequestBuilder::new().with_dialect("ABC");
        let mut encoded = Vec::new();
        builder.encode(&mut encoded).unwrap();
        // byte_count (2) + format (1) + "ABC" (3) + null (1) = 7
        assert_eq!(encoded.len(), 2 + 1 + 3 + 1);
        let byte_count = u16::from_le_bytes([encoded[0], encoded[1]]);
        assert_eq!(byte_count as usize, encoded.len() - 2);
    }

    #[test]
    fn should_encode_and_parse_dialect_of_len_2() {
        let builder = RequestBuilder::new().with_dialect("AB");
        let mut encoded = Vec::new();
        builder.encode(&mut encoded).unwrap();
        let mut reader = BufferReader::new(&encoded);
        let req = super::Request::parse(&mut reader).unwrap();
        let dialects: Vec<_> = req.dialects().collect::<Result<_, _>>().unwrap();
        assert_eq!(dialects, &["AB"]);
    }
}
