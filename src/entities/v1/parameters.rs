use crate::entities::{BufferReader, u16_from_le_bytes};

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum ParseError {
    #[error("buffer too short")]
    BufferTooShort,
}

#[derive(Clone, Copy, Debug)]
pub struct Parameters<'a> {
    pub word_count: u8,
    /// variable 2 bytes words
    pub words: &'a [u8],
}

impl<'a> Parameters<'a> {
    pub fn parse(buf: &'a mut BufferReader<'a>) -> Result<Self, ParseError> {
        let word_count = buf.pop().ok_or(ParseError::BufferTooShort)?;
        let words = buf
            .next((word_count as usize) * 2)
            .ok_or(ParseError::BufferTooShort)?;

        Ok(Parameters { word_count, words })
    }
}

impl<'a> Parameters<'a> {
    pub const fn size(&self) -> usize {
        (self.word_count as usize) * 2 + 1
    }

    pub fn words(&self) -> impl Iterator<Item = u16> {
        self.words
            .chunks(2)
            .filter(|item| item.len() == 2)
            .map(u16_from_le_bytes)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    #[error("too many words")]
    TooManyWords,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Default)]
pub struct ParametersBuilder {
    pub words: Vec<u16>,
}

impl ParametersBuilder {
    pub fn with_word(mut self, value: u16) -> Self {
        self.words.push(value);
        self
    }

    pub fn encode<W: std::io::Write>(&self, buf: &mut W) -> Result<(), EncodeError> {
        let word_count = u8::try_from(self.words.len()).map_err(|_| EncodeError::TooManyWords)?;

        let mut words: Vec<u8> = Vec::with_capacity(self.words.len() * 2 + 1);
        words.push(word_count);
        words.extend(self.words.iter().flat_map(|item| item.to_le_bytes()));
        buf.write_all(&words)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::entities::BufferReader;

    #[test]
    fn should_encode_and_parse() {
        let mut buf = Vec::with_capacity(1024);
        super::ParametersBuilder::default()
            .with_word(1)
            .with_word(2)
            .encode(&mut buf)
            .unwrap();
        let mut buf = BufferReader(buf.as_slice());
        let params = super::Parameters::parse(&mut buf).unwrap();
        assert_eq!(params.size(), 5);
        let words = params.words().collect::<Vec<_>>();
        assert_eq!(words.len(), 2);
    }

    #[test]
    fn should_fail_parse_empty() {
        let mut buf = BufferReader(&[]);
        let err = super::Parameters::parse(&mut buf).unwrap_err();
        assert_eq!(err, super::ParseError::BufferTooShort);
    }

    #[test]
    fn should_fail_parse_invalid_size() {
        let mut buf = BufferReader(&[1u8, 2]);
        let err = super::Parameters::parse(&mut buf).unwrap_err();
        assert_eq!(err, super::ParseError::BufferTooShort);
    }

    #[test]
    fn should_parse_empty_params() {
        let mut buf = BufferReader(&[0u8]);
        let params = super::Parameters::parse(&mut buf).unwrap();
        assert_eq!(params.size(), 1);
        let words = params.words().collect::<Vec<_>>();
        assert_eq!(words.len(), 0);
    }

    #[test]
    fn should_parse_some_params() {
        let mut buf = BufferReader(&[1u8, 1, 2]);
        let params = super::Parameters::parse(&mut buf).unwrap();
        assert_eq!(params.size(), 3);
        assert_eq!(params.word_count, 1);
        let words = params.words().collect::<Vec<_>>();
        assert_eq!(words.len(), 1);
    }
}
