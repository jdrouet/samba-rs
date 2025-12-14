//! https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e14db7ff-763a-4263-8b10-0c3944f52fc5

use crate::entities::{BufferIterator, u16_from_le_bytes, u32_from_le_bytes, u128_from_le_bytes};

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ParseError {
    #[error("buffer too short")]
    BufferTooShort,
    #[error("no hash algorithm provided")]
    NoHashAlgorithmProvided,
    #[error("no encryption cipher provided")]
    NoEncryptionCipherProvided,
    #[error("invalid structure size, expected 36, received {_0}")]
    InvalidStructureSize(u16),
    #[error("invalid dialect {_0}")]
    InvalidDialect(u16),
    #[error("invalid context type {_0}")]
    InvalidContextType(u16),
    #[error("invalid compression algorithm {_0}")]
    InvalidCompressionAlgorithm(u16),
    #[error("invalid compression flag {_0}")]
    InvalidCompressionFlag(u32),
    #[error("invalid encryption cipher {_0}")]
    InvalidEncryptionCipher(u16),
    #[error("invalid hash algorithm {_0}")]
    InvalidHashAlgorithm(u16),
    #[error("unknown capabilities")]
    UnknownCapabilities,
    #[error("unknown security modes")]
    UnknownSecurityModes,
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SecurityMode: u16 {
        /// SMB2_NEGOTIATE_SIGNING_ENABLED
        ///
        /// 0x0001
        ///
        /// When set, indicates that security signatures are enabled on the client.
        /// The server MUST ignore this bit.
        const SMB2_NEGOTIATE_SIGNING_ENABLED = 0x0001;
        /// SMB2_NEGOTIATE_SIGNING_REQUIRED
        ///
        /// 0x0002
        ///
        /// When set, indicates that security signatures are required by the client.
        const SMB2_NEGOTIATE_SIGNING_REQUIRED = 0x0002;
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Capabilities: u32 {
        /// SMB2_GLOBAL_CAP_DFS
        ///
        /// 0x00000001
        ///
        /// When set, indicates that the client supports the Distributed File System (DFS).
        const SMB2_GLOBAL_CAP_DFS = 0x0001;
        /// SMB2_GLOBAL_CAP_LEASING
        ///
        /// 0x00000002
        ///
        /// When set, indicates that the client supports leasing.
        const SMB2_GLOBAL_CAP_LEASING = 0x0002;
        /// SMB2_GLOBAL_CAP_LARGE_MTU
        ///
        /// 0x00000004
        ///
        /// When set, indicates that the client supports multi-credit operations.
        const SMB2_GLOBAL_CAP_LARGE_MTU = 0x0004;
        /// SMB2_GLOBAL_CAP_MULTI_CHANNEL
        ///
        /// 0x00000008
        ///
        /// When set, indicates that the client supports establishing multiple channels for a single session.
        const SMB2_GLOBAL_CAP_MULTI_CHANNEL = 0x0008;
        /// SMB2_GLOBAL_CAP_PERSISTENT_HANDLES
        ///
        /// 0x00000010
        ///
        /// When set, indicates that the client supports persistent handles.
        const SMB2_GLOBAL_CAP_PERSISTENT_HANDLES = 0x0010;
        /// SMB2_GLOBAL_CAP_DIRECTORY_LEASING
        ///
        /// 0x00000020
        ///
        /// When set, indicates that the client supports directory leasing.
        const SMB2_GLOBAL_CAP_DIRECTORY_LEASING = 0x0020;
        /// SMB2_GLOBAL_CAP_ENCRYPTION
        ///
        /// 0x00000040
        ///
        /// When set, indicates that the client supports encryption with AES-128-CCM cipher.
        const SMB2_GLOBAL_CAP_ENCRYPTION = 0x0040;
        /// SMB2_GLOBAL_CAP_NOTIFICATIONS
        ///
        /// 0x00000080
        ///
        /// When set, indicates that the client supports receiving one-way notifications from a server,
        /// specified in section 2.2.44.
        const SMB2_GLOBAL_CAP_NOTIFICATIONS = 0x0080;
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(u16)]
pub enum Dialect {
    /// SMB 2.0.2 dialect revision number.
    Smb202 = 0x0202,
    /// SMB 2.1 dialect revision number.
    Smb21 = 0x0210,
    /// SMB 3.0 dialect revision number.
    Smb30 = 0x0300,
    /// SMB 3.0.2 dialect revision number.
    Smb302 = 0x0302,
    /// SMB 3.1.1 dialect revision number.
    Smb311 = 0x0311,
}

impl TryFrom<u16> for Dialect {
    type Error = u16;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(match value {
            0x0202 => Self::Smb202,
            0x0210 => Self::Smb21,
            0x0300 => Self::Smb30,
            0x0302 => Self::Smb302,
            0x0311 => Self::Smb311,
            other => return Err(other),
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    /// StructureSize (2 bytes)
    ///
    /// The client MUST set this field to 36, indicating the size of a NEGOTIATE request.
    /// This is not the size of the structure with a single dialect in the Dialects[] array.
    /// This value MUST be set regardless of the number of dialects or number of negotiate contexts sent.
    // pub structure_size: u16,

    /// DialectCount (2 bytes)
    ///
    /// The number of dialects that are contained in the Dialects[] array. This value MUST be greater than 0.
    pub dialect_count: u16,

    /// SecurityMode (2 bytes)
    ///
    /// The security mode field specifies whether SMB signing is enabled or required at the client.
    /// This field MUST be constructed using the following values.
    ///
    /// - SMB2_NEGOTIATE_SIGNING_ENABLED (0x0001): When set, indicates that security signatures
    ///   are enabled on the client. The server MUST ignore this bit.
    /// - SMB2_NEGOTIATE_SIGNING_REQUIRED (0x0002): When set, indicates that security signatures
    ///   are required by the client.
    pub security_mode: SecurityMode,

    /// Reserved (2 bytes)
    // The client MUST set this to 0, and the server SHOULD<9> ignore it on receipt.
    // pub reserved: u16,

    /// Capabilities (4 bytes)
    ///
    /// If the client implements the SMB 3.x dialect family, the Capabilities field MUST be constructed
    /// using the following values. Otherwise, this field MUST be set to 0.
    pub capabilities: Capabilities,

    /// ClientGuid (16 bytes)
    ///
    /// It MUST be a GUID (as specified in [MS-DTYP] section 2.3.4.2) generated by the client.
    pub client_guid: u128,

    // (NegotiateContextOffset,NegotiateContextCount,Reserved2)/ClientStartTime (8 bytes)
    //
    // This field is interpreted in different ways depending on the SMB2 Dialects field.
    //
    // If the Dialects field contains 0x0311, this field is interpreted as the NegotiateContextOffset, NegotiateContextCount, and Reserved2 fields.
    // - NegotiateContextOffset (4 bytes)
    //   The offset, in bytes, from the beginning of the SMB2 header to the first, 8-byte-aligned negotiate context in the NegotiateContextList.
    // - NegotiateContextCount (2 bytes): The number of negotiate contexts in NegotiateContextList.
    // - Reserved2 (2 bytes): The client MUST set this to 0, and the server MUST ignore it on receipt.
    //
    // If the Dialects field doesn't contain 0x0311, this field is interpreted as the ClientStartTime field.
    //
    // ClientStartTime (8 bytes)
    //
    // This field MUST NOT be used and MUST be reserved. The client MUST set this to 0, and the server MUST ignore it on receipt.
    /// NegotiateContextOffset (4 bytes)
    ///
    /// The offset, in bytes, from the beginning of the SMB2 header to the first, 8-byte-aligned negotiate context in the NegotiateContextList.
    pub negotiate_context_offset: u32,
    /// NegotiateContextCount (2 bytes)
    ///
    /// The number of negotiate contexts in NegotiateContextList.
    pub negotiate_context_count: u16,
    /// Dialects (variable)
    ///
    /// An array of one or more 16-bit integers specifying the supported dialect revision numbers.
    /// The array MUST contain at least one of the following values.
    pub dialects: &'a [u8],
    /// NegotiateContextList (variable)
    ///
    /// If the Dialects field contains 0x0311, then this field will contain an array of SMB2 NEGOTIATE_CONTEXTs.
    /// The first negotiate context in the list MUST appear at the byte offset indicated by the SMB2 NEGOTIATE
    /// request's NegotiateContextOffset field. Subsequent negotiate contexts MUST appear at
    /// the first 8-byte-aligned offset following the previous negotiate context.
    pub negotiate_contexts: &'a [u8],
}

impl<'a> Request<'a> {
    pub fn dialects(&self) -> impl Iterator<Item = Result<Dialect, ParseError>> {
        self.dialects
            .chunks(2)
            .map(u16_from_le_bytes)
            .map(|value| Dialect::try_from(value).map_err(ParseError::InvalidDialect))
    }
}

impl<'a> Request<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<Self, ParseError> {
        if buf.len() < 36 {
            return Err(ParseError::BufferTooShort);
        }
        let structure_size = u16_from_le_bytes(&buf[0..2]);
        if structure_size != 36 {
            return Err(ParseError::InvalidStructureSize(structure_size));
        }

        let dialect_count = u16_from_le_bytes(&buf[2..4]);
        let security_mode = SecurityMode::from_bits(u16_from_le_bytes(&buf[4..6]))
            .ok_or(ParseError::UnknownSecurityModes)?;
        // reserved 2 bytes
        let capabilities = Capabilities::from_bits(u32_from_le_bytes(&buf[8..12]))
            .ok_or(ParseError::UnknownCapabilities)?;
        let client_guid = u128_from_le_bytes(&buf[12..28]);
        let negotiate_context_offset = u32_from_le_bytes(&buf[28..32]);
        let negotiate_context_count = u16_from_le_bytes(&buf[32..34]);
        // reserved 2 bytes
        let dialects_start = 36;
        let dialects_end = dialects_start + (dialect_count as usize) * 2;
        if buf.len() < dialects_end {
            return Err(ParseError::BufferTooShort);
        }
        let dialects = &buf[dialects_start..dialects_end];
        // padding
        let negotiate_context_start = (negotiate_context_offset - 64) as usize; // remove header
        let negotiate_contexts = &buf[negotiate_context_start..];

        Ok(Self {
            dialect_count,
            security_mode,
            capabilities,
            client_guid,
            negotiate_context_offset,
            negotiate_context_count,
            dialects,
            negotiate_contexts,
        })
    }
}

pub struct NegotiateContextIterator<'a>(BufferIterator<'a>);

impl<'a> NegotiateContextIterator<'a> {
    pub fn try_next(&mut self) -> Result<Option<NegotiateContext<'a>>, ParseError> {
        if self.0.0.is_empty() {
            return Ok(None);
        }

        NegotiateContext::parse(&mut self.0).map(Some)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum NegotiateContextType {
    /// The Data field contains a list of preauthentication integrity hash functions
    /// as well as an optional salt value, as specified in section 2.2.3.1.1.
    PreauthIntegrityCapabilities = 0x0001,
    /// The Data field contains a list of encryption algorithms, as specified in section 2.2.3.1.2.
    EncryptionCapabilities = 0x0002,
    /// The Data field contains a list of compression algorithms, as specified in section 2.2.3.1.3.
    CompressionCapabilities = 0x0003,
    /// The Data field contains the server name to which the client connects.
    NetNameNegotiateContextId = 0x0005,
    /// The Data field contains transport capabilities, as specified in section 2.2.3.1.5.
    TransportCapabilities = 0x0006,
    /// The Data field contains a list of RDMA transforms, as specified in section 2.2.3.1.6.
    RDMATransformCapabilities = 0x0007,
    /// The Data field contains a list of signing algorithms, as specified in section 2.2.3.1.7.
    SigningCapabilities = 0x0008,
    /// This value MUST be reserved and MUST be ignored on receipt.
    ContextTypeReserved = 0x0100,
}

impl TryFrom<u16> for NegotiateContextType {
    type Error = u16;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(match value {
            0x0001 => Self::PreauthIntegrityCapabilities,
            0x0002 => Self::EncryptionCapabilities,
            0x0003 => Self::CompressionCapabilities,
            0x0005 => Self::NetNameNegotiateContextId,
            0x0006 => Self::TransportCapabilities,
            0x0007 => Self::RDMATransformCapabilities,
            0x0008 => Self::SigningCapabilities,
            0x1000 => Self::ContextTypeReserved,
            other => return Err(other),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NegotiateContextRaw<'a> {
    /// ContextType (2 bytes)
    ///
    /// Specifies the type of context in the Data field. This field MUST be one of the following values.
    pub context_type: NegotiateContextType,
    /// DataLength (2 bytes)
    ///
    /// The length, in bytes, of the Data field.
    pub data_length: u16,
    // Reserved (4 bytes): This field MUST NOT be used and MUST be reserved.
    // This value MUST be set to 0 by the client, and MUST be ignored by the server.
    /// Data (variable)
    ///
    /// A variable-length field that contains the negotiate context specified by the ContextType field.
    pub data: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NegotiateContext<'a> {
    PreauthIntegrityCapabilities(PreauthIntegrityCapabilities<'a>),
    EncryptionCapabilities(EncryptionCapabilities<'a>),
    CompressionCapabilities(CompressionCapabilities<'a>),
}

impl<'a> NegotiateContext<'a> {
    pub(super) fn parse(it: &mut BufferIterator<'a>) -> Result<Self, ParseError> {
        let context_type = it.next_u16().ok_or(ParseError::BufferTooShort)?;
        let context_type =
            NegotiateContextType::try_from(context_type).map_err(ParseError::InvalidContextType)?;

        let data_length = it.next_u16().ok_or(ParseError::BufferTooShort)?;
        // skip reserved
        it.next(4).ok_or(ParseError::BufferTooShort)?;
        let buf = it
            .next(data_length as usize)
            .ok_or(ParseError::BufferTooShort)?;
        match context_type {
            NegotiateContextType::PreauthIntegrityCapabilities => {
                PreauthIntegrityCapabilities::parse(buf)
                    .map(NegotiateContext::PreauthIntegrityCapabilities)
            }
            NegotiateContextType::EncryptionCapabilities => {
                EncryptionCapabilities::parse(buf).map(NegotiateContext::EncryptionCapabilities)
            }
            NegotiateContextType::CompressionCapabilities => {
                CompressionCapabilities::parse(buf).map(NegotiateContext::CompressionCapabilities)
            }
            _ => todo!(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum HashAlgorithm {
    /// SHA-512 as specified in [FIPS180-4]
    Sha512 = 0x0001,
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

#[cfg(test)]
mod tests {
    #[test]
    fn should_parse_compression_capabilities() {
        let cap = super::CompressionCapabilities::parse(&[0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert!(cap.compression_algorithms().next().is_none());
        let cap = super::CompressionCapabilities::parse(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(
            cap.compression_algorithms().next().unwrap().unwrap(),
            super::CompressionAlgorithm::None
        );
    }

    #[test]
    fn should_fail_parse_compression_capabilities_with_invalid_size() {
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
    fn should_fail_parse_compression_capabilities_with_invalid_flags() {
        let err = super::CompressionCapabilities::parse(&[0, 0, 0, 0, 2, 0, 0, 0]).unwrap_err();
        assert_eq!(err, super::ParseError::InvalidCompressionFlag(2));
    }

    #[test]
    fn should_fail_parse_compression_capabilities_with_invalid_algorithm() {
        let cap = super::CompressionCapabilities::parse(&[1, 0, 0, 0, 0, 0, 0, 0, 6, 0]).unwrap();
        let err = cap.compression_algorithms().next().unwrap().unwrap_err();
        assert_eq!(err, super::ParseError::InvalidCompressionAlgorithm(6));
    }

    #[test]
    fn should_parse_preauth_integrity_capabilities() {
        let cap = super::PreauthIntegrityCapabilities::parse(&[1, 0, 0, 0, 1, 0]).unwrap();
        let _ = cap.hash_algorithms.iter().collect::<Vec<_>>();
    }

    #[test]
    fn should_fail_parse_preauth_integrity_capabilities_small_buffer() {
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
    fn should_fail_parse_preauth_integrity_capabilities_without_hash_algorithm() {
        let err = super::PreauthIntegrityCapabilities::parse(&[0, 0, 0, 0]).unwrap_err();
        assert_eq!(err, super::ParseError::NoHashAlgorithmProvided);
    }

    #[test]
    fn should_fail_parse_preauth_integrity_capabilities_with_invalid_hash_algorithm() {
        let value = super::PreauthIntegrityCapabilities::parse(&[1, 0, 0, 0, 4, 0]).unwrap();
        let err = value.hash_algorithms().next().unwrap().unwrap_err();
        assert_eq!(err, super::ParseError::InvalidHashAlgorithm(4));
    }

    #[test]
    fn should_parse_encryption_capabilities() {
        let cap = super::EncryptionCapabilities::parse(&[1, 0, 1, 0]).unwrap();
        let _ = cap.ciphers().collect::<Vec<_>>();
    }

    #[test]
    fn should_fail_parse_encryption_capabilities_invalid_size() {
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
    fn should_fail_parse_encryption_capabilities_empty() {
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
