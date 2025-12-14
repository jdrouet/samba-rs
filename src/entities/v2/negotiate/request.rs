//! https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e14db7ff-763a-4263-8b10-0c3944f52fc5

use crate::entities::{BufferIterator, u16_from_le_bytes, u32_from_le_bytes, u128_from_le_bytes};

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ParseError {
    #[error("buffer too short")]
    BufferTooShort,
    #[error("no hash algorithm provided")]
    NoHashAlgorithmProvided,
    #[error("invalid structure size, expected 36, received {_0}")]
    InvalidStructureSize(u16),
    #[error("invalid dialect {_0}")]
    InvalidDialect(u16),
    #[error("invalid context type {_0}")]
    InvalidContextType(u16),
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
pub struct DialectList<'a>(pub &'a [u8]);

impl<'a> DialectList<'a> {
    pub fn iter(&self) -> impl Iterator<Item = Result<Dialect, ParseError>> {
        self.0
            .chunks(2)
            .map(u16_from_le_bytes)
            .map(|value| Dialect::try_from(value).map_err(ParseError::InvalidDialect))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct NegotiateContextList<'a>(pub &'a [u8]);

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
    pub dialects: DialectList<'a>,
    /// NegotiateContextList (variable)
    ///
    /// If the Dialects field contains 0x0311, then this field will contain an array of SMB2 NEGOTIATE_CONTEXTs.
    /// The first negotiate context in the list MUST appear at the byte offset indicated by the SMB2 NEGOTIATE
    /// request's NegotiateContextOffset field. Subsequent negotiate contexts MUST appear at
    /// the first 8-byte-aligned offset following the previous negotiate context.
    pub negotiate_contexts: NegotiateContextList<'a>,
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
        let dialects = DialectList(&buf[dialects_start..dialects_end]);
        // padding
        let negotiate_context_start = (negotiate_context_offset - 64) as usize; // remove header
        let negotiate_contexts = NegotiateContextList(&buf[negotiate_context_start..]);

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
pub struct HashAlgorithmList<'a>(pub &'a [u8]);

impl<'a> HashAlgorithmList<'a> {
    pub fn iter(&self) -> impl Iterator<Item = Result<HashAlgorithm, ParseError>> {
        self.0
            .chunks(2)
            .map(u16_from_le_bytes)
            .map(|value| HashAlgorithm::try_from(value).map_err(ParseError::InvalidHashAlgorithm))
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
    pub hash_algorithms: HashAlgorithmList<'a>,
    /// Salt (variable)
    ///
    /// A buffer containing the salt value of the hash.
    pub salt: &'a [u8],
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
        let hash_algorithms = HashAlgorithmList(hash_algorithms);

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

#[cfg(test)]
mod tests {
    #[test]
    fn should_parse_preauth_integrity_capabilities() {
        super::PreauthIntegrityCapabilities::parse(&[1, 0, 0, 0, 1, 0]).unwrap();
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
        let err = value.hash_algorithms.iter().next().unwrap().unwrap_err();
        assert_eq!(err, super::ParseError::InvalidHashAlgorithm(4));
    }
}
