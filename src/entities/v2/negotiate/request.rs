//! Samba v2 negotiate request
//!
//! Related doc <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e14db7ff-763a-4263-8b10-0c3944f52fc5>

use std::str::Utf8Error;

use super::context::NegotiateContextBuilder;
use crate::entities::{u16_from_le_bytes, u32_from_le_bytes, u128_from_le_bytes};

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ParseError {
    #[error("buffer too short")]
    BufferTooShort,
    #[error("no hash algorithm provided")]
    NoHashAlgorithmProvided,
    #[error("no signing algorithm provided")]
    NoSigningAlgorithmProvided,
    #[error("no encryption cipher provided")]
    NoEncryptionCipherProvided,
    #[error("no RDMA transform provided")]
    NoRDMATransformProvided,
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
    #[error("invalid transform id {_0}")]
    InvalidTransformId(u16),
    #[error("invalid signing algorithm {_0}")]
    InvalidSigningAlgorithm(u16),
    #[error("invalid unicode string")]
    InvalidUnicode(#[from] Utf8Error),
    #[error("unknown capabilities")]
    UnknownCapabilities,
    #[error("unknown security modes")]
    UnknownSecurityModes,
    #[error("unknown transport flags")]
    UnknownTransportFlags,
}

#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    #[error("no RDMA transform provided")]
    NoRDMATransformProvided,
    #[error("no hash algorithm provided")]
    NoHashAlgorithmProvided,
    #[error("no signing algorithm provided")]
    NoSigningAlgorithmProvided,
    #[error("number ouf of bound")]
    NumberOutOfBound,
    #[error(transparent)]
    Io(#[from] std::io::Error),
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

impl Dialect {
    pub const fn to_u16(&self) -> u16 {
        match self {
            Self::Smb202 => 0x0202,
            Self::Smb21 => 0x0210,
            Self::Smb30 => 0x0300,
            Self::Smb302 => 0x0302,
            Self::Smb311 => 0x0311,
        }
    }
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

    pub fn negotiate_contexts(&self) -> super::context::NegotiateContextIterator<'a> {
        super::context::NegotiateContextIterator::new(self.negotiate_contexts)
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
        println!("buf = {:?}", &buf[dialects_end..]);
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

#[derive(Clone, Debug)]
pub struct RequestBuilder {
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
    /// Dialects (variable)
    ///
    /// An array of one or more 16-bit integers specifying the supported dialect revision numbers.
    /// The array MUST contain at least one of the following values.
    pub dialects: Vec<Dialect>,
    /// NegotiateContextList (variable)
    ///
    /// If the Dialects field contains 0x0311, then this field will contain an array of SMB2 NEGOTIATE_CONTEXTs.
    /// The first negotiate context in the list MUST appear at the byte offset indicated by the SMB2 NEGOTIATE
    /// request's NegotiateContextOffset field. Subsequent negotiate contexts MUST appear at
    /// the first 8-byte-aligned offset following the previous negotiate context.
    pub negotiate_contexts: Vec<NegotiateContextBuilder>,
}

impl Default for RequestBuilder {
    fn default() -> Self {
        Self {
            security_mode: SecurityMode::empty(),
            capabilities: Capabilities::empty(),
            client_guid: 0,
            dialects: Vec::default(),
            negotiate_contexts: Vec::default(),
        }
    }
}

impl RequestBuilder {
    pub fn with_security_mode(mut self, value: SecurityMode) -> Self {
        self.security_mode = self.security_mode.union(value);
        self
    }

    pub fn with_capability(mut self, value: Capabilities) -> Self {
        self.capabilities = self.capabilities.union(value);
        self
    }

    pub fn with_client_guid(mut self, value: u128) -> Self {
        self.client_guid = value;
        self
    }

    pub fn with_dialect(mut self, value: Dialect) -> Self {
        self.dialects.push(value);
        self
    }

    pub fn with_negotiate_context(mut self, value: NegotiateContextBuilder) -> Self {
        self.negotiate_contexts.push(value);
        self
    }
}

impl RequestBuilder {
    pub fn encode<W: std::io::Write>(&self, buf: &mut W) -> Result<(), EncodeError> {
        let dialect_size = self.dialects.len() * 2;

        // structure size (2)
        buf.write_all(&36u16.to_le_bytes())?; // 0..2
        // dialect count (2)
        let dialect_count =
            u16::try_from(self.dialects.len()).map_err(|_| EncodeError::NumberOutOfBound)?;
        buf.write_all(&dialect_count.to_le_bytes())?; // 2..4
        // security mode (2)
        buf.write_all(&self.security_mode.bits().to_le_bytes())?; // 4..6
        // reserved (2)
        buf.write_all(&[0, 0])?; // 6..8
        // capabilities (4)
        buf.write_all(&self.capabilities.bits().to_le_bytes())?; // 8..12
        // client guid (16)
        buf.write_all(&self.client_guid.to_le_bytes())?; // 12..28
        // negotiate context offset (4)
        let context_offset = 64 + 28 + 8 + dialect_size;
        let padding = match context_offset % 8 {
            0 => 0,
            n => 8 - n,
        };
        let context_offset =
            u32::try_from(context_offset + padding).map_err(|_| EncodeError::NumberOutOfBound)?;
        buf.write_all(&context_offset.to_le_bytes())?; // 32
        // context_count (2)
        let context_count = u16::try_from(self.negotiate_contexts.len())
            .map_err(|_| EncodeError::NumberOutOfBound)?;
        buf.write_all(&context_count.to_le_bytes())?; // 34
        // reserved (2)
        buf.write_all(&[0, 0])?; // 36
        // dialects
        for dialect in &self.dialects {
            buf.write_all(&dialect.to_u16().to_le_bytes())?;
        }
        // padding
        if padding > 0 {
            buf.write_all(&vec![0u8; padding])?;
        }
        // contexts
        for ctx in &self.negotiate_contexts {
            ctx.encode(buf)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn should_convert_dialect_to_u16() {
        assert_eq!(super::Dialect::Smb202.to_u16(), 0x0202);
        assert_eq!(super::Dialect::Smb21.to_u16(), 0x0210);
        assert_eq!(super::Dialect::Smb30.to_u16(), 0x0300);
        assert_eq!(super::Dialect::Smb302.to_u16(), 0x0302);
        assert_eq!(super::Dialect::Smb311.to_u16(), 0x0311);
    }

    #[test]
    fn should_encode_and_parse_empty_request() {
        let mut buf = Vec::with_capacity(1024);
        super::RequestBuilder::default().encode(&mut buf).unwrap();
        let req = super::Request::parse(&buf).unwrap();
        assert_eq!(req.dialect_count, 0);
        assert_eq!(req.negotiate_context_count, 0);
    }

    #[test]
    fn should_encode_and_parse_only_dialects() {
        let mut buf = Vec::with_capacity(1024);
        super::RequestBuilder::default()
            .with_dialect(super::Dialect::Smb202)
            .with_dialect(super::Dialect::Smb30)
            .encode(&mut buf)
            .unwrap();
        let req = super::Request::parse(&buf).unwrap();
        assert_eq!(req.dialect_count, 2);
        assert_eq!(req.negotiate_context_count, 0);
    }

    #[test]
    fn should_encode_and_parse_only_contexts() {
        use crate::entities::v2::negotiate::context::signing::{
            SigningAlgorithm, SigningCapabilitiesBuilder,
        };
        use crate::entities::v2::negotiate::context::transport::{
            TransportCapabilitiesBuilder, TransportFlags,
        };

        let mut buf = Vec::with_capacity(1024);
        super::RequestBuilder::default()
            .with_client_guid(12345)
            .with_security_mode(super::SecurityMode::SMB2_NEGOTIATE_SIGNING_ENABLED)
            .with_capability(super::Capabilities::SMB2_GLOBAL_CAP_DFS)
            .with_negotiate_context(
                TransportCapabilitiesBuilder::new(
                    TransportFlags::SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY,
                )
                .into(),
            )
            .with_negotiate_context(
                SigningCapabilitiesBuilder::default()
                    .with_signing_algorithm(SigningAlgorithm::AesCmac)
                    .with_signing_algorithm(SigningAlgorithm::AesGmac)
                    .into(),
            )
            .encode(&mut buf)
            .unwrap();
        let req = super::Request::parse(&buf).unwrap();
        assert!(
            req.security_mode
                .contains(super::SecurityMode::SMB2_NEGOTIATE_SIGNING_ENABLED)
        );
        assert!(
            req.capabilities
                .contains(super::Capabilities::SMB2_GLOBAL_CAP_DFS)
        );
        assert_eq!(req.client_guid, 12345);
        assert_eq!(req.dialect_count, 0);
        assert_eq!(req.negotiate_context_count, 2);
        let mut ctx_iterator = req.negotiate_contexts();
        let _ctx = ctx_iterator.try_next().unwrap();
        let _ctx = ctx_iterator.try_next().unwrap();
    }
}
