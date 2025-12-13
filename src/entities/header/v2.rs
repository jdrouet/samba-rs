use crate::entities::{u16_from_le_bytes, u32_from_le_bytes, u64_from_le_bytes};

pub const PROTOCOL_ID: [u8; 4] = [0xFE, b'S', b'M', b'B'];

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("buffer too short")]
    BufferTooShort,
    #[error("invalid structure size, expected 64, received {_0}")]
    InvalidStructureSize(u16),
    #[error("invalid command {_0}")]
    InvalidCommand(u16),
    #[error("signature must be zero")]
    NonZeroSignature,
    #[error("tree_id must be zero")]
    TreeIdMustBeZero,
    #[error("session_id must be zero")]
    SessionIdMustBeZero,
    #[error("unknown flags")]
    UnknownFlags,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Command {
    Negotiate = 0x0000,
    SessionSetup = 0x0001,
    Logoff = 0x0002,
    TreeConnect = 0x0003,
    TreeDisconnect = 0x0004,
    Create = 0x0005,
    Close = 0x0006,
    Flush = 0x0007,
    Read = 0x0008,
    Write = 0x0009,
    Lock = 0x000A,
    IOCtl = 0x000B,
    Cancel = 0x000C,
    Echo = 0x000D,
    QueryDirectory = 0x000E,
    ChangeNotify = 0x000F,
    QueryInfo = 0x0010,
    SetInfo = 0x0011,
    OPLockBreak = 0x0012,
    ServerToClientNotification = 0x0013,
}

impl TryFrom<u16> for Command {
    type Error = u16;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Ok(match value {
            0x0000 => Self::Negotiate,
            0x0001 => Self::SessionSetup,
            0x0002 => Self::Logoff,
            0x0003 => Self::TreeConnect,
            0x0004 => Self::TreeDisconnect,
            0x0005 => Self::Create,
            0x0006 => Self::Close,
            0x0007 => Self::Flush,
            0x0008 => Self::Read,
            0x0009 => Self::Write,
            0x000A => Self::Lock,
            0x000B => Self::IOCtl,
            0x000C => Self::Cancel,
            0x000D => Self::Echo,
            0x000E => Self::QueryDirectory,
            0x000F => Self::ChangeNotify,
            0x0010 => Self::QueryInfo,
            0x0011 => Self::SetInfo,
            0x0012 => Self::OPLockBreak,
            0x0013 => Self::ServerToClientNotification,
            other => return Err(other),
        })
    }
}

impl Command {
    #[inline]
    pub const fn to_u16(&self) -> u16 {
        *self as u16
    }
}

bitflags::bitflags! {
    #[derive(Debug, PartialEq, Eq)]
    pub struct Flags: u32 {
        /// SMB2_FLAGS_SERVER_TO_REDIR
        ///
        /// 0x00000001
        ///
        /// When set, indicates the message is a response rather than a request.
        /// This MUST be set on responses sent from the server to the client,
        /// and MUST NOT be set on requests sent from the client to the server.
        const SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001;
        /// SMB2_FLAGS_ASYNC_COMMAND
        ///
        /// 0x00000002
        ///
        /// When set, indicates that this is an ASYNC SMB2 header.
        /// Always set for headers of the form described in this section.
        const SMB2_FLAGS_ASYNC_COMMAND = 0x00000002;
        /// SMB2_FLAGS_RELATED_OPERATIONS
        ///
        /// 0x00000004
        ///
        /// When set in an SMB2 request, indicates that this request is a related
        /// operation in a compounded request chain. The use of this flag in an
        /// SMB2 request is as specified in section 3.2.4.1.4.
        ///
        /// When set in an SMB2 compound response, indicates that the request
        /// corresponding to this response was part of a related operation in a compounded
        /// request chain. The use of this flag in an SMB2 response is as specified
        /// in section 3.3.5.2.7.2.
        const SMB2_FLAGS_RELATED_OPERATIONS = 0x00000004;
        /// SMB2_FLAGS_SIGNED
        ///
        /// 0x00000008
        ///
        /// When set, indicates that this packet has been signed.
        /// The use of this flag is as specified in section 3.1.5.1.
        const SMB2_FLAGS_SIGNED = 0x00000008;
        /// SMB2_FLAGS_PRIORITY_MASK
        ///
        /// 0x00000070
        ///
        /// This flag is only valid for the SMB 3.1.1 dialect.
        /// It is a mask for the requested I/O priority of the request,
        /// and it MUST be a value in the range 0 to 7.
        const SMB2_FLAGS_PRIORITY_MASK = 0x00000070;
        /// SMB2_FLAGS_DFS_OPERATIONS
        ///
        /// 0x10000000
        ///
        /// When set, indicates that this command is a Distributed File System (DFS)
        /// operation. The use of this flag is as specified in section 3.3.5.9.
        const SMB2_FLAGS_DFS_OPERATIONS = 0x10000000;
        /// SMB2_FLAGS_REPLAY_OPERATION
        ///
        /// 0x20000000
        ///
        /// This flag is only valid for the SMB 3.x dialect family.
        /// When set, it indicates that this command is a replay operation.
        ///
        /// The client MUST ignore this bit on receipt.
        const SMB2_FLAGS_REPLAY_OPERATION = 0x20000000;
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Header {
    /// CreditCharge (2 bytes)
    ///
    /// In the SMB 2.0.2 dialect, this field MUST NOT be used and MUST be reserved.
    /// The sender MUST set this to 0, and the receiver MUST ignore it.
    ///
    /// In all other dialects, this field indicates the number of credits that this request consumes.
    pub credit_charge: u16,
    /// Status (4 bytes)
    ///
    /// The client MUST set this field to 0 and the server MUST ignore it on receipt.
    /// In all SMB dialects for a response this field is interpreted as the Status field.
    /// This field can be set to any value. For a list of valid status codes, see [MS-ERREF] section 2.3.
    pub status: u32,
    /// Command (2 bytes)
    ///
    /// The command code of this packet.
    pub command: Command,
    /// CreditRequest/CreditResponse (2 bytes)
    ///
    /// On a request, this field indicates the number of credits the client is requesting.
    /// On a response, it indicates the number of credits granted to the client.
    pub credit_value: u16,
    /// Flags (4 bytes)
    ///
    /// A flags field, which indicates how to process the operation.
    pub flags: Flags,
    /// NextCommand (4 bytes)
    ///
    /// For a compounded request and response, this field MUST be set to the offset, in bytes,
    /// from the beginning of this SMB2 header to the start of the subsequent 8-byte aligned SMB2 header.
    /// If this is not a compounded request or response, or this is the last header in a compounded
    /// request or response, this value MUST be 0.
    pub next_command: u32,
    /// MessageId (8 bytes)
    ///
    /// A value that identifies a message request and response uniquely across all messages that are sent
    /// on the same SMB 2 Protocol transport connection.
    pub message_id: u64,
    pub variant: HeaderVariant,
    /// SessionId (8 bytes)
    ///
    /// Uniquely identifies the established session for the command. This field MUST be set to 0
    /// for an SMB2 NEGOTIATE Request (section 2.2.3) and for an SMB2 NEGOTIATE Response (section 2.2.4).
    pub session_id: u64,
    /// Signature (16 bytes)
    ///
    /// The 16-byte signature of the message, if SMB2_FLAGS_SIGNED is set in the Flags field
    /// of the SMB2 header and the message is not encrypted.
    /// If the message is not signed, this field MUST be 0.
    pub signature: [u8; 16],
}

#[derive(Debug, PartialEq, Eq)]
pub enum HeaderVariant {
    Async {
        /// AsyncId (8 bytes)
        ///
        /// A unique identification number that is created by the server to handle operations asynchronously,
        /// as specified in section 3.3.4.2.
        async_id: u64,
    },
    Sync {
        /// Reserved (4 bytes)
        ///
        /// The client SHOULD set this field to 0. The server MAY ignore this field on receipt.
        reserved: u32,
        /// TreeId (4 bytes)
        ///
        /// Uniquely identifies the tree connect for the command.
        /// This MUST be 0 for the SMB2 TREE_CONNECT Request.
        /// The TreeId can be any unsigned 32-bit integer that is received from a previous
        /// SMB2 TREE_CONNECT Response. TreeId SHOULD be set to 0 for the following commands:
        /// - SMB2 NEGOTIATE Request
        /// - SMB2 NEGOTIATE Response
        /// - SMB2 SESSION_SETUP Request
        /// - SMB2 SESSION_SETUP Response
        /// - SMB2 LOGOFF Request
        /// - SMB2 LOGOFF Response
        /// - SMB2 ECHO Request
        /// - SMB2 ECHO Response
        /// - SMB2 CANCEL Request
        tree_id: u32,
    },
}

impl HeaderVariant {
    pub fn encode(&self, buf: &mut [u8]) {
        match self {
            Self::Async { async_id } => {
                buf.copy_from_slice(&async_id.to_le_bytes());
            }
            Self::Sync {
                reserved: _,
                tree_id,
            } => {
                // reserved is supposed to only be zeros, skipping
                buf[4..].copy_from_slice(&tree_id.to_le_bytes());
            }
        }
    }
}

impl Header {
    pub fn parse(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < 64 {
            return Err(ParseError::BufferTooShort);
        }

        // This MUST be set to 64, which is the size, in bytes, of the SMB2 header structure.
        let structure_size = u16_from_le_bytes(&buf[4..6]);
        if structure_size != 64 {
            return Err(ParseError::InvalidStructureSize(structure_size));
        }

        let credit_charge = u16_from_le_bytes(&buf[6..8]);
        let status = u32_from_le_bytes(&buf[8..12]);

        let command = u16_from_le_bytes(&buf[12..14]);
        let command = Command::try_from(command).map_err(ParseError::InvalidCommand)?;

        let credit_value = u16_from_le_bytes(&buf[14..16]);

        let flags =
            Flags::from_bits(u32_from_le_bytes(&buf[16..20])).ok_or(ParseError::UnknownFlags)?;
        let next_command = u32_from_le_bytes(&buf[20..24]);
        let message_id = u64_from_le_bytes(&buf[24..32]);

        let variant = if flags.contains(Flags::SMB2_FLAGS_ASYNC_COMMAND) {
            let async_id = u64_from_le_bytes(&buf[32..40]);

            HeaderVariant::Async { async_id }
        } else {
            let reserved = u32_from_le_bytes(&buf[32..36]);
            let tree_id = u32_from_le_bytes(&buf[36..40]);

            // This MUST be 0 for the SMB2 TREE_CONNECT Request.
            if matches!(command, Command::TreeConnect)
                && !flags.contains(Flags::SMB2_FLAGS_SERVER_TO_REDIR)
                && tree_id != 0
            {
                return Err(ParseError::TreeIdMustBeZero);
            }

            HeaderVariant::Sync { reserved, tree_id }
        };

        let session_id = u64_from_le_bytes(&buf[40..48]);

        // This field MUST be set to 0 for an SMB2 NEGOTIATE Request and for an SMB2 NEGOTIATE Response
        if matches!(command, Command::Negotiate) && session_id != 0 {
            return Err(ParseError::SessionIdMustBeZero);
        }

        let mut signature = [0u8; 16];
        signature.copy_from_slice(&buf[48..64]);

        if !flags.contains(Flags::SMB2_FLAGS_SIGNED) && signature != [0u8; 16] {
            return Err(ParseError::NonZeroSignature);
        }

        Ok(Self {
            credit_charge,
            status,
            command,
            credit_value,
            flags,
            next_command,
            message_id,
            variant,
            session_id,
            signature,
        })
    }
}

impl Header {
    pub fn negociate() -> Self {
        Self {
            credit_charge: 0,
            status: 0,
            command: Command::Negotiate,
            credit_value: 0,
            flags: Flags::empty(),
            next_command: 0,
            message_id: 0,
            variant: HeaderVariant::Sync {
                reserved: 0,
                tree_id: 0,
            },
            session_id: 0,
            signature: [0; 16],
        }
    }

    pub fn encode(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf[0..4].copy_from_slice(&PROTOCOL_ID);
        buf[4..6].copy_from_slice(&64u16.to_le_bytes());
        buf[6..8].copy_from_slice(&self.credit_charge.to_le_bytes());
        buf[8..12].copy_from_slice(&self.status.to_le_bytes());
        buf[12..14].copy_from_slice(&self.command.to_u16().to_le_bytes());
        buf[14..16].copy_from_slice(&self.credit_value.to_le_bytes());
        buf[16..20].copy_from_slice(&self.flags.bits().to_le_bytes());
        buf[20..24].copy_from_slice(&self.next_command.to_le_bytes());
        buf[24..32].copy_from_slice(&self.message_id.to_le_bytes());
        self.variant.encode(&mut buf[32..40]);
        buf[40..48].copy_from_slice(&self.session_id.to_le_bytes());
        buf[48..64].copy_from_slice(&self.signature);
        buf
    }
}

#[cfg(test)]
mod tests {
    use crate::entities::header::v2::Flags;

    #[test]
    fn should_encode_decode_commands() {
        for i in 0..20u16 {
            let cmd = super::Command::try_from(i).unwrap();
            assert_eq!(cmd.to_u16(), i);
        }
    }

    #[test]
    fn should_not_parse_commands() {
        for i in 20u16..u16::MAX {
            let value = super::Command::try_from(i).unwrap_err();
            assert_eq!(value, i);
        }
    }

    #[test]
    fn should_fail_parsing_with_small_buffer() {
        for i in 0..64 {
            let buf = vec![0u8; i];
            let err = super::Header::parse(&buf).unwrap_err();
            assert!(matches!(err, super::ParseError::BufferTooShort));
        }
    }

    #[test]
    fn should_fail_parsing_with_invalid_structure_size() {
        let mut buf = [0u8; 64];
        for size in (0..=u16::MAX).filter(|i| *i != 64) {
            buf[4..6].copy_from_slice(&size.to_le_bytes());
            let err = super::Header::parse(&buf).unwrap_err();
            assert!(matches!(err, super::ParseError::InvalidStructureSize(_)));
        }
    }

    #[test]
    fn should_fail_parsing_negotiate_with_session_id() {
        let mut header = super::Header::negociate();
        header.session_id = 42;
        let encoded = header.encode();
        let err = super::Header::parse(&encoded).unwrap_err();
        assert!(matches!(err, super::ParseError::SessionIdMustBeZero));
    }

    #[test]
    fn should_fail_parsing_without_signature_when_expected() {
        let mut header = super::Header::negociate();
        header.flags.set(Flags::SMB2_FLAGS_SIGNED, false);
        header.signature[0] = 1;
        let encoded = header.encode();
        let err = super::Header::parse(&encoded).unwrap_err();
        assert!(matches!(err, super::ParseError::NonZeroSignature));
    }

    #[test]
    fn should_fail_parsing_tree_connect_with_tree_id() {
        let mut header = super::Header::negociate();
        header.command = super::Command::TreeConnect;
        let encoded = header.encode();
        let _ = super::Header::parse(&encoded).unwrap();

        // tree_connect request
        let mut header = super::Header::negociate();
        header.command = super::Command::TreeConnect;
        header.variant = super::HeaderVariant::Sync {
            reserved: 0,
            tree_id: 42,
        };
        let encoded = header.encode();
        let err = super::Header::parse(&encoded).unwrap_err();
        assert!(matches!(err, super::ParseError::TreeIdMustBeZero));

        // tree_connect response
        let mut header = super::Header::negociate();
        header.command = super::Command::TreeConnect;
        header.variant = super::HeaderVariant::Sync {
            reserved: 0,
            tree_id: 42,
        };
        header.flags.set(Flags::SMB2_FLAGS_SERVER_TO_REDIR, true);
        let encoded = header.encode();
        let _ = super::Header::parse(&encoded).unwrap();
    }

    #[test]
    fn should_encode_async_variant() {
        let mut buf = [0u8; 8];
        super::HeaderVariant::Async { async_id: 42 }.encode(&mut buf);
        assert_eq!(buf, [42, 0, 0, 0, 0, 0, 0, 0]);
        super::HeaderVariant::Async { async_id: 12 }.encode(&mut buf);
        assert_eq!(buf, [12, 0, 0, 0, 0, 0, 0, 0]);
        super::HeaderVariant::Async { async_id: 1234 }.encode(&mut buf);
        assert_eq!(buf, [210, 4, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn should_encode_sync_variant() {
        let mut buf = [0u8; 8];
        super::HeaderVariant::Sync {
            reserved: 0,
            tree_id: 10,
        }
        .encode(&mut buf);
        assert_eq!(buf, [0, 0, 0, 0, 10, 0, 0, 0]);
        super::HeaderVariant::Sync {
            reserved: 0,
            tree_id: 128,
        }
        .encode(&mut buf);
        assert_eq!(buf, [0, 0, 0, 0, 128, 0, 0, 0]);
        super::HeaderVariant::Sync {
            reserved: 0,
            tree_id: 1234,
        }
        .encode(&mut buf);
        assert_eq!(buf, [0, 0, 0, 0, 210, 4, 0, 0]);
    }

    #[test]
    fn should_encode_decode_negotiate() {
        let header = super::Header::negociate();
        let encoded = header.encode();
        let decoded = super::Header::parse(&encoded).unwrap();
        assert_eq!(header, decoded);
    }
}
