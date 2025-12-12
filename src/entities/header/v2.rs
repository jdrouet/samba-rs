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
}

#[derive(Debug)]
pub enum Command {
    Negotiate,
    SessionSetup,
    Logoff,
    TreeConnect,
    TreeDisconnect,
    Create,
    Close,
    Flush,
    Read,
    Write,
    Lock,
    IOCtl,
    Cancel,
    Echo,
    QueryDirectory,
    ChangeNotify,
    QueryInfo,
    SetInfo,
    OPLockBreak,
    ServerToClientNotification,
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

#[derive(Debug)]
pub struct Flags(pub u32);

impl Flags {
    /// SMB2_FLAGS_SERVER_TO_REDIR
    ///
    /// 0x00000001
    ///
    /// When set, indicates the message is a response rather than a request.
    /// This MUST be set on responses sent from the server to the client,
    /// and MUST NOT be set on requests sent from the client to the server.
    pub fn is_server_to_redir(&self) -> bool {
        self.0 & 0x00000001 > 0
    }

    /// SMB2_FLAGS_ASYNC_COMMAND
    ///
    /// 0x00000002
    ///
    /// When set, indicates that this is an ASYNC SMB2 header.
    /// Always set for headers of the form described in this section.
    pub fn is_async_command(&self) -> bool {
        self.0 & 0x00000002 > 0
    }

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
    pub fn is_related_operations(&self) -> bool {
        self.0 & 0x00000004 > 0
    }

    /// SMB2_FLAGS_SIGNED
    ///
    /// 0x00000008
    ///
    /// When set, indicates that this packet has been signed.
    /// The use of this flag is as specified in section 3.1.5.1.
    pub fn is_signed(&self) -> bool {
        self.0 & 0x00000008 > 0
    }

    /// SMB2_FLAGS_PRIORITY_MASK
    ///
    /// 0x00000070
    ///
    /// This flag is only valid for the SMB 3.1.1 dialect.
    /// It is a mask for the requested I/O priority of the request,
    /// and it MUST be a value in the range 0 to 7.
    pub fn is_priority_mask(&self) -> bool {
        self.0 & 0x00000070 > 0
    }

    /// SMB2_FLAGS_DFS_OPERATIONS
    ///
    /// 0x10000000
    ///
    /// When set, indicates that this command is a Distributed File System (DFS)
    /// operation. The use of this flag is as specified in section 3.3.5.9.
    pub fn is_dfs_operations(&self) -> bool {
        self.0 & 0x10000000 > 0
    }

    /// SMB2_FLAGS_REPLAY_OPERATION
    ///
    /// 0x20000000
    ///
    /// This flag is only valid for the SMB 3.x dialect family.
    /// When set, it indicates that this command is a replay operation.
    ///
    /// The client MUST ignore this bit on receipt.
    pub fn is_replay_operation(&self) -> bool {
        self.0 & 0x20000000 > 0
    }
}

#[derive(Debug)]
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

#[derive(Debug)]
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

impl Header {
    pub fn parse(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < 64 {
            return Err(ParseError::BufferTooShort);
        }

        // This MUST be set to 64, which is the size, in bytes, of the SMB2 header structure.
        let mut structure_size = [0u8; 2];
        structure_size.copy_from_slice(&buf[4..6]);
        let structure_size = u16::from_le_bytes(structure_size);
        if structure_size != 64 {
            return Err(ParseError::InvalidStructureSize(structure_size));
        }

        let mut credit_charge = [0u8; 2];
        credit_charge.copy_from_slice(&buf[6..8]);
        let credit_charge = u16::from_le_bytes(credit_charge);

        let mut status = [0u8; 4];
        status.copy_from_slice(&buf[8..12]);
        let status = u32::from_le_bytes(status);

        let mut command = [0u8; 2];
        command.copy_from_slice(&buf[12..14]);
        let command = u16::from_be_bytes(command);
        let command = Command::try_from(command).map_err(ParseError::InvalidCommand)?;

        let mut credit_value = [0u8; 2];
        credit_value.copy_from_slice(&buf[14..16]);
        let credit_value = u16::from_le_bytes(credit_value);

        let mut flags = [0u8; 4];
        flags.copy_from_slice(&buf[16..20]);
        let flags = Flags(u32::from_le_bytes(flags));

        let mut next_command = [0u8; 4];
        next_command.copy_from_slice(&buf[20..24]);
        let next_command = u32::from_le_bytes(next_command);

        let mut message_id = [0u8; 8];
        message_id.copy_from_slice(&buf[24..32]);
        let message_id = u64::from_le_bytes(message_id);

        let variant = if flags.is_async_command() {
            let mut async_id = [0u8; 8];
            async_id.copy_from_slice(&buf[32..40]);
            let async_id = u64::from_le_bytes(async_id);

            HeaderVariant::Async { async_id }
        } else {
            let mut reserved = [0u8; 4];
            reserved.copy_from_slice(&buf[32..36]);
            let reserved = u32::from_le_bytes(reserved);

            let mut tree_id = [0u8; 4];
            tree_id.copy_from_slice(&buf[36..40]);
            let tree_id = u32::from_le_bytes(tree_id);

            // This MUST be 0 for the SMB2 TREE_CONNECT Request.
            if matches!(command, Command::TreeConnect) && tree_id != 0 {
                return Err(ParseError::TreeIdMustBeZero);
            }

            HeaderVariant::Sync { reserved, tree_id }
        };

        let mut session_id = [0u8; 8];
        session_id.copy_from_slice(&buf[40..48]);
        let session_id = u64::from_le_bytes(session_id);

        // This field MUST be set to 0 for an SMB2 NEGOTIATE Request and for an SMB2 NEGOTIATE Response
        if matches!(command, Command::Negotiate) && session_id != 0 {
            return Err(ParseError::SessionIdMustBeZero);
        }

        let mut signature = [0u8; 16];
        signature.copy_from_slice(&buf[48..64]);

        if !flags.is_signed() && signature != [0u8; 16] {
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

#[cfg(test)]
mod tests {
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
            (&mut buf[4..6]).copy_from_slice(&size.to_le_bytes());
            let err = super::Header::parse(&buf).unwrap_err();
            assert!(matches!(err, super::ParseError::InvalidStructureSize(_)));
        }
    }
}
