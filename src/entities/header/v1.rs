//! Taken from https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/69a29f73-de0c-45a6-a1aa-8ceeea42217f

use crate::entities::{u16_from_le_bytes, u32_from_le_bytes};

pub const PROTOCOL_ID: [u8; 4] = [0xFF, b'S', b'M', b'B'];

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("buffer too short")]
    BufferTooShort,
    #[error("invalid command {_0}")]
    InvalidCommand(u8),
    #[error("reserved must be zero")]
    ReservedMustBeZero,
    #[error("unknown flags")]
    UnknownFlags,
    #[error("unknown extended flags")]
    UnknownExtendedFlags,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    CreateDirectory = 0x00,
    DeleteDirectory = 0x01,
    Open = 0x02,
    Create = 0x03,
    Close = 0x04,
    Flush = 0x05,
    Delete = 0x06,
    Rename = 0x07,
    QueryInformation = 0x08,
    SetInformation = 0x09,

    Read = 0x0A,
    Write = 0x0B,
    LockByteRange = 0x0C,
    UnlockByteRange = 0x0D,
    CreateTemporary = 0x0E,
    CreateNew = 0x0F,
    CheckDirectory = 0x10,
    ProcessExit = 0x11,
    Seek = 0x12,

    LockAndRead = 0x13,
    WriteAndUnlock = 0x14,

    ReadRaw = 0x1A,
    ReadMpx = 0x1B,
    ReadMpxSecondary = 0x1C,
    WriteRaw = 0x1D,
    WriteMpx = 0x1E,
    WriteMpxSecondary = 0x1F,
    WriteComplete = 0x20,
    QueryServer = 0x21,

    SetInformation2 = 0x22,
    QueryInformation2 = 0x23,
    LockingAndx = 0x24,
    Transaction = 0x25,
    TransactionSecondary = 0x26,
    Ioctl = 0x27,
    IoctlSecondary = 0x28,
    Copy = 0x29,
    Move = 0x2A,
    Echo = 0x2B,
    WriteAndClose = 0x2C,
    OpenAndx = 0x2D,
    ReadAndx = 0x2E,
    WriteAndx = 0x2F,

    TreeConnect = 0x70,
    TreeDisconnect = 0x71,
    Negotiate = 0x72,
    SessionSetupAndx = 0x73,
    LogoffAndx = 0x74,
    TreeConnectAndx = 0x75,

    QueryInformationDisk = 0x80,
    Search = 0x81,
    Find = 0x82,
    FindUnique = 0x83,
    FindClose = 0x84,

    NtTransact = 0xA0,
    NtTransactSecondary = 0xA1,
    NtCreateAndx = 0xA2,
    NtCancel = 0xA3,
    NtRename = 0xA4,

    SendMessage = 0xD0,
    SendBroadcastMessage = 0xD1,
    SendForwardMessage = 0xD2,
    Cancel = 0xD3,
    GetMachineName = 0xD4,
    SendStartMailslot = 0xD5,
    SendEndMailslot = 0xD6,
    SendTextMailslot = 0xD7,
}

impl TryFrom<u8> for Command {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x00 => Self::CreateDirectory,
            0x01 => Self::DeleteDirectory,
            0x02 => Self::Open,
            0x03 => Self::Create,
            0x04 => Self::Close,
            0x05 => Self::Flush,
            0x06 => Self::Delete,
            0x07 => Self::Rename,
            0x08 => Self::QueryInformation,
            0x09 => Self::SetInformation,

            0x0A => Self::Read,
            0x0B => Self::Write,
            0x0C => Self::LockByteRange,
            0x0D => Self::UnlockByteRange,
            0x0E => Self::CreateTemporary,
            0x0F => Self::CreateNew,
            0x10 => Self::CheckDirectory,
            0x11 => Self::ProcessExit,
            0x12 => Self::Seek,

            0x13 => Self::LockAndRead,
            0x14 => Self::WriteAndUnlock,

            0x1A => Self::ReadRaw,
            0x1B => Self::ReadMpx,
            0x1C => Self::ReadMpxSecondary,
            0x1D => Self::WriteRaw,
            0x1E => Self::WriteMpx,
            0x1F => Self::WriteMpxSecondary,
            0x20 => Self::WriteComplete,
            0x21 => Self::QueryServer,

            0x22 => Self::SetInformation2,
            0x23 => Self::QueryInformation2,
            0x24 => Self::LockingAndx,
            0x25 => Self::Transaction,
            0x26 => Self::TransactionSecondary,
            0x27 => Self::Ioctl,
            0x28 => Self::IoctlSecondary,
            0x29 => Self::Copy,
            0x2A => Self::Move,
            0x2B => Self::Echo,
            0x2C => Self::WriteAndClose,
            0x2D => Self::OpenAndx,
            0x2E => Self::ReadAndx,
            0x2F => Self::WriteAndx,

            0x70 => Self::TreeConnect,
            0x71 => Self::TreeDisconnect,
            0x72 => Self::Negotiate,
            0x73 => Self::SessionSetupAndx,
            0x74 => Self::LogoffAndx,
            0x75 => Self::TreeConnectAndx,

            0x80 => Self::QueryInformationDisk,
            0x81 => Self::Search,
            0x82 => Self::Find,
            0x83 => Self::FindUnique,
            0x84 => Self::FindClose,

            0xA0 => Self::NtTransact,
            0xA1 => Self::NtTransactSecondary,
            0xA2 => Self::NtCreateAndx,
            0xA3 => Self::NtCancel,
            0xA4 => Self::NtRename,

            0xD0 => Self::SendMessage,
            0xD1 => Self::SendBroadcastMessage,
            0xD2 => Self::SendForwardMessage,
            0xD3 => Self::Cancel,
            0xD4 => Self::GetMachineName,
            0xD5 => Self::SendStartMailslot,
            0xD6 => Self::SendEndMailslot,
            0xD7 => Self::SendTextMailslot,

            other => return Err(other),
        })
    }
}

impl Command {
    #[inline]
    pub const fn to_u8(&self) -> u8 {
        *self as u8
    }
}

bitflags::bitflags! {
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct Flags: u8 {
        /// This bit is set (1) in the SMB_COM_NEGOTIATE (0x72) Response (section 2.2.4.52.2)
        /// if the server supports SMB_COM_LOCK_AND_READ (0x13) (section 2.2.4.20)
        /// and SMB_COM_WRITE_AND_UNLOCK (0x14) (section 2.2.4.21) commands.
        const SMB_FLAGS_LOCK_AND_READ_OK = 0x01;
        /// Obsolete
        ///
        /// When set (on an SMB request being sent to the server), the client guarantees
        /// that there is a receive buffer posted such that a send without acknowledgment
        /// can be used by the server to respond to the client's request.
        ///
        /// This behavior is specific to an obsolete transport. This bit MUST be set
        /// to zero by the client and MUST be ignored by the server.
        const SMB_FLAGS_BUF_AVAIL = 0x02;
        /// Obsolete. If this bit is set then all pathnames in the SMB SHOULD be treated as case-insensitive.
        const SMB_FLAGS_CASE_INSENSITIVE = 0x08;
        /// When set in session setup, this bit indicates that all paths sent to
        /// the server are already in canonical format. That is, all file and
        /// directory names are composed of valid file name characters in all upper-case,
        /// and that the path segments are separated by backslash characters ('\').
        const SMB_FLAGS_CANONICALIZED_PATHS = 0x10;
        /// Obsolescent.
        ///
        /// This bit has meaning only in the deprecated SMB_COM_OPEN (0x02) Request
        /// (section 2.2.4.3.1), SMB_COM_CREATE (0x03) Request (section 2.2.4.4.1),
        /// and SMB_COM_CREATE_NEW (0x0F) Request (section 2.2.4.16.1) messages,
        /// where it is used to indicate that the client is requesting an Exclusive OpLock.
        /// It SHOULD be set to zero by the client, and ignored by the server, in all
        /// other SMB requests. If the server grants this OpLock request, then this bit
        /// SHOULD remain set in the corresponding response SMB to indicate to the client
        /// that the OpLock request was granted.
        const SMB_FLAGS_OPLOCK = 0x20;
        /// Obsolescent.
        ///
        /// This bit has meaning only in the deprecated SMB_COM_OPEN (0x02) Request
        /// (section 2.2.4.3.1), SMB_COM_CREATE (0x03) Request (section 2.2.4.4.1),
        /// and SMB_COM_CREATE_NEW (0x0F) Request (section 2.2.4.16.1) messages,
        /// where it is used to indicate that the client is requesting a Batch OpLock.
        /// It SHOULD be set to zero by the client, and ignored by the server, in all
        /// other SMB requests. If the server grants this OpLock request, then this
        /// bit SHOULD remain set in the corresponding response SMB to indicate to
        /// the client that the OpLock request was granted.
        ///
        /// If the SMB_FLAGS_OPLOCK bit is clear (0), then the SMB_FLAGS_OPBATCH bit is ignored.
        const SMB_FLAGS_OPBATCH = 0x40;

        /// When on, this message is being sent from the server in response to
        /// a client request. The Command field usually contains the same value
        /// in a protocol request from the client to the server as in the matching
        /// response from the server to the client. This bit unambiguously
        /// distinguishes the message as a server response.
        const SMB_FLAGS_REPLY = 0x80;
    }
}

bitflags::bitflags! {
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct ExtendedFlags: u16 {
        /// If the bit is set, the message MAY contain long file names. If the bit is clear
        /// then file names in the message MUST adhere to the 8.3 naming convention.
        ///
        /// If set in a client request for directory enumeration, the server MAY return long
        /// names (that is, names that are not 8.3 names) in the response to this request.
        /// If not set in a client request for directory enumeration, the server MUST return
        /// only 8.3 names in the response to this request. This flag indicates that in a direct
        /// enumeration request, paths returned by the server are not restricted to 8.3 names
        /// format. This bit field SHOULD be set to 1 when the negotiated dialect is LANMAN2.0 or later.
        const SMB_FLAGS2_LONG_NAMES = 0x0001;
        /// If the bit is set, the client is aware of extended attributes (EAs).
        ///
        /// The client MUST set this bit if the client is aware of extended attributes.
        /// In response to a client request with this flag set, a server MAY include extended
        /// attributes in the response. This bit field SHOULD be set to 1 when the negotiated
        /// dialect is LANMAN2.0 or later.
        const SMB_FLAGS2_EAS = 0x0002;
        /// If set by the client, the client is requesting signing (if signing is not yet active)
        /// or the message being sent is signed. This bit is used on the SMB header of an
        /// SMB_COM_SESSION_SETUP_ANDX (section 2.2.4.53) client request to indicate that the client
        /// supports signing and that the server can choose to enforce signing on the connection
        /// based on its configuration.
        ///
        /// To turn on signing for a connection, the server MUST set this flag and also sign
        /// the SMB_COM_SESSION_SETUP_ANDX Response (section 2.2.4.53), after which all of
        /// the traffic on the connection (except for OpLock Break notifications) MUST be signed.
        /// In the SMB header of other CIFS client requests, the setting of this bit indicates
        /// that the packet has been signed. This bit field SHOULD be set to 1 when the negotiated
        /// dialect is NT LANMAN or later.
        const SMB_FLAGS2_SMB_SECURITY_SIGNATURE = 0x0004;
        /// Reserved but not implemented.
        const SMB_FLAGS2_IS_LONG_NAME = 0x0040;
        /// If the bit is set, any pathnames in this SMB SHOULD be resolved in the Distributed File System (DFS).
        const SMB_FLAGS2_DFS = 0x1000;
        /// This flag is useful only on a read request. If the bit is set, then the client MAY read the file
        /// if the client does not have read permission but does have execute permission. This bit field SHOULD
        /// be set to 1 when the negotiated dialect is LANMAN2.0 or later.
        /// This flag is also known as SMB_FLAGS2_READ_IF_EXECUTE.
        const SMB_FLAGS2_PAGING_IO = 0x2000;
        /// If this bit is set in a client request, the server MUST return errors as 32-bit NTSTATUS codes
        /// in the response. If it is clear, the server SHOULD<27> return errors in SMBSTATUS format.
        ///
        /// If this bit is set in the server response, the Status field in the header is formatted as
        /// an NTSTATUS code; else, it is in SMBSTATUS format.
        const SMB_FLAGS2_NT_STATUS = 0x4000;
        /// If set in a client request or server response, each field that contains a string in
        /// this SMB message MUST be encoded as an array of 16-bit Unicode characters, unless otherwise specified.
        ///
        /// If this bit is clear, each of these fields MUST be encoded as an array of OEM characters.
        /// This bit field SHOULD be set to 1 when the negotiated dialect is NT LANMAN.
        const SMB_FLAGS2_UNICODE = 0x8000;
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SecurityFeatures {
    Negotiated {
        /// SecuritySignature (8 bytes)
        ///
        /// If SMB signing has been negotiated, this field MUST contain an 8-byte
        /// cryptographic message signature that can be used to detect whether
        /// the message was modified while in transit. The use of message signing
        /// is mutually exclusive with connectionless transport.
        signature: u64,
    },
    Connectionless {
        /// Key (4 bytes)
        ///
        /// An encryption key used for validating messages over connectionless transports.
        key: u32,
        /// CID (2 bytes)
        ///
        /// A connection identifier (CID).
        connection_id: u16,
        /// SequenceNumber (2 bytes)
        ///
        /// A number used to identify the sequence of a message over connectionless transports.
        sequence_number: u16,
    },
    Reserved {
        /// Finally, if neither of the above two cases applies, the SecurityFeatures field is
        /// treated as a reserved field, which MUST be set to zero by the client
        /// and MUST be ignored by the server.
        value: u64,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub struct Header {
    /// Command (1 byte)
    ///
    /// A one-byte command code. Defined SMB command codes are listed in section 2.2.2.1.
    pub command: Command,
    /// Status (4 bytes)
    ///
    /// A 32-bit field used to communicate error messages from the server to the client.
    pub status: u32,
    /// Flags (1 byte)
    ///
    /// An 8-bit field of 1-bit flags describing various features in effect for the message.
    pub flags: Flags,
    /// Flags2 (2 bytes)
    ///
    /// A 16-bit field of 1-bit flags that represent various features in effect for the message.
    /// Unspecified bits are reserved and MUST be zero.
    pub extended_flags: ExtendedFlags,
    /// PIDHigh (2 bytes)
    ///
    /// If set to a nonzero value, this field represents the high-order bytes of a process
    /// identifier (PID). It is combined with the PIDLow field below to form a full PID.
    pub pid_high: u16,
    /// SecurityFeatures (8 bytes)
    ///
    /// This 8-byte field has three possible interpretations.
    ///
    /// In the case that security signatures are negotiated (see SMB_COM_NEGOTIATE (0x72)
    /// (section 2.2.4.52), the following format MUST be observed.
    pub security_features: [u8; 8],
    /// TID (2 bytes)
    ///
    /// A tree identifier (TID).
    pub tree_id: u16,
    /// PIDLow (2 bytes)
    ///
    /// The lower 16-bits of the PID.
    pub pid_low: u16,
    /// UID (2 bytes)
    ///
    /// A user identifier (UID).
    pub user_id: u16,
    /// MID (2 bytes)
    ///
    /// A multiplex identifier (MID).
    pub multiplex_id: u16,
}

impl Header {
    pub fn parse(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < 32 {
            return Err(ParseError::BufferTooShort);
        }

        let command = Command::try_from(buf[4]).map_err(ParseError::InvalidCommand)?;

        let status = u32_from_le_bytes(&buf[5..9]);
        let flags = Flags::from_bits(buf[9]).ok_or(ParseError::UnknownFlags)?;

        let extended_flags = ExtendedFlags::from_bits(u16_from_le_bytes(&buf[10..12]))
            .ok_or(ParseError::UnknownExtendedFlags)?;
        let pid_high = u16_from_le_bytes(&buf[12..14]);

        let mut security_features = [0u8; 8];
        security_features.copy_from_slice(&buf[14..22]);

        // 22..24 must be zero
        if buf[22] != 0 || buf[23] != 0 {
            return Err(ParseError::ReservedMustBeZero);
        }

        let tree_id = u16_from_le_bytes(&buf[24..26]);
        let pid_low = u16_from_le_bytes(&buf[26..28]);
        let user_id = u16_from_le_bytes(&buf[28..30]);
        let multiplex_id = u16_from_le_bytes(&buf[30..32]);

        Ok(Self {
            command,
            status,
            flags,
            extended_flags,
            pid_high,
            security_features,
            tree_id,
            pid_low,
            user_id,
            multiplex_id,
        })
    }
}
