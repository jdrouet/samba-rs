pub mod header;
pub mod netbios;
pub mod v1;
pub mod v2;

const fn u16_from_le_bytes(buf: &[u8]) -> u16 {
    let mut res = [0u8; 2];
    res.copy_from_slice(buf);
    u16::from_le_bytes(res)
}

const fn u32_from_le_bytes(buf: &[u8]) -> u32 {
    let mut res = [0u8; 4];
    res.copy_from_slice(buf);
    u32::from_le_bytes(res)
}

const fn u64_from_le_bytes(buf: &[u8]) -> u64 {
    let mut res = [0u8; 8];
    res.copy_from_slice(buf);
    u64::from_le_bytes(res)
}
