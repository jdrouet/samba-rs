pub mod header;
pub mod netbios;
pub mod v1;
pub mod v2;

struct BufferIterator<'a>(&'a [u8]);

impl<'a> BufferIterator<'a> {
    fn next(&mut self, length: usize) -> Option<&'a [u8]> {
        let value = self.0.get(0..length)?;
        self.0 = &self.0[length..];
        Some(value)
    }

    fn next_u16(&mut self) -> Option<u16> {
        self.next(2).map(u16_from_le_bytes)
    }
}

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

const fn u128_from_le_bytes(buf: &[u8]) -> u128 {
    let mut res = [0u8; 16];
    res.copy_from_slice(buf);
    u128::from_le_bytes(res)
}
