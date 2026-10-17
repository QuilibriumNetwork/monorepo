//! Binary file-index format for chunked file deploys. Byte-exact port of
//! Go `types/hypergraph/file_index.go`.
//!
//! ```text
//! Header (28 bytes):
//!   magic:       8 bytes = "FILEINDX"
//!   version:     4 bytes = uint32(1)  big-endian
//!   chunk_size:  4 bytes = uint32      big-endian
//!   total_size:  8 bytes = uint64      big-endian
//!   chunk_count: 4 bytes = uint32      big-endian
//! Body:
//!   blob_addrs:  chunk_count * 32 bytes (data addresses, in chunk order)
//! ```

pub const FILE_INDEX_MAGIC: &[u8; 8] = b"FILEINDX";
pub const FILE_INDEX_VERSION: u32 = 1;
pub const FILE_INDEX_HEADER_SIZE: usize = 28;
pub const FILE_INDEX_ADDR_SIZE: usize = 32;

/// Build a binary file index. Mirror of Go `BuildFileIndex`.
pub fn build_file_index(total_size: u64, chunk_size: u32, blob_addresses: &[[u8; 32]]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(FILE_INDEX_HEADER_SIZE + blob_addresses.len() * FILE_INDEX_ADDR_SIZE);
    buf.extend_from_slice(FILE_INDEX_MAGIC);
    buf.extend_from_slice(&FILE_INDEX_VERSION.to_be_bytes());
    buf.extend_from_slice(&chunk_size.to_be_bytes());
    buf.extend_from_slice(&total_size.to_be_bytes());
    buf.extend_from_slice(&(blob_addresses.len() as u32).to_be_bytes());
    for addr in blob_addresses {
        buf.extend_from_slice(addr);
    }
    buf
}

/// `true` if `data` begins with the `FILEINDX` magic. Mirror of Go `IsFileIndex`.
pub fn is_file_index(data: &[u8]) -> bool {
    data.len() >= 8 && &data[0..8] == FILE_INDEX_MAGIC
}

/// Parse a binary file index into `(total_size, chunk_size, blob_addresses)`.
/// Mirror of Go `ParseFileIndex`.
pub fn parse_file_index(data: &[u8]) -> anyhow::Result<(u64, u32, Vec<[u8; 32]>)> {
    if data.len() < FILE_INDEX_HEADER_SIZE {
        anyhow::bail!("file index too short: {} bytes", data.len());
    }
    if &data[0..8] != FILE_INDEX_MAGIC {
        anyhow::bail!("invalid file index magic");
    }
    let version = u32::from_be_bytes(data[8..12].try_into().unwrap());
    if version != FILE_INDEX_VERSION {
        anyhow::bail!("unsupported file index version: {version}");
    }
    let chunk_size = u32::from_be_bytes(data[12..16].try_into().unwrap());
    let total_size = u64::from_be_bytes(data[16..24].try_into().unwrap());
    let chunk_count = u32::from_be_bytes(data[24..28].try_into().unwrap()) as usize;

    let expected_len = FILE_INDEX_HEADER_SIZE + chunk_count * FILE_INDEX_ADDR_SIZE;
    if data.len() < expected_len {
        anyhow::bail!(
            "file index truncated: expected {expected_len} bytes, got {}",
            data.len()
        );
    }
    let mut blob_addresses = Vec::with_capacity(chunk_count);
    for i in 0..chunk_count {
        let off = FILE_INDEX_HEADER_SIZE + i * FILE_INDEX_ADDR_SIZE;
        let mut a = [0u8; 32];
        a.copy_from_slice(&data[off..off + FILE_INDEX_ADDR_SIZE]);
        blob_addresses.push(a);
    }
    Ok((total_size, chunk_size, blob_addresses))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_parse_round_trip() {
        let addrs = vec![[0x11u8; 32], [0x22u8; 32], [0x33u8; 32]];
        let idx = build_file_index(9_000_000, 4 * 1024 * 1024, &addrs);
        assert!(is_file_index(&idx));
        assert_eq!(idx.len(), FILE_INDEX_HEADER_SIZE + 3 * 32);
        let (total, chunk, got) = parse_file_index(&idx).unwrap();
        assert_eq!(total, 9_000_000);
        assert_eq!(chunk, 4 * 1024 * 1024);
        assert_eq!(got, addrs);
    }

    #[test]
    fn known_header_bytes() {
        let idx = build_file_index(1, 2, &[[0xAAu8; 32]]);
        assert_eq!(&idx[0..8], b"FILEINDX");
        assert_eq!(&idx[8..12], &[0, 0, 0, 1]); // version 1
        assert_eq!(&idx[12..16], &[0, 0, 0, 2]); // chunk_size 2
        assert_eq!(&idx[16..24], &[0, 0, 0, 0, 0, 0, 0, 1]); // total_size 1
        assert_eq!(&idx[24..28], &[0, 0, 0, 1]); // chunk_count 1
        assert_eq!(&idx[28..60], &[0xAAu8; 32]);
    }

    #[test]
    fn rejects_bad_magic_and_short() {
        assert!(!is_file_index(b"nope"));
        assert!(parse_file_index(b"short").is_err());
        let mut idx = build_file_index(1, 2, &[[0u8; 32]]);
        idx[0] = b'X';
        assert!(parse_file_index(&idx).is_err());
    }
}
