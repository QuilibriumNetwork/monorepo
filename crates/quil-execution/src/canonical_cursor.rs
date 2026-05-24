//! Shared big-endian cursor helpers for canonical-bytes
//! serialization/deserialization.
//!
//! Every canonical-bytes module (global_intrinsic, token_intrinsic,
//! hypergraph_intrinsic, compute_intrinsic, message_envelope,
//! consensus_wire) needs the same put/read primitives. This module
//! provides a single canonical copy.

use quil_types::error::{QuilError, Result};

/// Write a big-endian u32.
pub fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Write a big-endian u64.
pub fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Write a length-prefixed byte slice (u32 BE length + data).
pub fn put_lp(out: &mut Vec<u8>, data: &[u8]) {
    put_u32(out, data.len() as u32);
    out.extend_from_slice(data);
}

/// Read a big-endian u32 from `buf` at `*cursor`, advancing the cursor.
pub fn read_u32(buf: &[u8], cursor: &mut usize) -> Result<u32> {
    if *cursor + 4 > buf.len() {
        return Err(QuilError::InvalidArgument(
            "canonical: EOF reading u32".into(),
        ));
    }
    let mut b = [0u8; 4];
    b.copy_from_slice(&buf[*cursor..*cursor + 4]);
    *cursor += 4;
    Ok(u32::from_be_bytes(b))
}

/// Read a big-endian u64 from `buf` at `*cursor`, advancing the cursor.
pub fn read_u64(buf: &[u8], cursor: &mut usize) -> Result<u64> {
    if *cursor + 8 > buf.len() {
        return Err(QuilError::InvalidArgument(
            "canonical: EOF reading u64".into(),
        ));
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[*cursor..*cursor + 8]);
    *cursor += 8;
    Ok(u64::from_be_bytes(b))
}

/// Read exactly `len` bytes from `buf` at `*cursor`, advancing the cursor.
pub fn read_bytes(buf: &[u8], cursor: &mut usize, len: usize) -> Result<Vec<u8>> {
    if *cursor + len > buf.len() {
        return Err(QuilError::InvalidArgument(
            "canonical: EOF reading bytes".into(),
        ));
    }
    let out = buf[*cursor..*cursor + len].to_vec();
    *cursor += len;
    Ok(out)
}

/// Read a length-prefixed byte slice (u32 BE length + data).
pub fn read_lp(buf: &[u8], cursor: &mut usize) -> Result<Vec<u8>> {
    let len = read_u32(buf, cursor)? as usize;
    read_bytes(buf, cursor, len)
}

/// Read an array of length-prefixed byte slices.
///
/// The element count is read as a u32 from the wire, which is then
/// used as `Vec::with_capacity(n)`. A malicious sender specifying
/// `n = 0xFFFFFFFF` would otherwise trigger a multi-gigabyte
/// allocation before the per-element bounds check fires. Cap the
/// pre-allocation against `(buf.len() - cursor) / MIN_ENTRY_BYTES`:
/// each entry carries at least its own 4-byte length prefix, so the
/// remaining buffer can hold at most that many entries. We then use
/// `with_capacity(min(n, ceiling))` — the loop still iterates n times
/// and read_lp's bounds check will fail before we exceed the buffer.
pub fn read_array(buf: &[u8], cursor: &mut usize) -> Result<Vec<Vec<u8>>> {
    let n = read_u32(buf, cursor)? as usize;
    const MIN_ENTRY_BYTES: usize = 4; // one u32 length prefix per entry
    let max_possible = buf.len().saturating_sub(*cursor) / MIN_ENTRY_BYTES;
    let alloc_hint = n.min(max_possible);
    let mut out = Vec::with_capacity(alloc_hint);
    for _ in 0..n {
        out.push(read_lp(buf, cursor)?);
    }
    Ok(out)
}

/// Write an array of length-prefixed byte slices.
pub fn write_array(out: &mut Vec<u8>, items: &[Vec<u8>]) {
    put_u32(out, items.len() as u32);
    for item in items {
        put_lp(out, item);
    }
}

/// Write a big-endian i64.
pub fn put_i64(out: &mut Vec<u8>, v: i64) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Read a big-endian i64 from `buf` at `*cursor`, advancing the cursor.
pub fn read_i64(buf: &[u8], cursor: &mut usize) -> Result<i64> {
    if *cursor + 8 > buf.len() {
        return Err(QuilError::InvalidArgument(
            "canonical: EOF reading i64".into(),
        ));
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[*cursor..*cursor + 8]);
    *cursor += 8;
    Ok(i64::from_be_bytes(b))
}

/// Assert that the actual type prefix matches the expected one.
pub fn expect_tp(actual: u32, expected: u32, name: &str) -> Result<()> {
    if actual != expected {
        return Err(QuilError::InvalidArgument(format!(
            "{}: bad type 0x{:08x}",
            name, actual
        )));
    }
    Ok(())
}
