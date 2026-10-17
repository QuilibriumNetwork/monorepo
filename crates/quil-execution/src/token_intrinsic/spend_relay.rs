//! The spend relay an app-shard header carries (`FrameHeader.spends`): the
//! spend entries of the confidential operations the shard verified in its
//! recent frames.
//!
//! Entries are opaque here — encoded `global_commit::SpendEntry` bytes — so
//! frame producers and validators handle the relay identically in every build.
//!
//! ```text
//! frame entries: count(u16 BE) ‖ count × { len(u16 BE) ‖ entry }
//! relay:         frames × { source frame(u64 BE) ‖ frame entries }   (ascending, non-empty)
//! ```
//!
//! Re-carried for [`RELAY_WINDOW_FRAMES`]. A relay lost past the window is
//! safe: nothing happens until the global commit, so the operation simply never
//! committed and can be submitted again.
use quil_types::error::{QuilError, Result};

/// Frames every header re-carries.
pub const RELAY_WINDOW_FRAMES: u64 = 8;
/// Relayed operations one shard frame may carry; later ones are skipped before
/// execution, identically on every replica.
pub const MAX_ENTRIES_PER_FRAME: usize = 64;
/// Longest one encoded entry may be.
pub const MAX_ENTRY_BYTES: usize = 4096;

fn invalid(message: &str) -> QuilError {
    QuilError::InvalidArgument(format!("spend relay: {message}"))
}

/// Source frames header `frame_number` relays: `N-8 ..= N-1`, never frame 0.
pub fn relay_window(frame_number: u64) -> std::ops::RangeInclusive<u64> {
    frame_number.saturating_sub(RELAY_WINDOW_FRAMES).max(1)..=frame_number.saturating_sub(1)
}

pub fn encode_frame_entries(entries: &[Vec<u8>]) -> Result<Vec<u8>> {
    if entries.len() > MAX_ENTRIES_PER_FRAME {
        return Err(invalid("too many entries in a frame"));
    }
    let mut bytes = (entries.len() as u16).to_be_bytes().to_vec();
    for entry in entries {
        if entry.is_empty() || entry.len() > MAX_ENTRY_BYTES {
            return Err(invalid("entry size"));
        }
        bytes.extend_from_slice(&(entry.len() as u16).to_be_bytes());
        bytes.extend_from_slice(entry);
    }
    Ok(bytes)
}

fn take<'a>(bytes: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    if bytes.len() < n {
        return Err(invalid("truncated"));
    }
    let (head, tail) = bytes.split_at(n);
    *bytes = tail;
    Ok(head)
}

fn read_frame_entries(bytes: &mut &[u8]) -> Result<Vec<Vec<u8>>> {
    let count = usize::from(u16::from_be_bytes(take(bytes, 2)?.try_into().unwrap()));
    if count > MAX_ENTRIES_PER_FRAME {
        return Err(invalid("too many entries in a frame"));
    }
    (0..count)
        .map(|_| {
            let len = usize::from(u16::from_be_bytes(take(bytes, 2)?.try_into().unwrap()));
            if len == 0 || len > MAX_ENTRY_BYTES {
                return Err(invalid("entry size"));
            }
            Ok(take(bytes, len)?.to_vec())
        })
        .collect()
}

pub fn decode_frame_entries(mut bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    let entries = read_frame_entries(&mut bytes)?;
    if !bytes.is_empty() {
        return Err(invalid("trailing bytes"));
    }
    Ok(entries)
}

pub fn encode_relay(frames: &[(u64, Vec<Vec<u8>>)]) -> Result<Vec<u8>> {
    if frames.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err(invalid("frames out of order"));
    }
    let mut bytes = Vec::new();
    for (frame, entries) in frames {
        if entries.is_empty() {
            return Err(invalid("a relayed frame carries entries"));
        }
        bytes.extend_from_slice(&frame.to_be_bytes());
        bytes.extend_from_slice(&encode_frame_entries(entries)?);
    }
    Ok(bytes)
}

/// Decode a header's relay, requiring canonical form and that every source
/// frame lies in [`relay_window`] of the carrying header.
pub fn decode_relay(header_frame: u64, mut bytes: &[u8]) -> Result<Vec<(u64, Vec<Vec<u8>>)>> {
    let window = relay_window(header_frame);
    let mut frames: Vec<(u64, Vec<Vec<u8>>)> = Vec::new();
    while !bytes.is_empty() {
        let frame = u64::from_be_bytes(take(&mut bytes, 8)?.try_into().unwrap());
        if !window.contains(&frame) || frames.last().is_some_and(|(last, _)| *last >= frame) {
            return Err(invalid("frame outside the window or out of order"));
        }
        let entries = read_frame_entries(&mut bytes)?;
        if entries.is_empty() {
            return Err(invalid("a relayed frame carries entries"));
        }
        frames.push((frame, entries));
    }
    Ok(frames)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relays_are_canonical_and_windowed() {
        let frames = vec![(12u64, vec![vec![1u8; 10], vec![2; 3]]), (15, vec![vec![3; 7]])];
        let bytes = encode_relay(&frames).unwrap();
        assert_eq!(decode_relay(16, &bytes).unwrap(), frames);
        // Frame 12 is outside header 21's window (13..=20).
        assert!(decode_relay(21, &bytes).is_err());
        // Trailing, truncated, empty-frame and oversize forms are refused.
        assert!(decode_relay(16, &bytes[..bytes.len() - 1]).is_err());
        assert!(encode_relay(&[(12, vec![])]).is_err());
        assert!(encode_relay(&[(15, vec![vec![1]]), (12, vec![vec![1]])]).is_err());
        assert!(encode_frame_entries(&vec![vec![1u8]; MAX_ENTRIES_PER_FRAME + 1]).is_err());
        assert!(encode_frame_entries(&[vec![0u8; MAX_ENTRY_BYTES + 1]]).is_err());
        assert_eq!(decode_frame_entries(&encode_frame_entries(&[vec![9; 4]]).unwrap()).unwrap(), vec![vec![9; 4]]);
        assert!(decode_relay(1, &[]).unwrap().is_empty());
        assert_eq!(relay_window(1), 1..=0);
        assert_eq!(relay_window(20), 12..=19);
    }
}
