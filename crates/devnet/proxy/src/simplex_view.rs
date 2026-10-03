//! Decode the simplex view out of a commonware-consensus vote or certificate.
//!
//! Global consensus rides four `:8340` channels. Only the block channel carries
//! a self-describing `(frame_number, rank)`; the vote and certificate channels
//! carry simplex's own types, which reference a *view*. Views are what the
//! devnet partition schedule keys on, because a view advances on every round —
//! including the nullified rounds a partition induces, which produce no block
//! and so leave the block channel silent.
//!
//! Only the fixed-size prefix is parsed. Both `Vote` and `Certificate` encode as
//! a one-byte discriminant followed by the `Round` (`epoch`, then `view`), so
//! one decoder covers both:
//!
//! ```text
//! tag:   u8       0 = Notarize(-ation), 1 = Nullify/Nullification, 2 = Finalize(-ation)
//! epoch: u64      LEB128 varint
//! view:  u64      LEB128 varint
//! ...             attestation / certificate / proposal remainder — never parsed
//! ```
//!
//! The remainder is deliberately left alone: it is generic over the signature
//! scheme (Falcon-512, 666 bytes per signature here) and decoding it would mean
//! taking a dependency on `commonware-consensus` and `quil-cw-consensus` for no
//! signal the harness needs.

/// CW channel ids, as returned by [`quil_engine::bitmasks::global_cw_channel_of`].
pub const CW_VOTE_CHANNEL: u64 = 0;
pub const CW_CERT_CHANNEL: u64 = 1;
pub const CW_BLOCK_CHANNEL: u64 = 3;

/// LEB128 bit masks, matching `commonware-codec`'s `UInt` encoding.
const DATA_BITS_MASK: u8 = 0x7F;
const CONTINUATION_BIT_MASK: u8 = 0x80;

/// Most bytes a `u64` LEB128 varint can occupy (⌈64/7⌉).
const MAX_VARINT_LEN: usize = 10;

/// Which simplex message the payload is. The vote and certificate channels share
/// the same discriminants (`Nullify` on the vote channel, `Nullification` on the
/// certificate channel, and so on), so this names the shape rather than the
/// exact type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoteKind {
    Notarize,
    Nullify,
    Finalize,
}

/// The round a simplex vote or certificate refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimplexView {
    pub epoch: u64,
    pub view: u64,
    pub kind: VoteKind,
}

/// Read one LEB128 varint, returning its value and the bytes consumed.
///
/// Mirrors `commonware-codec`'s decoder rather than being permissive like
/// protobuf: a non-canonical encoding (a continuation byte followed by an
/// all-zero group, which contributes nothing) and an overlong encoding that
/// would overflow a `u64` are both rejected. Being strict here means a
/// malformed payload reads as "not a view" instead of silently decoding to a
/// wrong view number that would fire the wrong partition entry.
fn read_uvarint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    for (i, &byte) in buf.iter().take(MAX_VARINT_LEN).enumerate() {
        if i > 0 && byte == 0 {
            return None;
        }
        let shift = 7 * i as u32;
        let bits = u64::from(byte & DATA_BITS_MASK);
        // Reject a group whose bits would fall off the top of the u64.
        if bits > (u64::MAX >> shift) {
            return None;
        }
        value |= bits << shift;
        if byte & CONTINUATION_BIT_MASK == 0 {
            return Some((value, i + 1));
        }
    }
    // Ran out of input, or the value is longer than any u64 encoding.
    None
}

/// Decode the `(epoch, view, kind)` prefix of a simplex vote or certificate.
///
/// Returns `None` for any other channel — notably the resolver channel, which
/// carries `Backfiller` requests in a different shape — and for a payload whose
/// prefix does not parse.
pub fn decode_view(channel: u64, data: &[u8]) -> Option<SimplexView> {
    if channel != CW_VOTE_CHANNEL && channel != CW_CERT_CHANNEL {
        return None;
    }
    let (&tag, rest) = data.split_first()?;
    let kind = match tag {
        0 => VoteKind::Notarize,
        1 => VoteKind::Nullify,
        2 => VoteKind::Finalize,
        _ => return None,
    };
    let (epoch, consumed) = read_uvarint(rest)?;
    let (view, _) = read_uvarint(rest.get(consumed..)?)?;
    Some(SimplexView { epoch, view, kind })
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::varint::UInt;
    use commonware_codec::Encode;

    /// Encode with the production codec so the hand-rolled reader is checked
    /// against the encoder it has to interoperate with, not against itself.
    fn varint(v: u64) -> Vec<u8> {
        UInt(v).encode().to_vec()
    }

    /// `tag || epoch || view`, then filler standing in for the attestation.
    fn payload(tag: u8, epoch: u64, view: u64) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend_from_slice(&varint(epoch));
        out.extend_from_slice(&varint(view));
        out.extend_from_slice(&[0xAB; 666]);
        out
    }

    #[test]
    fn reads_varints_the_codec_wrote() {
        for v in [0, 1, 42, 127, 128, 300, 16_383, 16_384, u64::MAX] {
            let encoded = varint(v);
            assert_eq!(
                read_uvarint(&encoded),
                Some((v, encoded.len())),
                "round-trip failed for {v}"
            );
        }
    }

    #[test]
    fn varint_stops_at_its_own_end() {
        let mut buf = varint(300);
        let len = buf.len();
        buf.extend_from_slice(&[0xFF, 0xFF]);
        assert_eq!(read_uvarint(&buf), Some((300, len)));
    }

    #[test]
    fn rejects_non_canonical_varint() {
        // 0x80 0x00 would decode to 0 in protobuf, but the codec forbids a
        // trailing all-zero group.
        assert_eq!(read_uvarint(&[0x80, 0x00]), None);
    }

    #[test]
    fn rejects_truncated_varint() {
        // Continuation bit set with nothing following.
        assert_eq!(read_uvarint(&[0x80]), None);
        assert_eq!(read_uvarint(&[]), None);
    }

    #[test]
    fn rejects_varint_overflowing_u64() {
        // Eleven continuation bytes: longer than any u64 encoding.
        assert_eq!(read_uvarint(&[0xFF; 11]), None);
        // Ten bytes, but the final group sets bits past bit 63.
        assert_eq!(
            read_uvarint(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F]),
            None
        );
    }

    #[test]
    fn decodes_every_kind_on_both_channels() {
        let cases = [
            (0u8, VoteKind::Notarize),
            (1, VoteKind::Nullify),
            (2, VoteKind::Finalize),
        ];
        for channel in [CW_VOTE_CHANNEL, CW_CERT_CHANNEL] {
            for (tag, kind) in cases {
                let got = decode_view(channel, &payload(tag, 0, 7)).expect("decode");
                assert_eq!(
                    got,
                    SimplexView {
                        epoch: 0,
                        view: 7,
                        kind
                    },
                    "channel {channel} tag {tag}"
                );
            }
        }
    }

    /// A nullified view is the case the whole change exists for: it advances the
    /// view while producing no block, so the block channel stays silent.
    #[test]
    fn decodes_multibyte_view() {
        let got = decode_view(CW_VOTE_CHANNEL, &payload(1, 0, 300)).expect("decode");
        assert_eq!(got.view, 300);
        assert_eq!(got.kind, VoteKind::Nullify);
    }

    #[test]
    fn reports_non_global_epoch_rather_than_hiding_it() {
        // Epoch filtering is the caller's job, so a foreign epoch decodes and is
        // rejected loudly upstream instead of vanishing here.
        let got = decode_view(CW_VOTE_CHANNEL, &payload(0, 4, 9)).expect("decode");
        assert_eq!((got.epoch, got.view), (4, 9));
    }

    #[test]
    fn rejects_unknown_tag() {
        assert_eq!(decode_view(CW_VOTE_CHANNEL, &payload(3, 0, 7)), None);
        assert_eq!(decode_view(CW_VOTE_CHANNEL, &payload(0xFF, 0, 7)), None);
    }

    #[test]
    fn rejects_other_channels() {
        // Resolver (2) carries Backfiller requests; block (3) carries frame
        // bytes. Neither has this prefix.
        for channel in [2, CW_BLOCK_CHANNEL, 9] {
            assert_eq!(decode_view(channel, &payload(0, 0, 7)), None);
        }
    }

    #[test]
    fn rejects_short_payloads() {
        assert_eq!(decode_view(CW_VOTE_CHANNEL, &[]), None);
        assert_eq!(decode_view(CW_VOTE_CHANNEL, &[0x00]), None);
        // Tag and epoch, but the view varint is missing.
        assert_eq!(decode_view(CW_VOTE_CHANNEL, &[0x00, 0x00]), None);
    }
}
