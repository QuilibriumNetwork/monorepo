//! Small shared text/scroll helpers. Port of `centerTrunc`, `truncHex`,
//! `clampOffset` from `manage_model.go`.

/// `centerTrunc` — shorten `h` to `max_width` by eliding the middle with "...".
pub fn center_trunc(h: &str, max_width: usize) -> String {
    // Byte indexing matches Go's []byte slicing; hex strings are ASCII.
    if max_width <= 3 {
        if h.len() > max_width {
            return h[..max_width].to_string();
        }
        return h.to_string();
    }
    if h.len() <= max_width {
        return h.to_string();
    }
    let prefix = (max_width - 3) / 2;
    let suffix = max_width - 3 - prefix;
    format!("{}...{}", &h[..prefix], &h[h.len() - suffix..])
}

/// Keep bit-path suffixes aligned, using spare width for the shared address's
/// trailing characters. All rows use the same address budget and full-width
/// transition, determined by the panel's longest suffix.
pub fn filter_label(h: &str, max_width: usize, longest_suffix: usize) -> String {
    if h.len() <= 64 || max_width >= 64 + longest_suffix {
        return center_trunc(h, max_width);
    }
    let suffix = &h[64..];
    if longest_suffix + 3 <= max_width {
        let address_chars = (max_width - 3 - longest_suffix).min(64);
        format!("...{}{suffix}", &h[64 - address_chars..64])
    } else {
        center_trunc(h, max_width)
    }
}

/// Abbreviate an address only when it is shared by every displayed row.
pub fn shared_filter_address<'a>(mut hexes: impl Iterator<Item = &'a str>) -> bool {
    let Some(first) = hexes.next() else { return false; };
    let Some(address) = first.get(..64) else { return false; };
    hexes.all(|h| h.get(..64) == Some(address))
}

/// `truncHex` — shorten a hex string for short status messages.
pub fn trunc_hex(h: &str) -> String {
    center_trunc(h, 20)
}

/// `filtersLabel` — display label for one or more filters.
pub fn filters_label(filters: &[Vec<u8>]) -> String {
    if filters.len() == 1 {
        trunc_hex(&hex::encode(&filters[0]))
    } else {
        format!("{} filters", filters.len())
    }
}

/// `clampOffset` — adjust the scroll offset so the cursor stays visible.
pub fn clamp_offset(mut offset: usize, cursor: usize, visible_rows: usize, total: usize) -> usize {
    if cursor < offset {
        offset = cursor;
    }
    if cursor >= offset + visible_rows {
        offset = cursor + 1 - visible_rows;
    }
    if total >= visible_rows && offset > total - visible_rows {
        offset = total - visible_rows;
    }
    if total < visible_rows {
        offset = 0;
    }
    offset
}

#[cfg(test)]
mod tests {
    use super::{center_trunc, filter_label, shared_filter_address, clamp_offset};

    #[test]
    fn compressed_filters_keep_complete_suffixes_at_the_same_start() {
        let prefix = "ab".repeat(32);
        assert_eq!(filter_label(&format!("{prefix}000123"), 18, 8), "...bababab000123");
        assert_eq!(filter_label(&format!("{prefix}00012380"), 18, 8), "...bababab00012380");
        let full = format!("{prefix}000123");
        let sibling = format!("{prefix}00012380");
        for width in 11..72 {
            let short = filter_label(&full, width, 8);
            let long = filter_label(&sibling, width, 8);
            assert_eq!(long.len(), width);
            assert_eq!(short.len(), width - 2);
            assert_eq!(short.find("000123"), long.find("00012380"));
            assert_eq!(&short[..short.len() - 6], &long[..long.len() - 8]);
        }
        assert!(filter_label(&full, 70, 8).starts_with("..."));
        let different_address = format!("{}000123", "cd".repeat(32));
        assert!(shared_filter_address([full.as_str(), sibling.as_str()].into_iter()));
        assert!(!shared_filter_address([full.as_str(), different_address.as_str()].into_iter()));
        assert_eq!(filter_label(&full, 72, 8), full);
        assert!(filter_label(&full, 5, 8).len() <= 5);
    }

    #[test]
    fn center_trunc_elides_middle() {
        assert_eq!(center_trunc("abcdef", 10), "abcdef"); // fits
        assert_eq!(center_trunc("abcdefghij", 7), "ab...ij"); // 2 + 3 + 2
        // max_width <= 3 hard-truncates from the front.
        assert_eq!(center_trunc("abcdef", 3), "abc");
    }

    #[test]
    fn clamp_offset_keeps_cursor_visible() {
        // Cursor below window scrolls down.
        assert_eq!(clamp_offset(0, 9, 5, 20), 5);
        // Cursor above window scrolls up.
        assert_eq!(clamp_offset(5, 2, 5, 20), 2);
        // Fewer rows than the window pins offset to 0.
        assert_eq!(clamp_offset(3, 0, 5, 2), 0);
        // Offset clamped so the last page is full.
        assert_eq!(clamp_offset(100, 19, 5, 20), 15);
    }
}
