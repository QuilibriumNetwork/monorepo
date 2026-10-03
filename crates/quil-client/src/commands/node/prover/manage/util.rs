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
    use super::{center_trunc, clamp_offset};

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
