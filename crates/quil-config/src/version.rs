/// Protocol version major.minor.patch (mirror of Go `config.GetVersion`).
pub const VERSION: [u8; 3] = [0x02, 0x01, 0x00];

/// Patch number (mirror of Go `config.GetPatchNumber`).
pub const PATCH_NUMBER: u8 = 0x19;

/// Minimum compatible version.
pub const MINIMUM_VERSION: [u8; 3] = [0x02, 0x01, 0x00];

/// Minimum compatible patch number.
pub const MINIMUM_PATCH_NUMBER: u8 = 0x04;

/// Full protocol version string including patch — must stay in sync
/// with `VERSION` and `PATCH_NUMBER`.
pub const VERSION_STRING: &str = "2.1.0.25";

/// The repository's `subpatch` counter at build time, bumped with each fix
/// within a patch release; empty when the build had no `subpatch` file.
pub const SUBPATCH: &str = env!("QUIL_SUBPATCH");

/// [`SUBPATCH`] as a number, as a prover's epoch confirmation reports it;
/// 0 when the build had no `subpatch` file, and saturated at `u16::MAX`.
pub const SUBPATCH_NUMBER: u16 = subpatch_number(SUBPATCH);

const fn subpatch_number(subpatch: &str) -> u16 {
    let bytes = subpatch.as_bytes();
    let mut value: u32 = 0;
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() {
            return 0;
        }
        value = value * 10 + (bytes[i] - b'0') as u32;
        if value > u16::MAX as u32 {
            return u16::MAX;
        }
        i += 1;
    }
    value as u16
}

/// The version shown to operators: `VERSION_STRING` with the subpatch as
/// a fifth part, e.g. `2.1.0.25.87`, so builds within one patch release can
/// be told apart. Peers still exchange `VERSION_STRING`.
pub fn display_version() -> &'static str {
    static DISPLAY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DISPLAY.get_or_init(|| with_subpatch(VERSION_STRING, SUBPATCH))
}

fn with_subpatch(version: &str, subpatch: &str) -> String {
    if subpatch.is_empty() {
        version.to_string()
    } else {
        format!("{version}.{subpatch}")
    }
}

/// Format a 3-byte version array as `"major.minor.patch"`. A 4th byte
/// is treated as a release-candidate suffix: `"major.minor.patch-pN"`.
pub fn format_version(version: &[u8]) -> String {
    match version.len() {
        3 => format!("{}.{}.{}", version[0], version[1], version[2]),
        4 => format!(
            "{}.{}.{}-p{}",
            version[0], version[1], version[2], version[3]
        ),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_subpatch_is_the_repository_counter() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../subpatch");
        let counter = std::fs::read_to_string(path).expect("subpatch file");
        assert_eq!(SUBPATCH, counter.trim());
        assert!(!SUBPATCH.is_empty());
    }

    #[test]
    fn the_display_version_carries_the_subpatch() {
        assert_eq!(display_version(), format!("{VERSION_STRING}.{SUBPATCH}"));
        assert_eq!(with_subpatch("2.1.0.25", "87"), "2.1.0.25.87");
        assert_eq!(with_subpatch("2.1.0.25", ""), "2.1.0.25");
    }

    #[test]
    fn the_subpatch_number_is_the_subpatch() {
        assert_eq!(SUBPATCH_NUMBER.to_string(), SUBPATCH);
        assert_eq!(subpatch_number(""), 0);
        assert_eq!(subpatch_number("92"), 92);
        assert_eq!(subpatch_number("9x"), 0);
        assert_eq!(subpatch_number("65536"), u16::MAX);
    }

    #[test]
    fn version_string_matches_constants() {
        let expected = format!("{}.{}", format_version(&VERSION), PATCH_NUMBER);
        assert_eq!(VERSION_STRING, expected);
    }
}
