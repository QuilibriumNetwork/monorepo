/// Protocol version major.minor.patch (mirror of Go `config.GetVersion`).
pub const VERSION: [u8; 3] = [0x02, 0x01, 0x00];

/// Patch number (mirror of Go `config.GetPatchNumber`).
pub const PATCH_NUMBER: u8 = 0x17;

/// Minimum compatible version.
pub const MINIMUM_VERSION: [u8; 3] = [0x02, 0x01, 0x00];

/// Minimum compatible patch number.
pub const MINIMUM_PATCH_NUMBER: u8 = 0x04;

/// Full protocol version string including patch — must stay in sync
/// with `VERSION` and `PATCH_NUMBER`.
pub const VERSION_STRING: &str = "2.1.0.23";

/// Format a 3-byte version array as `"major.minor.patch"`. A 4th byte
/// is treated as a release-candidate suffix: `"major.minor.patch-pN"`.
pub fn format_version(version: &[u8]) -> String {
    match version.len() {
        3 => format!("{}.{}.{}", version[0], version[1], version[2]),
        4 => format!("{}.{}.{}-p{}", version[0], version[1], version[2], version[3]),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_string_matches_constants() {
        let expected = format!("{}.{}", format_version(&VERSION), PATCH_NUMBER);
        assert_eq!(VERSION_STRING, expected);
    }
}
