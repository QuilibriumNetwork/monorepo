//! CPU features the native backend's C was compiled to use, checked against
//! the running CPU. A native x86 build compiled for features this CPU lacks
//! (`QUIL_LATTICE_X86_NATIVE=avx512`, or CFLAGS such as `-march=...`) would
//! otherwise die with SIGILL in its first proof.

/// How build.rs compiled the C backend: `portable` (SIMDe's portable path),
/// `native` (`QUIL_LATTICE_X86_NATIVE=1`), `avx512`, `aarch64`, or `none`
/// without the `native-backend` feature.
pub const BUILD_MODE: &str = env!("QUIL_LATTICE_BUILD_MODE");

/// The x86 features beyond baseline x86-64 that the C compiler targeted, as
/// `is_x86_feature_detected!` names. Empty elsewhere and without the backend.
pub fn required_cpu_features() -> Vec<&'static str> {
    parse(target_features())
}

/// The required features this CPU lacks: empty when the build runs here.
pub fn required_cpu_features_missing() -> Vec<&'static str> {
    missing(&required_cpu_features(), detected)
}

/// The startup refusal for `program`, or `None` when this CPU can run it.
pub fn unsupported_cpu_message(program: &str) -> Option<String> {
    let missing = required_cpu_features_missing();
    (!missing.is_empty()).then(|| {
        format!(
            "{program} cannot run on this CPU: its lattice backend was compiled for \
             CPU features this host lacks and would crash (SIGILL); run a build \
             made for this CPU, such as the standard release; missing={} build_mode={BUILD_MODE}",
            missing.join(",")
        )
    })
}

fn parse(list: &'static str) -> Vec<&'static str> {
    list.split(',').filter(|name| !name.is_empty()).collect()
}

fn missing(required: &[&'static str], has: impl Fn(&str) -> bool) -> Vec<&'static str> {
    required.iter().copied().filter(|name| !has(name)).collect()
}

#[cfg(all(feature = "native-backend", target_arch = "x86_64"))]
fn target_features() -> &'static str {
    // SAFETY: the C function returns a static NUL-terminated ASCII literal.
    unsafe { std::ffi::CStr::from_ptr(crate::ffi::quil_lattice_target_x86_features()) }
        .to_str()
        .expect("the feature list is ASCII")
}

#[cfg(not(all(feature = "native-backend", target_arch = "x86_64")))]
fn target_features() -> &'static str {
    ""
}

macro_rules! x86_features {
    ($($name:tt),* $(,)?) => {
        /// Every name adapter/target_features.c can list.
        #[cfg(test)]
        const KNOWN: &[&str] = &[$($name),*];

        #[cfg(target_arch = "x86_64")]
        fn detected(name: &str) -> bool {
            match name {
                $($name => std::arch::is_x86_feature_detected!($name),)*
                // A name this table lacks cannot be checked: count it missing.
                _ => false,
            }
        }
    };
}

x86_features!(
    "sse3",
    "ssse3",
    "sse4.1",
    "sse4.2",
    "sse4a",
    "popcnt",
    "lzcnt",
    "bmi1",
    "bmi2",
    "tbm",
    "movbe",
    "adx",
    "aes",
    "pclmulqdq",
    "avx",
    "f16c",
    "fma",
    "avx2",
    "avxvnni",
    "avx512f",
    "avx512cd",
    "avx512bw",
    "avx512dq",
    "avx512vl",
    "avx512ifma",
    "avx512vbmi",
    "avx512vbmi2",
    "avx512vnni",
    "avx512bitalg",
    "avx512vpopcntdq",
    "avx512bf16",
    "avx512fp16",
    "avx512vp2intersect",
    "gfni",
    "vaes",
    "vpclmulqdq",
);

/// Features compilers emit only for explicit intrinsics or inline asm, which
/// the backend never uses: adapter/target_features.c leaves them out even when
/// the target has them, so a CPU (or VM) hiding one still runs the build.
#[cfg(test)]
const INTRINSIC_ONLY: &[&str] = &["rdrand", "rdseed", "sha"];

/// Off x86-64 the C list is empty, so nothing is ever looked up.
#[cfg(not(target_arch = "x86_64"))]
fn detected(_: &str) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_lists_the_required_features_the_cpu_lacks_in_order() {
        let required = parse("avx2,avx512f,,avx512bw,");
        assert_eq!(required, ["avx2", "avx512f", "avx512bw"]);
        assert_eq!(
            missing(&required, |name| name == "avx2"),
            ["avx512f", "avx512bw"]
        );
        assert!(missing(&required, |_| true).is_empty());
        assert_eq!(missing(&required, |_| false), required);
        assert!(parse("").is_empty());
    }

    #[test]
    fn every_feature_the_c_list_can_name_is_checked() {
        let names = c_list_names();
        assert_eq!(names.len(), KNOWN.len(), "{names:?}");
        for name in names {
            assert!(KNOWN.contains(&name), "{name} has no CPU check");
        }
    }

    /// The names adapter/target_features.c can list: all of them are required
    /// for a target that defines every macro it tests.
    fn c_list_names() -> Vec<&'static str> {
        include_str!("../adapter/target_features.c")
            .lines()
            .filter_map(|line| line.trim().strip_prefix('"')?.strip_suffix(",\""))
            .collect()
    }

    #[test]
    fn a_cpu_lacking_only_intrinsic_only_features_runs_the_widest_build() {
        let required = c_list_names();
        assert!(required.contains(&"avx512f"), "{required:?}");
        // A target with every listed feature plus RDRAND, RDSEED and SHA (such
        // as -march=znver4) on an AVX-512 CPU reporting none of those three.
        let has = |name: &str| !INTRINSIC_ONLY.contains(&name);
        assert_eq!(missing(&required, has), Vec::<&str>::new());
        let has = |name: &str| name != "avx512f";
        assert_eq!(missing(&required, has), ["avx512f"]);
    }

    #[test]
    fn the_c_list_names_no_intrinsic_only_feature() {
        for name in c_list_names() {
            assert!(!INTRINSIC_ONLY.contains(&name), "{name} is intrinsic-only");
        }
    }

    /// Leaving INTRINSIC_ONLY out of the required list is safe only while no C
    /// source build.rs compiles or includes uses those instructions.
    #[test]
    fn the_backend_uses_no_intrinsic_only_instruction() {
        const NEEDLES: &[&str] = &[
            "rdrand",
            "rdrnd",
            "rdseed",
            "_mm_sha1",
            "_mm_sha256",
            "ia32_sha1",
            "ia32_sha256",
            "sha1rnds",
            "sha1nexte",
            "sha1msg",
            "sha256rnds",
            "sha256msg",
        ];
        fn scan(dir: &std::path::Path, files: &mut usize, hits: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    scan(&path, files, hits);
                    continue;
                }
                let source = matches!(
                    path.extension().and_then(|ext| ext.to_str()),
                    Some("c" | "h" | "S" | "s" | "inc")
                );
                if !source || path.ends_with("adapter/target_features.c") {
                    continue;
                }
                *files += 1;
                let text = String::from_utf8_lossy(&std::fs::read(&path).unwrap()).to_lowercase();
                for needle in NEEDLES {
                    if text.contains(needle) {
                        hits.push(format!("{}: {needle}", path.display()));
                    }
                }
            }
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let (mut files, mut hits) = (0, Vec::new());
        for dir in ["adapter", "vendor"] {
            scan(&root.join(dir), &mut files, &mut hits);
        }
        assert!(files > 100, "scanned only {files} files");
        assert!(
            hits.is_empty(),
            "intrinsic-only instructions in the backend: {hits:?}"
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn each_name_checks_its_own_feature() {
        use std::arch::is_x86_feature_detected;
        assert_eq!(detected("sse4.2"), is_x86_feature_detected!("sse4.2"));
        assert_eq!(detected("avx2"), is_x86_feature_detected!("avx2"));
        assert_eq!(detected("avx512f"), is_x86_feature_detected!("avx512f"));
        assert_eq!(detected("avx512bw"), is_x86_feature_detected!("avx512bw"));
        assert_eq!(detected("vaes"), is_x86_feature_detected!("vaes"));
        assert!(!detected("sse2,"), "an unknown name counts as missing");
    }

    #[test]
    fn the_portable_build_requires_no_cpu_features() {
        if BUILD_MODE != "portable" {
            return;
        }
        assert!(
            required_cpu_features().is_empty(),
            "{:?}",
            required_cpu_features()
        );
        assert_eq!(unsupported_cpu_message("test"), None);
    }

    #[test]
    fn the_refusal_names_the_missing_features_and_the_build_mode() {
        let required = required_cpu_features();
        let missing = required_cpu_features_missing();
        eprintln!("build_mode={BUILD_MODE} required={required:?} missing={missing:?}");
        assert!(missing.iter().all(|name| required.contains(name)));
        match unsupported_cpu_message("test") {
            None => assert!(missing.is_empty()),
            Some(message) => {
                assert!(message.contains(&format!("missing={}", missing.join(","))));
                assert!(message.ends_with(&format!("build_mode={BUILD_MODE}")));
            }
        }
    }
}
