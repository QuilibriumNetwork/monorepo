use std::env;

fn main() {
    println!("cargo:rerun-if-changed=vendor");
    println!("cargo:rerun-if-changed=adapter");
    println!("cargo:rerun-if-env-changed=QUIL_LATTICE_X86_NATIVE");
    if env::var_os("CARGO_FEATURE_NATIVE_BACKEND").is_none() {
        println!("cargo:rustc-env=QUIL_LATTICE_BUILD_MODE=none");
        return;
    }
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    assert!(
        matches!(os.as_str(), "macos" | "linux"),
        "unsupported native proof OS"
    );
    let mut build = cc::Build::new();
    build
        .include("adapter/shim")
        .include("adapter")
        .include("vendor/labrados")
        .include("vendor/simde")
        .flag("-std=gnu2x")
        .flag("-fwrapv")
        .flag("-ffp-contract=off")
        .flag("-UNDEBUG")
        .flag_if_supported("-Wno-pass-failed")
        .opt_level(3)
        .warnings(false)
        .debug(true);
    if env::var_os("CARGO_FEATURE_BENCH_KNOBS").is_some() {
        build.define("QUIL_BENCH_KNOBS", None);
    }
    // The tested recipe uses clang and keeps assertions enabled. Callers can
    // select a cross compiler using cc's standard target-specific environment.
    if env::var_os("CC").is_none() && env::var("HOST").ok() == env::var("TARGET").ok() {
        build.compiler("clang");
    }
    let mode = match arch.as_str() {
        "aarch64" => {
            build.flag("-march=armv8-a+crypto");
            "aarch64"
        }
        "x86_64" => {
            // QUIL_LATTICE_X86_NATIVE selects how the reference AVX-512 code
            // runs. Unset or "0": SIMDe's portable path. "1": natively on the
            // instructions the C compiler targets (CFLAGS; plain x86-64 is
            // SSE2), SIMDe lowering what the target lacks. "avx512": the same,
            // and the build fails unless that target has AVX-512 F/BW/DQ/VL.
            match env::var("QUIL_LATTICE_X86_NATIVE").as_deref() {
                Err(_) | Ok("") | Ok("0") => {
                    build.define("SIMDE_NO_NATIVE", None);
                    "portable"
                }
                Ok("1") => "native",
                Ok("avx512") => {
                    build.define("QUIL_REQUIRE_X86_AVX512", None);
                    "avx512"
                }
                Ok(other) => {
                    panic!("QUIL_LATTICE_X86_NATIVE must be 0, 1 or avx512, got {other:?}")
                }
            }
        }
        _ => panic!("unsupported native proof architecture"),
    };
    // src/cpu.rs reports it beside the CPU features the C targets
    // (adapter/target_features.c).
    println!("cargo:rustc-env=QUIL_LATTICE_BUILD_MODE={mode}");
    for name in [
        "pack",
        "labrador_core",
        "labradoodle",
        "labrador",
        "labrador_tail",
        "timing",
        "proofsystem",
        "constraints",
        "comkey",
        "data",
        "polx",
        "poly",
        "polz",
        "aesctr",
        "randombytes",
        "fips202",
        "ntt",
        "jlproj",
        "gaussian",
        "rejection",
        "lnp",
        "dachshund",
        "labrados_python",
    ] {
        build.file(format!("vendor/labrados/{name}.c"));
    }
    build
        .file("adapter/target_features.c")
        .file("adapter/fixture_bridge.c")
        .compile("quil_lattice_proof");
    println!("cargo:rustc-link-lib=m");
    println!("cargo:rustc-link-lib=pthread");
}
