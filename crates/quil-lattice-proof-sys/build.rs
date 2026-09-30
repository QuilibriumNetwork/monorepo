use std::env;

fn main() {
    println!("cargo:rerun-if-changed=vendor");
    println!("cargo:rerun-if-changed=adapter");
    if env::var_os("CARGO_FEATURE_NATIVE_BACKEND").is_none() {
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
    match arch.as_str() {
        "aarch64" => {
            build.flag("-march=armv8-a+crypto");
        }
        "x86_64" => {
            build.define("SIMDE_NO_NATIVE", None);
        }
        _ => panic!("unsupported native proof architecture"),
    }
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
        .file("adapter/fixture_bridge.c")
        .compile("quil_lattice_proof");
    println!("cargo:rustc-link-lib=m");
    println!("cargo:rustc-link-lib=pthread");
}
