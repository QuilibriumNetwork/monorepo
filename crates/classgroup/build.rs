use cc;
use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/vdf.cpp");

    println!("cargo:rustc-link-lib=gmp");
    println!("cargo:rustc-link-lib=flint");
    println!("cargo:rustc-link-lib=mpfr");

    let target = env::var("TARGET").expect("cargo should have set this");
    if target == "aarch64-apple-darwin" {
        // Use /opt/homebrew/opt/ symlinks (version-independent)
        let gmp_prefix = env::var("GMP_PREFIX")
            .unwrap_or_else(|_| "/opt/homebrew/opt/gmp".into());
        let flint_prefix = env::var("FLINT_PREFIX")
            .unwrap_or_else(|_| "/opt/homebrew/opt/flint".into());
        let mpfr_prefix = env::var("MPFR_PREFIX")
            .unwrap_or_else(|_| "/opt/homebrew/opt/mpfr".into());

        println!("cargo:rustc-link-search={}/lib", gmp_prefix);
        println!("cargo:rustc-link-search={}/lib", flint_prefix);
        println!("cargo:rustc-link-search={}/lib", mpfr_prefix);

        cc::Build::new()
            .cpp(true)
            .file("src/vdf.cpp")
            .flag(&format!("-I{}/include", gmp_prefix))
            .flag(&format!("-I{}/include", flint_prefix))
            .flag(&format!("-I{}/include", mpfr_prefix))
            .flag(&format!("-L{}/lib", gmp_prefix))
            .flag(&format!("-L{}/lib", flint_prefix))
            .flag(&format!("-L{}/lib", mpfr_prefix))
            .flag("-lgmp")
            .flag("-lflint")
            .flag("-lmpfr")
            .compile("vdf");
    } else if target == "aarch64-unknown-linux-gnu" {
        println!("cargo:rustc-link-search=/usr/lib/aarch64-linux-gnu/");
        cc::Build::new()
            .cpp(true)
            .file("src/vdf.cpp")
            .static_flag(true)
            .flag("-lflint")
            .flag("-lmpfr")
            .compile("vdf");
    } else if target == "x86_64-unknown-linux-gnu" {
        println!("cargo:rustc-link-search=/usr/lib/");
        cc::Build::new()
            .cpp(true)
            .file("src/vdf.cpp")
            .static_flag(true)
            .flag("-lflint")
            .flag("-lmpfr")
            .compile("vdf");
    } else {
        panic!("unsupported target {target}");
    }
}
