use cc;
use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/vdf.cpp");

    let target = env::var("TARGET").expect("cargo should have set this");

    // Emit link directives. On Linux we prefer static when a `.a` is
    // available (Dockerfile.sourceavx512 builds FLINT from source with
    // `--disable-shared`, producing only `libflint.a` / `libmpfr.a` in
    // `/usr/local/lib`). The apt-based `Dockerfile.source` path only
    // ships the `.so` form, so fall back to the default `dylib` there.
    // Without the explicit `static=` tag, rustc defaults to `dylib`
    // and will silently pick up a `.so` if one exists anywhere on the
    // search path — baking in a runtime dep the stripped image can't
    // satisfy.
    //
    // macOS (Homebrew) dev builds always link dynamically.
    fn has_static(name: &str) -> bool {
        const SEARCH_DIRS: &[&str] = &[
            "/usr/local/lib",
            "/usr/lib",
            "/usr/lib/x86_64-linux-gnu",
            "/usr/lib/aarch64-linux-gnu",
        ];
        SEARCH_DIRS.iter().any(|d| {
            std::path::Path::new(&format!("{}/lib{}.a", d, name)).exists()
        })
    }

    if target == "aarch64-apple-darwin" {
        println!("cargo:rustc-link-lib=gmp");
        println!("cargo:rustc-link-lib=flint");
        println!("cargo:rustc-link-lib=mpfr");
    } else {
        // gmp is provided by the distro package — leave dynamic.
        println!("cargo:rustc-link-lib=gmp");
        println!(
            "cargo:rustc-link-lib={}flint",
            if has_static("flint") { "static=" } else { "" }
        );
        println!(
            "cargo:rustc-link-lib={}mpfr",
            if has_static("mpfr") { "static=" } else { "" }
        );
    }

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
        println!("cargo:rustc-link-search=/usr/local/lib");
        println!("cargo:rustc-link-search=/usr/lib/aarch64-linux-gnu/");
        cc::Build::new()
            .cpp(true)
            .file("src/vdf.cpp")
            .static_flag(true)
            .flag("-lflint")
            .flag("-lmpfr")
            .compile("vdf");
    } else if target == "x86_64-unknown-linux-gnu" {
        println!("cargo:rustc-link-search=/usr/local/lib");
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
