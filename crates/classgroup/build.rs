use cc;
use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/vdf.cpp");

    let target = env::var("TARGET").expect("cargo should have set this");

    // On Linux use `rustc-link-lib` (not `rustc-link-arg`) so rustc places
    // the `-l` flags AFTER the rlibs on the link line. With
    // `-Wl,--as-needed` (default in this toolchain), pre-rlib `-l` flags get
    // dropped as "unused" because the references in `libclassgroup.rlib`
    // haven't been seen yet — leaving mpfr_*/fmpz_* symbols unresolved.
    //
    // Flint and GMP are both forced static on Linux:
    //   * `libflint-dev` in the apt base ships a `libflint.so` with an ABI
    //     that diverges from the source-built flint-3.0 under
    //     `/usr/local/lib/libflint.a` that vdf.cpp was written against
    //     (e.g. `_fmpz_clear_mpz` was renamed in newer FLINT).
    //   * FLINT's static archive references GMP-internal `__gmpn_*` symbols
    //     that aren't guaranteed to be exported by every host's libgmp.so,
    //     producing runtime `symbol lookup error: undefined symbol:
    //     __gmpn_modexact_1_odd` on downstream machines. Bundling the
    //     source-built static GMP (see gmp-builder stage in the Dockerfiles)
    //     makes the binary self-contained.
    //
    // Link order matters for static resolution: flint depends on gmp and
    // mpfr, so those must come AFTER `-lflint` on the link line.
    //
    // macOS Homebrew provides dynamic libs only. Use `rustc-link-lib`
    // rather than `rustc-link-arg` so the `-l` flags propagate to
    // downstream test binaries that link `classgroup.rlib` — `link-arg`
    // only applies to the emitting crate's own binaries.
    if target == "aarch64-apple-darwin" {
        println!("cargo:rustc-link-lib=gmp");
        println!("cargo:rustc-link-lib=flint");
        println!("cargo:rustc-link-lib=mpfr");
    } else {
        println!("cargo:rustc-link-lib=static=flint");
        println!("cargo:rustc-link-lib=mpfr");
        println!("cargo:rustc-link-lib=static=gmp");
    }

    if target == "aarch64-apple-darwin" {
        println!("cargo:rustc-link-search=/opt/homebrew/Cellar/gmp/6.3.0/lib");
        println!("cargo:rustc-link-search=/opt/homebrew/Cellar/flint/3.4.0/lib");
        println!("cargo:rustc-link-search=/opt/homebrew/Cellar/mpfr/4.2.2/lib");
    } else if target == "aarch64-unknown-linux-gnu" {
        println!("cargo:rustc-link-search=/usr/local/lib");
        println!("cargo:rustc-link-search=/usr/lib/aarch64-linux-gnu/");
    } else if target == "x86_64-unknown-linux-gnu" {
        println!("cargo:rustc-link-search=/usr/local/lib");
        println!("cargo:rustc-link-search=/usr/lib/");
    } else {
        panic!("unsupported target {target}");
    }
    if target == "aarch64-apple-darwin" {
      cc::Build::new()
        .cpp(true)
        .file("src/vdf.cpp")
        .flag("-I/opt/homebrew/Cellar/gmp/6.3.0/include")
        .flag("-I/opt/homebrew/Cellar/flint/3.4.0/include")
        .flag("-I/opt/homebrew/Cellar/mpfr/4.2.2/include")
        .flag("-L/opt/homebrew/Cellar/gmp/6.3.0/lib")
        .flag("-L/opt/homebrew/Cellar/flint/3.4.0/lib")
        .flag("-L/opt/homebrew/Cellar/mpfr/4.2.2/lib")
        .flag("-lgmp")
        .flag("-lflint")
        .flag("-lmpfr")
        .compile("vdf");
    } else if target == "aarch64-unknown-linux-gnu" {
      cc::Build::new()
        .cpp(true)
        .file("src/vdf.cpp")
        .static_flag(true)
        .flag("-lflint")
        .flag("-lmpfr")
        .compile("vdf");
    } else if target == "x86_64-unknown-linux-gnu" {
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