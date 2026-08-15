use cc;
use std::env;
use std::path::Path;
use std::process::Command;

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
    // Link-library declarations are split per target. Linux and
    // macOS resolve GMP/FLINT/MPFR through entirely different supply
    // chains (apt + dockerized source builds on Linux; Homebrew on
    // macOS), and the mix of static vs dynamic that's correct on one
    // is broken on the other.
    //
    // Linux (both arches): `libflint.a` and `libgmp.a` are static —
    // FLINT references GMP-internal `__gmpn_*` symbols that aren't
    // part of GMP's public ABI, so linking the same source-built
    // static GMP that FLINT was built against avoids runtime
    // `undefined symbol: __gmpn_modexact_1_odd`. `mpfr` stays
    // DYNAMIC on Linux: every working Linux build prior to the
    // macOS-self-contained-binary work was `static=flint`,
    // `mpfr` (dynamic), `static=gmp`. Forcing `static=mpfr` here
    // pulled GMP's public exports in twice (once through
    // `libmpfr.a`'s internal copy, once through the explicit
    // `static=gmp`) and produced `__gmpz_export redeclared` link
    // failures on Linux. (The macOS path is fine with all three
    // static because Homebrew's `libmpfr.a` doesn't repackage GMP.)
    //
    // macOS: GMP and MPFR are unconditionally static (Homebrew ships
    // `.a` for both). FLINT is conditionally static — Homebrew's
    // flint formula ships only `libflint.dylib`, so a default `brew
    // install flint` can't satisfy `static=flint`. Users wanting a
    // self-contained binary set `FLINT_DIR=<path>` pointing at an
    // install root containing `lib/libflint.a` (or an in-tree source
    // build with `libflint.a` at the root). When `FLINT_DIR` is unset
    // the macOS link falls back to dynamic and the binary needs
    // `libflint.dylib` at runtime.
    //
    // Link order matters for static resolution: vdf depends on
    // flint/gmp/mpfr, and flint depends on gmp/mpfr. With static
    // archives, ld only extracts members whose exports satisfy
    // currently-unresolved symbols, so the dependent archives must
    // appear BEFORE the dependencies on the link line. cc's
    // `compile("vdf")` emits `cargo:rustc-link-lib=static=vdf` at the
    // time it's called — so we must call it BEFORE the flint/mpfr/gmp
    // link-lib prints, otherwise libvdf ends up after libgmp on the
    // link line and gmp members referenced only by vdf go unresolved.
    if target == "aarch64-apple-darwin" {
        // Resolve Homebrew install prefixes dynamically. The previous
        // hardcoded `/opt/homebrew/Cellar/gmp/6.3.0/lib`-style paths
        // broke on every minor version bump and were impossible to
        // override without editing build.rs. `brew --prefix LIB`
        // returns a stable per-package symlink
        // (e.g. `/opt/homebrew/opt/gmp`) that survives version
        // upgrades. Env var override (`GMP_DIR`/`FLINT_DIR`/`MPFR_DIR`)
        // lets users on non-Homebrew installs (MacPorts,
        // source-builds, vendored prefixes) point at their own
        // install root.
        let gmp = resolve_lib_root("gmp", "GMP_DIR");
        let mpfr = resolve_lib_root("mpfr", "MPFR_DIR");
        let (flint_lib_dir, flint_include) = resolve_flint();

        println!("cargo:rustc-link-search=native={}/lib", gmp);
        println!("cargo:rustc-link-search=native={}", flint_lib_dir);
        println!("cargo:rustc-link-search=native={}/lib", mpfr);

        let inc_gmp = format!("-I{}/include", gmp);
        let inc_flint = format!("-I{}", flint_include);
        let inc_mpfr = format!("-I{}/include", mpfr);
        cc::Build::new()
            .cpp(true)
            .file("src/vdf.cpp")
            .flag(&inc_gmp)
            .flag(&inc_flint)
            .flag(&inc_mpfr)
            .compile("vdf");

        let flint_static_on_macos = env::var("FLINT_DIR").is_ok();
        if flint_static_on_macos {
            println!("cargo:rustc-link-lib=static=flint");
        } else {
            println!("cargo:rustc-link-lib=flint");
        }
        println!("cargo:rustc-link-lib=static=mpfr");
        println!("cargo:rustc-link-lib=static=gmp");
    } else if target == "aarch64-unknown-linux-gnu" {
        println!("cargo:rustc-link-search=native=/usr/local/lib");
        println!("cargo:rustc-link-search=native=/usr/lib/aarch64-linux-gnu/");
        cc::Build::new()
            .cpp(true)
            .file("src/vdf.cpp")
            .static_flag(true)
            .flag("-lflint")
            .flag("-lmpfr")
            .compile("vdf");
        println!("cargo:rustc-link-lib=static=flint");
        println!("cargo:rustc-link-lib=mpfr");
        println!("cargo:rustc-link-lib=static=gmp");
    } else if target == "x86_64-unknown-linux-gnu" {
        // Ubuntu/Debian put apt's libgmp.a under the multiarch dir
        // (/usr/lib/x86_64-linux-gnu/), not directly in /usr/lib. Without
        // this search path rustc fails with "could not find native static
        // library `gmp`". Mirrors the aarch64 branch above.
        println!("cargo:rustc-link-search=native=/usr/local/lib");
        println!("cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu/");
        println!("cargo:rustc-link-search=native=/usr/lib/");
        cc::Build::new()
            .cpp(true)
            .file("src/vdf.cpp")
            .static_flag(true)
            .flag("-lflint")
            .flag("-lmpfr")
            .compile("vdf");
        println!("cargo:rustc-link-lib=static=flint");
        println!("cargo:rustc-link-lib=mpfr");
        println!("cargo:rustc-link-lib=static=gmp");
    } else {
        panic!("unsupported target {target}");
    }
}

/// Resolve flint's library-search dir and header-include dir,
/// supporting two layouts:
///
///   * **Install prefix**  (`make install --prefix=PFX`): archive at
///     `<PFX>/lib/libflint.a`, headers at `<PFX>/include/flint/*.h`.
///   * **In-tree source build** (no install step): archive at
///     `<ROOT>/libflint.a`, headers flat in `<ROOT>/src/` with no
///     `flint/` subdirectory. The user's `~/src/flint` is this shape.
///
/// For the in-tree layout the include directive `#include <flint/fmpz.h>`
/// won't resolve directly — there's no `flint/` directory. We create
/// a shim under `$OUT_DIR/flint-shim` whose `flint` entry symlinks to
/// `<ROOT>/src`, so `-I$OUT_DIR/flint-shim` makes the header path
/// resolve to `<ROOT>/src/fmpz.h`.
///
/// Returns `(lib_search_dir, header_include_dir)`. Panics with an
/// actionable message if neither layout is present.
fn resolve_flint() -> (String, String) {
    println!("cargo:rerun-if-env-changed=FLINT_DIR");
    let root = if let Ok(p) = env::var("FLINT_DIR") {
        if p.is_empty() {
            resolve_lib_root("flint", "FLINT_DIR")
        } else {
            p
        }
    } else {
        resolve_lib_root("flint", "FLINT_DIR")
    };

    let install_a = format!("{root}/lib/libflint.a");
    let source_a = format!("{root}/libflint.a");

    if Path::new(&install_a).exists() {
        return (format!("{root}/lib"), format!("{root}/include"));
    }
    if Path::new(&source_a).exists() {
        // Synthesize <OUT_DIR>/flint-shim/flint -> <root>/src so that
        // `#include <flint/fmpz.h>` resolves. unix-only, but this
        // branch is only reachable on macOS today and Linux uses the
        // install-prefix layout shipped by the gmp/flint builders.
        let out_dir = env::var("OUT_DIR").expect("cargo OUT_DIR");
        let shim_root = format!("{out_dir}/flint-shim");
        let shim_dir = format!("{shim_root}/flint");
        let src_dir = format!("{root}/src");
        // `create_dir_all` is idempotent; remove any stale symlink
        // before re-creating so we always point at the current src/.
        std::fs::create_dir_all(&shim_root)
            .unwrap_or_else(|e| panic!("create_dir_all {shim_root}: {e}"));
        if Path::new(&shim_dir).exists() || Path::new(&shim_dir).is_symlink() {
            std::fs::remove_file(&shim_dir).or_else(|_| std::fs::remove_dir_all(&shim_dir))
                .unwrap_or_else(|e| panic!("remove stale shim {shim_dir}: {e}"));
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(&src_dir, &shim_dir)
            .unwrap_or_else(|e| panic!("symlink {src_dir} -> {shim_dir}: {e}"));
        return (root, shim_root);
    }

    panic!(
        "FLINT at {root} contains neither lib/libflint.a (install-prefix \
         layout) nor libflint.a (in-tree source-build layout). Set \
         FLINT_DIR to a directory containing one of those, e.g. a \
         flint source tree where `./configure --enable-static` then \
         `make` has been run."
    );
}

/// Resolve a Homebrew-installed library's root directory. Checks
/// `<env_var>` first (so users can point at non-Homebrew locations)
/// and falls back to `brew --prefix <pkg>`. Panics with an actionable
/// message if neither resolves.
fn resolve_lib_root(pkg: &str, env_var: &str) -> String {
    println!("cargo:rerun-if-env-changed={env_var}");
    if let Ok(p) = env::var(env_var) {
        if !p.is_empty() {
            return p;
        }
    }
    let out = Command::new("brew").args(["--prefix", pkg]).output();
    match out {
        Ok(o) if o.status.success() => {
            let s = String::from_utf8(o.stdout)
                .unwrap_or_else(|e| panic!("brew --prefix {pkg}: utf8 decode failed: {e}"));
            let trimmed = s.trim();
            if trimmed.is_empty() {
                panic!(
                    "brew --prefix {pkg} returned empty; install with `brew install {pkg}` \
                     or set {env_var} to the install root containing lib/lib{pkg}.a"
                );
            }
            trimmed.to_string()
        }
        Ok(o) => panic!(
            "brew --prefix {pkg} failed (exit {:?}): {}; install with `brew install {pkg}` \
             or set {env_var} to the install root containing lib/lib{pkg}.a",
            o.status.code(),
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => panic!(
            "could not invoke `brew --prefix {pkg}`: {e}; install Homebrew and run \
             `brew install {pkg}`, or set {env_var} to the install root containing \
             lib/lib{pkg}.a"
        ),
    }
}
