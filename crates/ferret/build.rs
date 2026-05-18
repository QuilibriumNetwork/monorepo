// build.rs
use cc;
use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
  let target = env::var("TARGET").expect("cargo should have set this");

  // Get path to local emp-tool and emp-ot directories (relative to crates/ferret)
  // manifest_dir is .../ceremonyclient/crates/ferret
  // emp-tool is at .../ceremonyclient/emp-tool
  // emp-ot is at .../ceremonyclient/emp-ot
  let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
  let emp_tool_local = format!("{}/../../emp-tool", manifest_dir);
  let emp_ot_local = format!("{}/../../emp-ot", manifest_dir);

  if target == "aarch64-apple-darwin" {
    // Resolve Homebrew openssl@3 dynamically. Previous code hardcoded
    // `/opt/homebrew/Cellar/openssl@3/3.6.1`, which broke on every
    // OpenSSL minor-version bump. `brew --prefix openssl@3` returns
    // the stable `/opt/homebrew/opt/openssl@3` symlink. Env var
    // override (`OPENSSL_DIR`) lets users on non-Homebrew installs
    // point at their own prefix.
    let openssl_prefix = resolve_lib_root("openssl@3", "OPENSSL_DIR");
    let openssl_inc = format!("-I{}/include", openssl_prefix);
    let openssl_lib = format!("-L{}/lib", openssl_prefix);

    cc::Build::new()
        .cpp(true)
        .flag_if_supported("-std=c++17")
        .file("emp_bridge.cpp")
        // Local emp-tool first (for buffer_io_channel.h)
        .flag(&format!("-I{}", emp_tool_local))
        // Local emp-ot first (for ferret_cot.h with is_setup())
        .flag(&format!("-I{}", emp_ot_local))
        .flag("-I/usr/local/include/emp-tool/")
        .flag("-I/usr/local/include/emp-ot/")
        .flag(&openssl_inc)
        .flag("-L/usr/local/lib/emp-tool/")
        .flag(&openssl_lib)
        .warnings(false)
        .compile("emp_bridge");

    println!("cargo:rustc-link-search=native=/usr/local/lib");
    println!("cargo:rustc-link-search=native={}/lib", openssl_prefix);
    println!("cargo:rustc-link-search=native=/opt/homebrew/lib");

    println!("cargo:rustc-link-lib=static=emp-tool");

    // libc++ is an Apple system framework — only ships dynamic. Keep
    // it as a dylib link; the runtime always provides it. OpenSSL's
    // libcrypto/libssl ARE statically linkable from Homebrew (a
    // `libcrypto.a` / `libssl.a` ships alongside the .dylib) and we
    // want them in the binary so users don't need `brew install
    // openssl@3` at runtime — the same self-contained-binary
    // motivation as the gmp/flint/mpfr switch in `crates/classgroup`.
    println!("cargo:rustc-link-lib=dylib=c++");
    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-lib=static=ssl");

    println!("cargo:rerun-if-changed=emp_bridge.cpp");
    println!("cargo:rerun-if-changed=emp_bridge.h");
  } else if target == "aarch64-unknown-linux-gnu" {
    cc::Build::new()
        .cpp(true)
        .flag_if_supported("-std=c++17")
        .flag_if_supported("-march=armv8-a+crypto")
        .file("emp_bridge.cpp")
        .flag("-I/usr/local/include/emp-tool/")
        .flag("-I/usr/local/include/emp-ot/")
        .flag("-I/usr/include/openssl/")
        .flag("-L/usr/local/lib/")
        .flag("-L/usr/local/lib/aarch64-linux-gnu/")
        .flag("-L/usr/lib/aarch64-linux-gnu/openssl/")
        .warnings(false)
        .compile("emp_bridge");

    println!("cargo:rustc-link-search=native=/usr/local/lib/aarch64-linux-gnu");
    println!("cargo:rustc-link-search=native=/usr/local/lib/");

    println!("cargo:rustc-link-lib=static=emp-tool");

    println!("cargo:rustc-link-lib=dylib=stdc++");
    println!("cargo:rustc-link-lib=dylib=crypto");
    println!("cargo:rustc-link-lib=dylib=ssl");

    println!("cargo:rerun-if-changed=emp_bridge.cpp");
    println!("cargo:rerun-if-changed=emp_bridge.h");
  } else if target == "x86_64-unknown-linux-gnu" {
    cc::Build::new()
        .cpp(true)
        .flag_if_supported("-std=c++17")
        .flag_if_supported("-maes")
        .flag_if_supported("-msse4.1")
        .file("emp_bridge.cpp")
        .flag("-I/usr/local/include/emp-tool/")
        .flag("-I/usr/local/include/emp-ot/")
        .flag("-I/usr/include/openssl/")
        .flag("-L/usr/local/lib/")
        .flag("-L/usr/lib/openssl/")
        .warnings(false)
        .compile("emp_bridge");

    println!("cargo:rustc-link-search=native=/usr/local/lib");

    println!("cargo:rustc-link-lib=static=emp-tool");

    println!("cargo:rustc-link-lib=dylib=stdc++");
    println!("cargo:rustc-link-lib=dylib=crypto");
    println!("cargo:rustc-link-lib=dylib=ssl");

    println!("cargo:rerun-if-changed=emp_bridge.cpp");
    println!("cargo:rerun-if-changed=emp_bridge.h");
  } else {
    panic!("unsupported target {target}");
  }
  uniffi::generate_scaffolding("src/lib.udl").expect("uniffi generation failed");
}

/// Resolve a Homebrew-installed library's root directory. Checks
/// `<env_var>` first (so users can point at non-Homebrew locations)
/// and falls back to `brew --prefix <pkg>`. Panics with an actionable
/// message if neither resolves. Mirrors the helper in
/// `crates/classgroup/build.rs` — kept duplicated rather than
/// extracted into a shared crate to avoid pulling a build-dep
/// dependency edge between two otherwise-independent leaf crates.
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
                     or set {env_var} to the install root"
                );
            }
            trimmed.to_string()
        }
        Ok(o) => panic!(
            "brew --prefix {pkg} failed (exit {:?}): {}; install with `brew install {pkg}` \
             or set {env_var} to the install root",
            o.status.code(),
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => panic!(
            "could not invoke `brew --prefix {pkg}`: {e}; install Homebrew and run \
             `brew install {pkg}`, or set {env_var} to the install root"
        ),
    }
}
