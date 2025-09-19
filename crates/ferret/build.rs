// build.rs
use cc;
use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
  let target = env::var("TARGET").expect("cargo should have set this");
  if target == "aarch64-apple-darwin" {
    cc::Build::new()
        .cpp(true)
        .flag_if_supported("-std=c++17")
        .file("emp_bridge.cpp")
        .flag("-I/usr/local/include/emp-tool/")
        .flag("-I/usr/local/include/emp-ot/")
        .flag("-I/opt/homebrew/Cellar/openssl@3/3.5.0/include")
        .flag("-L/usr/local/lib/emp-tool/")
        .flag("-L/opt/homebrew/Cellar/openssl@3/3.5.0/lib")
        .warnings(false)
        .compile("emp_bridge");

    println!("cargo:rustc-link-search=native=/usr/local/lib");
    println!("cargo:rustc-link-search=native=/opt/homebrew/lib");

    println!("cargo:rustc-link-lib=static=emp-tool");

    println!("cargo:rustc-link-lib=dylib=c++");
    println!("cargo:rustc-link-lib=dylib=crypto");
    println!("cargo:rustc-link-lib=dylib=ssl");

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
