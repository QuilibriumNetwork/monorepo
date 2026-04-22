use cc;
use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/vdf.cpp");

    println!("cargo:rustc-link-arg=-lgmp");
    println!("cargo:rustc-link-arg=-lflint");
    println!("cargo:rustc-link-arg=-lmpfr");

    let target = env::var("TARGET").expect("cargo should have set this");
    if target == "aarch64-apple-darwin" {
        println!("cargo:rustc-link-search=/opt/homebrew/Cellar/gmp/6.3.0/lib");
        println!("cargo:rustc-link-search=/opt/homebrew/Cellar/flint/3.1.3-p1/lib");
        println!("cargo:rustc-link-search=/opt/homebrew/Cellar/mpfr/4.2.1/lib");
    } else if target == "aarch64-unknown-linux-gnu" {
        println!("cargo:rustc-link-search=/usr/lib/aarch64-linux-gnu/");
    } else if target == "x86_64-unknown-linux-gnu" {
        println!("cargo:rustc-link-search=/usr/lib/");
    } else {
        panic!("unsupported target {target}");
    }
    if target == "aarch64-apple-darwin" {
      cc::Build::new()
        .cpp(true)
        .file("src/vdf.cpp")
        .flag("-I/opt/homebrew/Cellar/gmp/6.3.0/include")
        .flag("-I/opt/homebrew/Cellar/flint/3.1.3-p1/include")
        .flag("-I/opt/homebrew/Cellar/mpfr/4.2.1/include")
        .flag("-L/opt/homebrew/Cellar/gmp/6.3.0/lib")
        .flag("-L/opt/homebrew/Cellar/flint/3.1.3-p1/lib")
        .flag("-L/opt/homebrew/Cellar/mpfr/4.2.1/lib")
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