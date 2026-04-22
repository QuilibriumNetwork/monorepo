fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/lib.udl");

    // Skip uniffi scaffolding generation for wasm32 targets — the dkls23-wasm
    // crate provides its own wasm-bindgen surface and does not need (or want)
    // the uniffi C ABI exports.
    let target = std::env::var("TARGET").unwrap_or_default();
    if target.starts_with("wasm32") {
        return;
    }

    uniffi::generate_scaffolding("src/lib.udl").expect("uniffi generation failed");
}
