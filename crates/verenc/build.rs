fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    uniffi::generate_scaffolding("src/lib.udl").expect("uniffi generation failed");
}
