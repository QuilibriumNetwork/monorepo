fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/lib.udl");

    uniffi::generate_scaffolding("src/lib.udl").expect("uniffi generation failed");
}
