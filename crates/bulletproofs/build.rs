fn main() {
    #[cfg(feature = "uniffi-bindings")]
    uniffi::generate_scaffolding("src/lib.udl").unwrap();
}