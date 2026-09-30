//! Trusted local worker; no networking, state lookup, or transaction admission.
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(quil_lattice_ct::confidential::relation::backend::worker_request::run_worker(&args));
}
