//! Trusted local worker; no networking, state lookup, or transaction admission.
fn main() {
    if let Some(message) =
        quil_lattice_ct::native_cpu::unsupported_cpu_message("quil-amount-proof-worker")
    {
        eprintln!("Error: {message}");
        // Neither the valid nor the invalid exit: the caller reports a failure.
        std::process::exit(82);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(
        quil_lattice_ct::confidential::relation::backend::worker_request::run_worker(&args),
    );
}
