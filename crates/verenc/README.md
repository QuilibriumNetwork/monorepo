
## Introduction
Implementation of the Robust DKG-in-the-head (RDKGitH) verifiable encryption scheme.

## Description
This verifiable encryption (VE) scheme allows one to encrypt a discrete logarithm instance under an Elgamal public key and prove to anyone that the correct value is encrypted.  

We use the ed448-goldilocks-plus library for ed448, but it was converted from an arkworks implementation. There was also a significant performance issue in the original implementation it was forked from in the lagrange calculation – previously the numerator and denominator of the polynomial evaluation was calculated at every degree, incurring the cost of modular inversion with every degree. We defer inversion to the final step of the accumulated value, drastically increasing performance of compression.

Hashing is done with SHA512, using the Rust [`sha2`](https://docs.rs/sha2/latest/sha2/) crate. 

Our seed tree implementation is inspired by the one in the C implementation of the [LegRoast](https://github.com/WardBeullens/LegRoast) signature scheme. 

## Running Tests and Benchmarks
To run unit tests type `cargo test --release`. 

Sizes of the proofs and ciphertexts for the two schemes are computed in unit tests, use the script `run_size_benchmarks.sh` to run the tests and display the output. 

Benchmarks of the time required to run the main VE operations `Prove()`, `Verify()`, `Compress()` and `Recover()`
are also provided, and can be run with `cargo bench`.  To run the RDKGitH benchmarks use
```
cargo bench -- "^RDKGitH"
```

