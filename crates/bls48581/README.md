# bls48581

BLS signature implementation using the BLS48-581 pairing-friendly elliptic curve.

This crate provides cryptographic primitives for BLS (Boneh-Lynn-Shacham) signatures on the BLS48-581 curve, including:

- BLS signature generation and verification
- BLS signature aggregation
- Key generation and management
- KZG (Kate-Zaverucha-Goldberg) polynomial commitments
- KZG inclusion proofs (single and multiproofs)

## Features

- **BLS Signatures**: Create and verify BLS signatures with support for aggregation
- **KZG Commitments**: Polynomial commitment scheme for vector commitments
- **Inclusion Proofs**: Generate and verify proofs that elements are included in committed data
- **Multiproofs**: Efficient batched proofs for multiple indices

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
bls48581 = "2.1.0"
```

### Example: BLS Signatures

```rust
use bls48581::{bls_keygen, bls_sign, bls_verify};

// Initialize the library
bls48581::init();

// Generate a key pair
let keypair = bls_keygen();

// Sign a message
let message = b"Hello, World!";
let signature = bls_sign(&keypair.secret_key, message).unwrap();

// Verify the signature
let is_valid = bls_verify(&keypair.public_key, message, &signature).unwrap();
assert!(is_valid);
```

### Example: KZG Commitments

```rust
use bls48581::{commit, prove, verify_raw};

bls48581::init();

// Create a polynomial (as bytes)
let data = vec![1u8; 4096]; // 64 coefficients * 64 bytes each
let poly_size = 64;

// Generate commitment
let commitment = commit(&data, poly_size).unwrap();

// Generate proof for index 5
let index = 5;
let proof = prove(&data, index, poly_size).unwrap();

// Verify proof
let is_valid = verify_raw(&data, &commitment, index as u64, &proof, poly_size).unwrap();
assert!(is_valid);
```

## Security Notice

This library implements cryptographic primitives and should be used with care. It is based on the MIRACL Core library and implements the BLS48-581 curve which provides approximately 256-bit security.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

This crate is derived from [MIRACL Core](https://github.com/miracl/core), which is also licensed under Apache 2.0.

## Attribution

Portions of this software are based on:
- MIRACL Core (https://github.com/miracl/core)
- Apache Milagro Cryptographic Library (AMCL)

## References

- [BLS Signatures](https://en.wikipedia.org/wiki/BLS_digital_signature)
- [KZG Polynomial Commitments](https://dankradfeist.de/ethereum/2020/06/16/kate-polynomial-commitments.html)
- [MIRACL Core](https://github.com/miracl/core)
