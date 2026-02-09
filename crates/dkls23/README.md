<div align="center">
    <picture>
        <source srcset=".assets/dkls23-banner.png"  media="(prefers-color-scheme: dark)">
        <img src=".assets/dkls23-banner.png" alt="DKLs logo">
    </picture>

  <p>
    <a href="https://github.com/0xCarbon/DKLs23/actions?query=workflow%3Abackend-ci">
      <img src="https://github.com/0xCarbon/DKLs23/actions/workflows/backend-ci.yml/badge.svg?event=push" alt="Test Status">
    </a>
    <a href="https://crates.io/crates/dkls23">
      <img src="https://img.shields.io/crates/v/dkls23.svg" alt="DKLs23 Crate">
    </a>
    <a href="https://docs.rs/dkls23/latest/dkls23/">
      <img src="https://docs.rs/dkls23/badge.svg" alt="DKLs23 Docs">
    </a>
  </p>
</div>

<br /> 

## Overview
DKLs23 is an advanced open-source implementation of the Threshold ECDSA method (see https://eprint.iacr.org/2023/765.pdf). The primary goal of DKLs23 is to compute a secret key without centralizing it in a single location. Instead, it leverages multiple parties to compute the secret key, with each party receiving a key share. This approach enhances security by eliminating single points of failure.

## Getting Started
These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Installation
A step-by-step guide to installing the project.

1. **Install Rust using `rustup`**
``` bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

2. **Clone the repository:**
```bash
git clone https://github.com/0xCarbon/DKLs23 cd DKLs23
```

3. **Install dependencies:**
```bash
cargo build
```

## Contributing
We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to get started.

## Security
For information on how to report security vulnerabilities, please see our [SECURITY.md](SECURITY.md).

## Code of Conduct
Please note that this project is released with a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms.


## License
This project is licensed under either of
- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT license](LICENSE-MIT)

at your option.

## Authors
See the list of [contributors](https://github.com/0xCarbon/DKLs23/contributors) who participated in this project.