# Contributing to DKLs23
First off, thank you for considering contributing to our project! We appreciate your time and effort.

## Table of Contents

- [How to Contribute](#how-to-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Enhancements](#suggesting-enhancements)
  - [Submitting Changes](#submitting-changes)
- [Setup Instructions](#setup-instructions)
  - [Installing Rust](#installing-rust)
  - [Cloning the Repository](#cloning-the-repository)
  - [Installing Dependencies](#installing-dependencies)
  - [Building the Project](#building-the-project)
- [Code Style](#code-style)
- [Running Tests](#running-tests)
- [Code of Conduct](#code-of-conduct)
- [Acknowledgments](#acknowledgments)

## How to Contribute

### Reporting Bugs
If you find a bug, please report it by opening an issue on our [GitHub Issues](https://github.com/0xCarbon/DKLs23/issues) page. Include the following details:
- A clear and descriptive title.
- A detailed description of the issue.
- Steps to reproduce the issue.
- Any relevant logs or screenshots.

### Suggesting Enhancements
We welcome suggestions for new features or improvements. Please open an issue on our [GitHub Issues](https://github.com/0xCarbon/DKLs23/issues) page and describe your idea in detail. Include:
- A clear and descriptive title.
- A detailed description of the enhancement.
- Any relevant examples or use cases.

### Submitting Changes
1. Fork the repository.
2. Create a new branch following [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/) pattern (`git checkout -b <branch-name>`)
3. Make your changes.
4. Commit your changes (`git commit -m 'feat: describe your feature'`).
5. Push to the branch (`git push origin <branch-name>`).
6. Create a new Pull Request.


## Setup Instructions
### Installing Rust

To contribute to this project, you need to have Rust installed on your machine. You can install Rust by following these steps:

1. Open a terminal.
2. Run the following command to install Rust using `rustup`:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
3. Follow the on-screen instructions to complete the installation.
4. After installation, ensure that Rust is installed correctly by running:
```bash
rustc --version
```
### Cloning the Repository
Once Rust is installed, you can clone the repository:

1. Open a terminal.
2. Run the following commands:
```bash
git clone https://github.com/0xCarbon/DKLs23 cd DKLs23
```
### Installing Dependencies
This project uses Cargo, Rust's package manager, to manage dependencies. To install the necessary dependencies, run:
```bash
cargo build
```
This command will fetch all the dependencies and build them along with the project.

### Building the Project
To build the project, run:
```bash
cargo build
```
This will compile DKLs23 and create rust libraries (`libdkls23.d` and `libdkls23.rlib`) in the `target/debug` directory.

## Code Style
Please follow our coding conventions and style guides. We use [Rustfmt](https://github.com/rust-lang/rustfmt) for formatting Rust code. You can run `cargo fmt` to format your code.

## Running Tests
Make sure all tests pass before submitting your changes. You can run tests using `cargo test`.

## Code of Conduct
Please note that this project is released with a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms.

## Acknowledgments
Thank you for contributing with us!
