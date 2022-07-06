---
description: "Concrete is built in Rust (\U0001F49B). Here is how to install it."
---

# Installation

## Installing Rust

Concrete requires Rust 1.46 or above. Run the following to install the latest Rust version, or refer to the [rust website](https://forge.rust-lang.org/infra/other-installation-methods.html) for more options.

```bash
curl  --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Installing FFTW

Concrete uses the FFTW library for fast FFT calculations. Use the following commands to install it:

### On macOS using Homebrew

```bash
brew install fftw
```

### On Debian Linux

```bash
sudo apt-get update && sudo apt-get install -y libfftw3-dev
```

### From source

To install FFTW from source, follow the steps described in [FFTW's website](http://www.fftw.org/fftw2_doc/fftw_6.html).

## Importing Concrete in your project

Create a new Rust project if needed using Cargo:

```bash
cargo new play_with_fhe
```

Then add the Concrete dependency `concrete_lib = "0.1.0"` to the `Cargo.toml`file. For the code examples in this guide, you will also need to import `itertools`. Your configuration should look something like:

```rust
[package]
name = "play_with_fhe"
version = "0.1.0"
authors = ["FHE Curious"]

[dependencies]
concrete = "0.1.0"
itertools = "0.9.0"
```

To use the Concrete library in your code, simply import the `concrete` root module:

```rust
// file: main.rs
use concrete::*;

fn main() {
    println!("Hello Concrete!");
}
```

Then compile and run to test everything works fine:

```bash
RUSTFLAGS="-C target-cpu=native" cargo run --release 
```

Next, we will learn about homomorphic encryption and how to use Concrete to execute a program over encrypted data!

