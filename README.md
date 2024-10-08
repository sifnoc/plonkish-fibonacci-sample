[![Rust](https://github.com/sifnoc/plonkish-fibonacci-sample/actions/workflows/rust.yml/badge.svg)](https://github.com/sifnoc/plonkish-fibonacci-sample/actions/workflows/rust.yml)

# Fibonacci Circuit: HyperPlonk & Gemini Implementations

This example showcases the Fibonacci circuit using two distinct backend implementations: **HyperPlonk** and **Gemini**.

HyperPlonk leverages a multilinear KZG commitment scheme on a Boolean hypercube, avoiding the need for FFT. 
Gemini uses a time- and space-efficient univariate KZG commitment scheme with a similar modular structure to HyperPlonk. 
Both implementations enable efficient proof generation with distinct approaches to polynomial commitments.

## Running Tests
To execute the tests for both backends, run:

```bash
cargo test
```

This will test the Fibonacci circuit across both the HyperPlonk and Gemini implementations.


## Generate proving key and verifying key


Each implementation requires a SRS file, but HyperPlonk and Gemini use different generators for the SRS.

### 1. HyperPlonk

For HyperPlonk, the SRS file must be generated using the [hyperplonk_srs_generator](https://github.com/sifnoc/plonkish/blob/setup_custom/plonkish_backend/bin/hyperplonk_srs_generator.rs). Assume that the SRS file generated as "hyperplonk-srs-4".

Once you have the SRS file, you can then generate the proving and verifying keys:

```bash
cargo run --release --bin gen-keys hyperplonk-srs-4
```

### 2. Gemini
For Gemini, the SRS file is generated using the [unihyperplonk_srs_generator](https://github.com/sifnoc/plonkish/blob/setup_custom/plonkish_backend/bin/unihyperplonk_srs_generator.rs). Assume that the SRS file generated as "unihyperplonk-srs-4".

Next, generate the proving and verifying keys for Gemini:

```bash
cargo run --release --bin gen-keys unihyperplonk-srs-4
```

