[![Rust](https://github.com/sifnoc/plonkish-fibonacci-sample/actions/workflows/rust.yml/badge.svg)](https://github.com/sifnoc/plonkish-fibonacci-sample/actions/workflows/rust.yml)

# Fibonacci Circuit: Plonk, HyperPlonk & Gemini Implementations

This example showcases the Fibonacci circuit using two distinct backend implementations: **HyperPlonk** and **Gemini**.

This project showcases the Fibonacci circuit using three distinct backend implementations: **Plonk**, **HyperPlonk** and **Gemini**.

- **Plonk** uses the basic backend of Halo2, relying on FFT for efficient proof generation.
- **HyperPlonk** leverages a multilinear KZG commitment scheme on a Boolean hypercube, avoiding the need for FFT.
- **Gemini** employs a univariate KZG scheme but shares similarities with the HyperPlonk structure.

## Running Tests
To execute the tests for all three backends (Plonk, HyperPlonk and Gemini), run:

```bash
cargo test
```

his will test the Fibonacci circuit across all implementations.

## Generate proving key and verifying key

Each implementation requires a SRS file, but Plonk, HyperPlonk, and Gemini use different generators for the SRS.

### 1. Plonk
For the Plonk backend, pre-generated SRS files are available for download [here - halo2-kzg-srs](https://github.com/han0110/halo2-kzg-srs?tab=readme-ov-file#download-the-converted-srs). Once you've downloaded the appropriate SRS file, you can use the following command to generate the proving and verifying keys:

```bash
cargo run --release --bin gen-keys perpetual-powers-of-tau-raw-3
```

This will generate proving and verifying keys for the Fibonacci circuit using the Plonk implementation.

### 2. HyperPlonk

For HyperPlonk, the SRS file must be generated using the [hyperplonk_srs_generator](https://github.com/sifnoc/plonkish/blob/setup_custom/plonkish_backend/bin/hyperplonk_srs_generator.rs). Assume that the SRS file generated as "hyperplonk-srs-4".

Once you have the SRS file, you can then generate the proving and verifying keys:

```bash
cargo run --release --bin gen-keys hyperplonk-srs-4
```

### 3. Gemini
For Gemini, the SRS file is generated using the [unihyperplonk_srs_generator](https://github.com/sifnoc/plonkish/blob/setup_custom/plonkish_backend/bin/unihyperplonk_srs_generator.rs). Assume that the SRS file generated as "unihyperplonk-srs-4".

Next, generate the proving and verifying keys for Gemini:

```bash
cargo run --release --bin gen-keys unihyperplonk-srs-4
```

