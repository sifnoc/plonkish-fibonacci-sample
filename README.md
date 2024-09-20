# Plonkish Halo2 Circuit

This is a Halo2 circuit that computes random plonkissh circuit.

## Running the tests

To run the tests, execute:

```bash
cargo test
```

## Generate the srs, proving key and verifying key

To generate the srs, proving key and verifying key, execute:

```bash
cargo run --release --bin gen-keys 4
```

