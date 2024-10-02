# Plonkish HyperPlonk Circuit

This is a HyperPlonk circuit that computes with different polynomial commitment scheme.

Currently support that f



## Running the tests

To run the tests, execute:

```bash
cargo test
```

## Generate proving key and verifying key

An SRS file is required. You can generate this file using **plonkish_backend**. Refer to the following link: [SRS Generator](https://github.com/sifnoc/plonkish/blob/setup_custom/plonkish_backend/bin/unihyperplonk_srs_generator.rs)

Assuming that `unihyperplonk-srs-4` has been generated, you can then generate the proving key and verifying key by executing:

```bash
cargo run --release --bin gen-keys unihyperplonk-srs-4
```

