# Fibonacci Halo2 Circuit

This is a Halo2 circuit that computes the Fibonacci sequence. It is a simple example to demonstrate how to use Halo2.
In particular, it is currently hardcoded to check that the 10th Fibonacci number is 55.

## Running the tests

To run the tests, execute:

```bash
cargo test
```

## Generate the srs, proving key and verifying key

To generate the srs, proving key and verifying key, execute:

```bash
cargo run --release --bin gen-keys
```

