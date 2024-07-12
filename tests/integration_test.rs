use std::collections::HashMap;
use std::process::Command;
use std::sync::Once;

static INIT: Once = Once::new();
const ASSETS_PATH: &str = "out";

// This function should run `cargo run --bin gen-keys` to generate the proving and verifying keys.
fn setup_keys() {
    INIT.call_once(|| {
        let mut gen_keys_command = Command::new("cargo");
        gen_keys_command
            .arg("run")
            .arg("--bin")
            .arg("gen-keys");

        gen_keys_command
            .spawn()
            .expect("Failed to spawn cargo build")
            .wait()
            .expect("cargo build errored");
    });
}


#[test]
fn test_prove_verify_end_to_end() {
    setup_keys();

    let mut input = HashMap::new();
    input.insert("out".to_string(), vec!["55".to_string()]);

    let proving_key_path = format!("{}/fibonacci_pk", ASSETS_PATH);
    let verifying_key_path = format!("{}/fibonacci_vk", ASSETS_PATH);
    let srs_key_path = format!("{}/fibonacci_srs", ASSETS_PATH);

    let result = halo2_fibonacci::prove(&srs_key_path, &proving_key_path, input).unwrap();
    let verified = halo2_fibonacci::verify(
        &srs_key_path,
        &verifying_key_path,
        result.0,
        result.1,
    )
        .unwrap();
    assert!(verified);
}