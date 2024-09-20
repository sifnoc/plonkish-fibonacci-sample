use std::collections::HashMap;
use std::process::Command;
use std::sync::Once;

static INIT: Once = Once::new();
const ASSETS_PATH: &str = "out";

// This function should run `cargo run --bin gen-keys` to generate the proving and verifying keys.
fn setup_keys(srs_filename: &str) {
    INIT.call_once(|| {
        let mut gen_keys_command = Command::new("cargo");
        gen_keys_command.arg("run").arg("--bin").arg("gen-keys").arg(srs_filename);

        gen_keys_command
            .spawn()
            .expect("Failed to spawn cargo build")
            .wait()
            .expect("cargo build errored");
    });
}

#[test]
fn test_prove_verify_end_to_end() {
    let mut input = HashMap::new();
    input.insert("out".to_string(), vec!["55".to_string()]);

    let srs_key_path= "unihyperplonk-srs-4";
    setup_keys(&srs_key_path);

    let proving_key_path = format!("{}/hyperplonk_fibonacci_pk.bin", ASSETS_PATH);
    let verifying_key_path = format!("{}/hyperplonk_fibonacci_vk.bin", ASSETS_PATH);

    let result = plonkish_fibonacci::prove(&srs_key_path, &proving_key_path, input).unwrap();

    let verified =
        plonkish_fibonacci::verify(&srs_key_path, &verifying_key_path, result.0, result.1).unwrap();
    assert!(verified);
}
