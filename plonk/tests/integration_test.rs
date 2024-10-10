use std::collections::HashMap;

use fibonacci_circuit::setup_keys;
use plonk_fibonacci::*;

#[test]
pub fn plonk_integration_test() {
    let srs_key_path = "hermez-raw-4";
    let proving_key_path = "out/plonk_fibonacci_pk.bin";
    let verifying_key_path = "out/plonk_fibonacci_vk.bin";

    let mut input = HashMap::new();
    input.insert("out".to_string(), vec!["55".to_string()]);

    setup_keys(&srs_key_path);

    let result = prove(&srs_key_path, &proving_key_path, input).unwrap();

    let verified = verify(&srs_key_path, &verifying_key_path, result.0, result.1).unwrap();
    
    assert!(verified);
}
