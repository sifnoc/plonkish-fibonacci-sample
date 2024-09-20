/// Halo2 Fibonacci circuit
mod circuit;
pub mod io;
mod serialisation;

use crate::circuit::{generate_halo2_proof, verify_halo2_proof};
use crate::serialisation::{deserialize_circuit_inputs, InputsSerialisationWrapper};
pub use circuit::FibonacciCircuit;
use halo2curves::bn256::{Bn256, Fr};
#[warn(unused_imports)]
use plonkish_backend::{
    backend::hyperplonk::{HyperPlonkProverParam, HyperPlonkVerifierParam},
    pcs::{multilinear::Gemini, univariate::UnivariateKzg},
};
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Display;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub struct FibonacciError(String);

impl Display for FibonacciError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

type GeminiKzg = Gemini<UnivariateKzg<Bn256>>;
type GenerateProofResult = (Vec<u8>, Vec<u8>);

pub fn prove(
    srs_key_path: &str,
    proving_key_path: &str,
    input: HashMap<String, Vec<String>>,
) -> Result<GenerateProofResult, Box<dyn Error>> {
    let circuit_inputs = deserialize_circuit_inputs(input)
        .map_err(|e| FibonacciError(format!("Failed to deserialize circuit inputs: {}", e)))?;

    let srs = io::read_srs_path(Path::new(&srs_key_path));

    let proving_key =
        io::read_pk::<HyperPlonkProverParam<Fr, GeminiKzg>>(Path::new(&proving_key_path));

    let (proof, inputs) = generate_halo2_proof(&srs, &proving_key, circuit_inputs)
        .map_err(|e| FibonacciError(format!("Failed to generate the proof: {}", e)))?;

    let serialized_inputs = bincode::serialize(&InputsSerialisationWrapper(inputs))
        .map_err(|e| FibonacciError(format!("Serialisation of Inputs failed: {}", e)))?;

    Ok((proof, serialized_inputs))
}

pub fn verify(
    srs_key_path: &str,
    verifying_key_path: &str,
    proof: Vec<u8>,
    public_inputs: Vec<u8>,
) -> Result<bool, Box<dyn Error>> {
    let deserialized_inputs: Vec<Fr> =
        bincode::deserialize::<InputsSerialisationWrapper>(&public_inputs)
            .map_err(|e| FibonacciError(e.to_string()))?
            .0;

    let srs = io::read_srs_path(Path::new(&srs_key_path));

    let verifying_key =
        io::read_vk::<HyperPlonkVerifierParam<Fr, GeminiKzg>>(Path::new(&verifying_key_path));

    let is_valid = verify_halo2_proof(&srs, &verifying_key, proof, deserialized_inputs).unwrap();

    Ok(is_valid)
}
