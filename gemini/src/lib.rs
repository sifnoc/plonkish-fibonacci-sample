use std::{collections::HashMap, error::Error};

use fibonacci_circuit::{
    prove as _prove, verify as _verify, GenerateProofResult, PlonkishComponents,
};
use halo2curves::bn256::{Bn256, Fr};
use plonkish_backend::{
    backend::hyperplonk::{HyperPlonk, HyperPlonkProverParam, HyperPlonkVerifierParam},
    pcs::{
        multilinear,
        univariate::{UnivariateKzg, UnivariateKzgParam},
    },
};

pub struct GeminiScheme;

impl PlonkishComponents for GeminiScheme {
    type Param = UnivariateKzgParam<Bn256>;
    type ProverParam = HyperPlonkProverParam<Fr, Self::Pcs>;
    type VerifierParam = HyperPlonkVerifierParam<Fr, Self::Pcs>;
    type Pcs = multilinear::Gemini<UnivariateKzg<Bn256>>;
    type ProvingBackend = HyperPlonk<Self::Pcs>;
}

pub fn prove(
    srs_key_path: &str,
    proving_key_path: &str,
    input: HashMap<String, Vec<String>>,
) -> Result<GenerateProofResult, Box<dyn Error>> {
    _prove::<GeminiScheme>(srs_key_path, proving_key_path, input)
}

pub fn verify(
    srs_key_path: &str,
    verifying_key_path: &str,
    proof: Vec<u8>,
    public_inputs: Vec<u8>,
) -> Result<bool, Box<dyn Error>> {
    _verify::<GeminiScheme>(srs_key_path, verifying_key_path, proof, public_inputs)
}

#[cfg(test)]
mod tests {
    use fibonacci_circuit::circuit::test_utils::{bad_proof_not_verified_test, helper_functions_test, fibonacci_circuit_test};

    use super::*;


    #[test]
    fn test_fibonacci_circuit() {
        fibonacci_circuit_test::<GeminiScheme>();
    }

    #[test]
    fn test_bad_proof_not_verified() {
        bad_proof_not_verified_test::<GeminiScheme>();
    }

    #[test]
    fn test_helper_functions() {
        helper_functions_test::<GeminiScheme>();
    }
}