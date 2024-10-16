use std::{collections::HashMap, env, error::Error, fmt::Display, io::Cursor, path::Path, process::Command, sync::Once};

use halo2curves::bn256::Fr;
use plonkish_backend::{
    backend::{PlonkishBackend, PlonkishCircuit, WitnessEncoding},
    frontend::halo2::Halo2Circuit,
    pcs::{CommitmentChunk, PolynomialCommitmentScheme},
    util::transcript::{Keccak256Transcript, TranscriptRead, TranscriptWrite},
};
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

/// Halo2 Fibonacci circuit
pub mod circuit;
use crate::circuit::{generate_halo2_proof, verify_halo2_proof};
pub use circuit::FibonacciCircuit;

pub mod io;
pub mod serialisation;
use crate::serialisation::{deserialize_circuit_inputs, InputsSerialisationWrapper};

pub trait PlonkishComponents {
    type Param: Clone + Serialize + DeserializeOwned;
    type ProverParam: Clone + Serialize + DeserializeOwned;
    type VerifierParam: Clone + Serialize + DeserializeOwned;
    type Pcs: PolynomialCommitmentScheme<
        Fr,
        Param = Self::Param,
    >;
    type ProvingBackend: PlonkishBackend<
            Fr,
            Pcs = Self::Pcs,
            ProverParam = Self::ProverParam,
            VerifierParam = Self::VerifierParam,
        > + WitnessEncoding;
}

#[derive(Debug, Error)]
pub struct FibonacciError(pub String);

impl Display for FibonacciError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub type GenerateProofResult = (Vec<u8>, Vec<u8>);
pub type ProofTranscript = Keccak256Transcript<Cursor<Vec<u8>>>;

pub fn gen_keys<PC>(filename_prefix: &str)
where
    PC: PlonkishComponents,
{
    // Get the project's root directory from the `CARGO_MANIFEST_DIR` environment variable
    let project_root = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is not set");

    // Read SRS from file
    let srs_filename = env::args().nth(1).expect("Please specify SRS file path");
    let srs_path = Path::new(&project_root).join(srs_filename);
    let param = io::read_srs_path::<PC>(&srs_path);

    // Create the path to the `out` directory under the project's root directory
    let out_dir = Path::new(&project_root).join("out");

    // Check if the `out` directory exists, if not, create it
    if !out_dir.exists() {
        std::fs::create_dir(&out_dir).expect("Unable to create out directory");
    }

    // Setup circuit
    let circuit = FibonacciCircuit::<Fr> {
        public_input: vec![vec![Fr::from(1), Fr::from(1), Fr::from(55)]],
    };

    let circuit_fn = |k| {
        let circuit =
            Halo2Circuit::<Fr, FibonacciCircuit<Fr>>::new::<PC::ProvingBackend>(k, circuit.clone());
        (circuit.circuit_info().unwrap(), circuit)
    };
    let (circuit_info, _) = circuit_fn(4usize);

    let (prover_parameters, verifier_parameters) =
        PC::ProvingBackend::preprocess(&param, &circuit_info).unwrap();

    let pk_path = out_dir.join(format!("{}_fibonacci_pk.bin", filename_prefix));
    let _ = io::save_to_file::<_, PC::ProverParam>(&pk_path, &prover_parameters);
    let vk_path = out_dir.join(format!("{}_fibonacci_vk.bin", filename_prefix));
    let _ = io::save_to_file::<_, PC::VerifierParam>(&vk_path, &verifier_parameters);

    println!("Preparation finished successfully.");
    println!("SRS readed from {}", srs_path.display());
    println!("Proving key stored in {}", pk_path.display());
    println!("Verification key stored in {}", vk_path.display());
}

pub fn prove<PC>(
    srs_key_path: &str,
    proving_key_path: &str,
    input: HashMap<String, Vec<String>>,
) -> Result<GenerateProofResult, Box<dyn Error>>
where
    PC: PlonkishComponents,
    ProofTranscript: TranscriptWrite<CommitmentChunk<Fr, PC::Pcs>, Fr>,
{
    let circuit_inputs = deserialize_circuit_inputs(input)
        .map_err(|e| FibonacciError(format!("Failed to deserialize circuit inputs: {}", e)))?;

    let srs = io::read_srs_path::<PC>(Path::new(&srs_key_path));

    let proving_key = io::read_pk::<PC::ProverParam>(Path::new(&proving_key_path));

    let (proof, inputs) = generate_halo2_proof::<PC>(&srs, &proving_key, circuit_inputs)
        .map_err(|e| FibonacciError(format!("Failed to generate the proof: {}", e)))?;

    let serialized_inputs = bincode::serialize(&InputsSerialisationWrapper(inputs))
        .map_err(|e| FibonacciError(format!("Serialisation of Inputs failed: {}", e)))?;

    Ok((proof, serialized_inputs))
}

pub fn verify<PC>(
    srs_key_path: &str,
    verifying_key_path: &str,
    proof: Vec<u8>,
    public_inputs: Vec<u8>,
) -> Result<bool, Box<dyn Error>>
where
    PC: PlonkishComponents,
    ProofTranscript: TranscriptRead<CommitmentChunk<Fr, PC::Pcs>, Fr>,
{
    let deserialized_inputs: Vec<Fr> =
        bincode::deserialize::<InputsSerialisationWrapper>(&public_inputs)
            .map_err(|e| FibonacciError(e.to_string()))?
            .0;

    let srs = io::read_srs_path::<PC>(Path::new(&srs_key_path));

    let verifying_key = io::read_vk::<PC::VerifierParam>(Path::new(&verifying_key_path));

    let is_valid =
        verify_halo2_proof::<PC>(&srs, &verifying_key, proof, deserialized_inputs).unwrap();

    Ok(is_valid)
}

pub fn setup_keys(srs_filename: &str) {
    let once = Once::new();

    once.call_once(|| {
        let mut gen_keys_command = Command::new("cargo");
        gen_keys_command
            .arg("run")
            .arg("--bin")
            .arg("gen-keys")
            .arg(srs_filename);

        gen_keys_command
            .spawn()
            .expect("Failed to spawn cargo build")
            .wait()
            .expect("cargo build errored");
    });
}

// For external integration tests 
pub fn test_prove_verify_end_to_end<PC>(
    srs_key_path: &str,
    proving_key_path: &str,
    verifying_key_path: &str,
) where
    PC: PlonkishComponents,
    ProofTranscript: TranscriptRead<CommitmentChunk<Fr, PC::Pcs>, Fr>
        + TranscriptWrite<CommitmentChunk<Fr, PC::Pcs>, Fr>,
{
    let mut input = HashMap::new();
    input.insert("out".to_string(), vec!["55".to_string()]);

    setup_keys(&srs_key_path);

    let result = prove::<PC>(&srs_key_path, &proving_key_path, input).unwrap();

    let verified =
        verify::<PC>(&srs_key_path, &verifying_key_path, result.0, result.1)
            .unwrap();
    assert!(verified);
}
