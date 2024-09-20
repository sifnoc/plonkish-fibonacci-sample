use std::env;
use std::path::Path;

use halo2_proofs::halo2curves::bn256::{Bn256, Fr};
#[warn(unused_imports)]
use plonkish_backend::{
    backend::{
        hyperplonk::{HyperPlonk, HyperPlonkProverParam, HyperPlonkVerifierParam},
        PlonkishBackend, PlonkishCircuit,
    },
    frontend::halo2::Halo2Circuit,
    pcs::{multilinear, univariate},
};
use plonkish_fibonacci::{
    io::{read_srs_path, save_to_file},
    FibonacciCircuit,
};

pub fn main() {
    type GeminiKzg = multilinear::Gemini<univariate::UnivariateKzg<Bn256>>;
    type ProvingBackend = HyperPlonk<GeminiKzg>;

    // Get the project's root directory from the `CARGO_MANIFEST_DIR` environment variable
    let project_root = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is not set");


    // Read SRS from file
    let srs_filename = env::args().nth(1).expect("Please specify SRS file path");
    let srs_path = Path::new(&project_root).join(srs_filename);
    let param = read_srs_path(&srs_path);

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
            Halo2Circuit::<Fr, FibonacciCircuit<Fr>>::new::<ProvingBackend>(k, circuit.clone());
        (circuit.circuit_info().unwrap(), circuit)
    };
    let (circuit_info, _) = circuit_fn(4usize);

    let (prover_parameters, verifier_parameters) =
        ProvingBackend::preprocess(&param, &circuit_info).unwrap();

    let pk_path = out_dir.join("hyperplonk_fibonacci_pk.bin");
    let _ = save_to_file::<_, HyperPlonkProverParam<Fr, GeminiKzg>>(&pk_path, &prover_parameters);
    let vk_path = out_dir.join("hyperplonk_fibonacci_vk.bin");
    let _ =
        save_to_file::<_, HyperPlonkVerifierParam<Fr, GeminiKzg>>(&vk_path, &verifier_parameters);

    println!("Preparation finished successfully.");
    println!("SRS readed from {}", srs_path.display());
    println!("Proving key stored in {}", pk_path.display());
    println!("Verification key stored in {}", vk_path.display());
}
