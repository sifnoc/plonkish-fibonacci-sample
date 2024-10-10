use std::{collections::HashMap, error::Error, fs::File};

use fibonacci_circuit::{serialisation::*, FibonacciCircuit, FibonacciError, GenerateProofResult};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{create_proof, verify_proof, ProvingKey, VerifyingKey},
    poly::{
        commitment::Params,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
    SerdeFormat::RawBytes,
};
use rand::rngs::OsRng;

fn generate_halo2_proof(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: FibonacciCircuit<Fr>,
    public_inputs: Vec<Fr>,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    let _result = create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        _,
        false,
    >(
        &params,
        &pk,
        &[circuit],
        &[&[&public_inputs]],
        OsRng,
        &mut transcript,
    )
    .expect("prover should not fail");

    let proof = transcript.finalize();
    let serialized_inputs = bincode::serialize(&InputsSerialisationWrapper(public_inputs))
        .map_err(|e| FibonacciError(format!("Serialisation of Inputs failed: {}", e)))?;

    Ok((proof, serialized_inputs))
}

fn verify_halo2_proof(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    proof: Vec<u8>,
    public_inputs: Vec<u8>,
) -> Result<bool, Box<dyn Error>> {
    let strategy = SingleStrategy::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

    let deserialized_inputs: Vec<Fr> =
        bincode::deserialize::<InputsSerialisationWrapper>(&public_inputs)
            .map_err(|e| FibonacciError(e.to_string()))?
            .0;

    let result = verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
        false,
    >(
        &params,
        &vk,
        strategy,
        &[&[&deserialized_inputs]],
        &mut transcript,
    )
    .is_ok();

    Ok(result)
}

pub fn prove(
    srs_key_path: &str,
    proving_key_path: &str,
    input: HashMap<String, Vec<String>>,
) -> Result<GenerateProofResult, Box<dyn Error>> {
    let mut param_fs =
        File::open(srs_key_path).expect(&format!("Couldn't load params from '{}'", srs_key_path));
    let params = ParamsKZG::<Bn256>::read(&mut param_fs)
        .expect(&format!("Failed to read params from '{}'", srs_key_path));

    let circuit = FibonacciCircuit::<Fr>::default();

    let pk_fs = &mut File::open(proving_key_path).expect("Couldn't load proving key form");
    let proving_key = ProvingKey::read::<_, FibonacciCircuit<Fr>, false>(pk_fs, RawBytes).unwrap();

    let circuit_inputs = deserialize_circuit_inputs(input)
        .map_err(|e| FibonacciError(format!("Failed to deserialize circuit inputs: {}", e)))?;

    let out = circuit_inputs
        .get("out")
        .ok_or(FibonacciError("Failed to get `out` value".to_string()))?
        .get(0)
        .ok_or(FibonacciError("Failed to get `out` value".to_string()))?
        .clone();

    // The public input followed fibonacci circuit
    let public_input = vec![Fr::from(1), Fr::from(1), out];

    let (proof, serialized_inputs) =
        generate_halo2_proof(&params, &proving_key, circuit, public_input).unwrap();

    Ok((proof, serialized_inputs))
}

pub fn verify(
    srs_key_path: &str,
    verifying_key_path: &str,
    proof: Vec<u8>,
    public_inputs: Vec<u8>,
) -> Result<bool, Box<dyn Error>> {
    let mut param_fs =
        File::open(srs_key_path).expect(&format!("Couldn't load params from '{}'", srs_key_path));
    let params = ParamsKZG::<Bn256>::read(&mut param_fs)
        .expect(&format!("Failed to read params from '{}'", srs_key_path));

    let vk_fs = &mut File::open(verifying_key_path).expect("Couldn't load proving key form");
    let verifying_key =
        VerifyingKey::read::<_, FibonacciCircuit<Fr>, false>(vk_fs, RawBytes).unwrap();

    let result = verify_halo2_proof(&params, &verifying_key, proof, public_inputs).unwrap();

    Ok(result)
}

#[cfg(test)]
mod tests {
    use halo2_proofs::plonk::{keygen_pk, keygen_vk};

    use super::*;

    fn initialize_params_and_circuit() -> (FibonacciCircuit<Fr>, ParamsKZG<Bn256>) {
        let params = ParamsKZG::<Bn256>::setup(4, OsRng);

        let circuit = FibonacciCircuit::<Fr>::default();

        (circuit, params)
    }

    fn generate_and_verify_proof(public_inputs: Vec<Fr>) -> bool {
        let (circuit, params) = initialize_params_and_circuit();

        let verifying_key = keygen_vk::<_, _, _, false>(&params, &circuit)
            .expect("Verifying Key generation should not fail");
        let proving_key = keygen_pk::<_, _, _, false>(&params, verifying_key.clone(), &circuit)
            .expect("Proving Key generation should not fail");

        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            _,
            false,
        >(
            &params,
            &proving_key,
            &[circuit.clone()],
            &[&[&public_inputs]],
            OsRng,
            &mut transcript,
        )
        .expect("prover should not fail");

        let proof = transcript.finalize();

        // Verifying Proof
        let strategy = SingleStrategy::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

        verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
            false,
        >(
            &params,
            &verifying_key,
            strategy,
            &[&[&public_inputs]],
            &mut transcript,
        )
        .is_ok()
    }

    #[test]
    fn test_fibonacci_circuit() {
        let public_inputs = vec![Fr::from(1), Fr::from(1), Fr::from(55)];
        let valid_result = generate_and_verify_proof(public_inputs);

        assert_eq!(valid_result, true);

        // Ensures verification fails with incorrect public input
        let wrong_public_inputs = vec![Fr::from(1), Fr::from(1), Fr::from(56)];
        let invalid_result = generate_and_verify_proof(wrong_public_inputs);

        assert_eq!(invalid_result, false)
    }

    #[test]
    fn test_helper_functions() {
        // Initialize circuit with zero values
        let (circuit, params) = initialize_params_and_circuit();

        let verifying_key = keygen_vk::<_, _, _, false>(&params, &circuit)
            .expect("Verifying Key generation should not fail");
        let proving_key = keygen_pk::<_, _, _, false>(&params, verifying_key.clone(), &circuit)
            .expect("Proving Key generation should not fail");

        let public_input = vec![Fr::from(1), Fr::from(1), Fr::from(55)];

        let (proof, serialized_input) =
            generate_halo2_proof(&params, &proving_key, circuit.clone(), public_input).unwrap();

        assert_eq!(
            verify_halo2_proof(&params, &verifying_key, proof, serialized_input).unwrap(),
            true
        );

        // Ensures verification fails with incorrect public input
        let wrong_public_input = vec![Fr::from(1), Fr::from(1), Fr::from(56)];
        let (bad_proof, serialized_input) =
            generate_halo2_proof(&params, &proving_key, circuit, wrong_public_input).unwrap();

        assert_eq!(
            verify_halo2_proof(&params, &verifying_key, bad_proof, serialized_input).unwrap(),
            false
        );
    }
}
