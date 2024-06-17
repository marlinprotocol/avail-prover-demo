use crate::model;
use aleo_rust::{
    snarkvm_types::{PrivateKey, Process, Program, Testnet3},
    AleoV0, BlockMemory, BlockStore, Identifier, Locator, Query,
};
use ethers::signers::{LocalWallet, Signer};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use rand::thread_rng;
use secp256k1;
use std::{fs, str::FromStr, time::Instant};

pub struct GenerateProofResponse {
    pub input: Option<ethers::types::Bytes>,
    pub proof: Option<ethers::types::Bytes>,
    pub verification_status: bool,
    pub signature: Option<String>,
}

pub struct BenchmarkResponse {
    pub proof_generation_time: u128,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecretInputs {
    pub private: String,
    pub address: String,
    pub amount: String
}

pub fn prove_authorization(private_key: String) -> Result<BenchmarkResponse, model::InputError> {
    let rng = &mut thread_rng();
    let pkey = PrivateKey::<Testnet3>::from_str(&private_key).unwrap();

    log::info!("Setup for proof generation started...");
    let setup_now = Instant::now();

    // Defining a simple hello program with only a hello function
    let program_path = "./app/test_hello.txt".to_string();
    let alt_program_path = "../app/test_hello.txt".to_string();
    let file_content =
        fs::read_to_string(program_path).or_else(|_| fs::read_to_string(alt_program_path));
    if file_content.is_err() {
        log::error!("{:#?}", file_content.err());
        return Err(model::InputError::FileNotFound);
    }
    let test_program = file_content.unwrap();
    let program = Program::from_str(&test_program).unwrap();

    // initializing a new process
    let mut process: Process<Testnet3> = Process::load().unwrap();
    process.add_program(&program).unwrap();

    // Check if program was added correctly
    let check_program = process.contains_program(program.id());
    assert!(check_program);

    let function = Identifier::<Testnet3>::try_from("hello").unwrap();
    let auth = process
        .authorize::<AleoV0, _>(
            &pkey,
            program.id(),
            function,
            ["3u32", "5u32"].into_iter(),
            rng,
        )
        .unwrap();

    log::info!("Setup time: {:?}ms", setup_now.elapsed().as_millis());

    log::info!("Execution started...");
    let execute_now = Instant::now();

    let (_result, mut trace) = process.execute::<AleoV0, _>(auth, rng).unwrap();

    let execute_time = execute_now.elapsed();

    log::info!("Execution time: {:?}ms", execute_time.as_millis());
    log::info!("Proof generation started...");
    let prove_now = Instant::now();

    let locator = Locator::new(*program.id(), function);
    let block_store = BlockStore::<Testnet3, BlockMemory<_>>::open(None).unwrap();
    trace.prepare(Query::from(block_store)).unwrap();
    let prove_result = trace.prove_execution::<AleoV0, _>(&locator.to_string(), rng);

    match prove_result {
        Ok(prove) => {
            let prove_time = prove_now.elapsed();
            log::info!("Proof generation time: {:?}ms", prove_time.as_millis());
            log::info!("Generated Proof: {:?}", prove.proof().unwrap());
            process.verify_execution(&prove).unwrap();
            log::info!("Proof verification status : {:?}", true);
            let execution_response = BenchmarkResponse {
                proof_generation_time: (execute_time + prove_time).as_millis(),
            };
            return Ok(execution_response);
        }
        Err(e) => {
            log::error!("Benchmarking error: {:?}", e);
            return Err(model::InputError::ExecutionFailed);
        }
    }
}

pub async fn prove_public(
    private_key: String,
    payload: model::ProverInputs,
) -> Result<GenerateProofResponse, model::InputError> {
    let rng = &mut thread_rng();
    let pkey = PrivateKey::<Testnet3>::from_str(&private_key).unwrap();
    let read_secp_private_key = fs::read("./app/secp.sec").unwrap();
    let secp_private_key = secp256k1::SecretKey::from_slice(&read_secp_private_key)
        .unwrap()
        .display_secret()
        .to_string();
    let signer_wallet = secp_private_key.parse::<LocalWallet>().unwrap();

    log::info!("Setup for proof generation started...");
    let setup_now = Instant::now();

    // Defining a complex program with 4 transitions
    let multi_program_path = "./app/multi_txn_t1.txt".to_string();
    let alt_multi_program_path = "../app/multi_txn_t1.txt".to_string();
    let file_content = fs::read_to_string(multi_program_path)
        .or_else(|_| fs::read_to_string(alt_multi_program_path));
    if file_content.is_err() {
        log::error!("{:#?}", file_content.err());
        return Err(model::InputError::FileNotFound);
    }
    let test_program = file_content.unwrap();
    let program = Program::from_str(&test_program).unwrap();

    let helper_program_path = "./app/helper.txt".to_string();
    let alt_helper_program_path = "../app/helper.txt".to_string();
    let file_content = fs::read_to_string(helper_program_path)
        .or_else(|_| fs::read_to_string(alt_helper_program_path));
    if file_content.is_err() {
        log::error!("{:#?}", file_content.err());
        return Err(model::InputError::FileNotFound);
    }
    let im_1 = file_content.unwrap();
    let im_program_1 = Program::from_str(&im_1).unwrap();

    let fees_program_path = "./app/fees.txt".to_string();
    let alt_fees_program_path = "../app/fees.txt".to_string();
    let file_content = fs::read_to_string(fees_program_path)
        .or_else(|_| fs::read_to_string(alt_fees_program_path));
    if file_content.is_err() {
        log::error!("{:#?}", file_content.err());
        return Err(model::InputError::FileNotFound);
    }
    let im_2 = file_content.unwrap();
    let im_program_2 = Program::from_str(&im_2).unwrap();

    // initializing a new process
    let mut process: Process<Testnet3> = Process::load().unwrap();
    process.add_program(&im_program_1).unwrap();
    process.add_program(&im_program_2).unwrap();
    process.add_program(&program).unwrap();

    // Check if program was added correctly
    let check_program = process.contains_program(program.id());
    assert!(check_program);

    let public_inputs = hex::encode(payload.ask.prover_data.clone());
    // log::info!("Public inputs: {:?}", public_inputs);
    let decoded_inputs = get_public_inputs_for_public_market(public_inputs.to_string()).unwrap();
    // log::info!("Received inputs: {:?}", decoded_inputs);

    let function = Identifier::<Testnet3>::try_from("transfer_public").unwrap();
    let auth = process
        .authorize::<AleoV0, _>(
            &pkey,
            program.id(),
            function,
            decoded_inputs.into_iter(),
            rng,
        )
        .unwrap();

    log::info!("Setup time: {:?}ms", setup_now.elapsed().as_millis());

    log::info!("Execution started...");
    let execute_now = Instant::now();

    let (_result, mut trace) = process.execute::<AleoV0, _>(auth.clone(), rng).unwrap();

    let execute_time = execute_now.elapsed();
    log::info!("Execution time: {:?}ms", execute_time.as_millis());
    log::info!("Proof generation started...");
    let prove_now = Instant::now();

    let locator = Locator::new(*program.id(), function);
    let block_store = BlockStore::<Testnet3, BlockMemory<_>>::open(None).unwrap();
    trace.prepare(Query::from(block_store)).unwrap();
    let prove_result = trace.prove_execution::<AleoV0, _>(&locator.to_string(), rng);

    let public_inputs = payload.ask.prover_data.clone();

    match prove_result {
        Ok(prove) => {
            let prove_time = prove_now.elapsed();
            log::info!("Proof generation time: {:?}ms", prove_time.as_millis());
            let proof: &aleo_rust::Proof<Testnet3> = prove.proof().unwrap();
            log::info!("Generated Proof: {:?}", proof.clone());
            process.verify_execution(&prove).unwrap();
            log::info!("Proof verification status : {:?}", true);
            
            let proof_string = proof.to_string();
            let proof_bytes = proof_string.as_bytes();
            let value = vec![
                ethers::abi::Token::Bytes(public_inputs.to_vec()),
                ethers::abi::Token::Bytes(proof_bytes.to_vec()),
            ];
            let encoded = ethers::abi::encode(&value);
            let digest = ethers::utils::keccak256(encoded);

            let signature = signer_wallet
                .sign_message(ethers::types::H256(digest))
                .await
                .unwrap();

            let execution_response = GenerateProofResponse {
                input: Some(payload.ask.prover_data.clone()),
                proof: Some(ethers::types::Bytes::from(proof_bytes.to_vec())),
                verification_status: true,
                signature: Some("0x".to_owned() + &signature.to_string()),
            };

            return Ok(execution_response);
        }
        Err(e) => {
            println!("Error: {:?}", e);
            let ask_id = payload.ask_id;
            let value = vec![
                ethers::abi::Token::Uint(ask_id.into()),
                ethers::abi::Token::Bytes(public_inputs.to_vec()),
            ];
            let encoded = ethers::abi::encode(&value);
            let digest = ethers::utils::keccak256(encoded);

            let signature = signer_wallet
                .sign_message(ethers::types::H256(digest))
                .await
                .unwrap();

            let execution_response = GenerateProofResponse {
                input: Some(payload.ask.prover_data.clone()),
                proof: None,
                verification_status: false,
                signature: Some("0x".to_owned() + &signature.to_string()),
            };
            return Ok(execution_response);
        }
    }
}

pub async fn prove_private(
    private_key: String,
    payload: model::ProverInputs,
) -> Result<GenerateProofResponse, model::InputError> {
    let rng = &mut thread_rng();
    let pkey = PrivateKey::<Testnet3>::from_str(&private_key).unwrap();
    let read_secp_private_key = fs::read("./app/secp.sec").unwrap();
    let secp_private_key = secp256k1::SecretKey::from_slice(&read_secp_private_key)
        .unwrap()
        .display_secret()
        .to_string();
    let signer_wallet = secp_private_key.parse::<LocalWallet>().unwrap();

    log::info!("Setup for proof generation started...");
    let setup_now = Instant::now();

    // Defining a complex program with 4 transitions
    let multi_program_path = "./app/multi_txn_t1.txt".to_string();
    let alt_multi_program_path = "../app/multi_txn_t1.txt".to_string();
    let file_content = fs::read_to_string(multi_program_path)
        .or_else(|_| fs::read_to_string(alt_multi_program_path));
    if file_content.is_err() {
        log::error!("{:#?}", file_content.err());
        return Err(model::InputError::FileNotFound);
    }
    let test_program = file_content.unwrap();
    let program = Program::from_str(&test_program).unwrap();

    let helper_program_path = "./app/helper.txt".to_string();
    let alt_helper_program_path = "../app/helper.txt".to_string();
    let file_content = fs::read_to_string(helper_program_path)
        .or_else(|_| fs::read_to_string(alt_helper_program_path));
    if file_content.is_err() {
        log::error!("{:#?}", file_content.err());
        return Err(model::InputError::FileNotFound);
    }
    let im_1 = file_content.unwrap();
    let im_program_1 = Program::from_str(&im_1).unwrap();

    let fees_program_path = "./app/fees.txt".to_string();
    let alt_fees_program_path = "../app/fees.txt".to_string();
    let file_content = fs::read_to_string(fees_program_path)
        .or_else(|_| fs::read_to_string(alt_fees_program_path));
    if file_content.is_err() {
        log::error!("{:#?}", file_content.err());
        return Err(model::InputError::FileNotFound);
    }
    let im_2 = file_content.unwrap();
    let im_program_2 = Program::from_str(&im_2).unwrap();

    // initializing a new process
    let mut process: Process<Testnet3> = Process::load().unwrap();
    process.add_program(&im_program_1).unwrap();
    process.add_program(&im_program_2).unwrap();
    process.add_program(&program).unwrap();

    // Check if program was added correctly
    let check_program = process.contains_program(program.id());
    assert!(check_program);

    let public_inputs = hex::encode(payload.ask.prover_data.clone());
    // log::info!("Public inputs: {:?}", public_inputs);
    let decoded_inputs = get_public_inputs_for_private_market(public_inputs.to_string()).unwrap();
    // log::info!("Received inputs: {:?}", decoded_inputs);

    let secrets = String::from_utf8(payload.private_input).unwrap();
    // log::info!("Secret inputs: {:?}", secrets);
    let value: Value = serde_json::from_str(&secrets).unwrap();
    let private_inputs: SecretInputs = serde_json::from_value(value).unwrap();

    let inputs = vec![private_inputs.address, private_inputs.amount, decoded_inputs[0].to_string()];
    // log::info!("Final inputs: {:?}", inputs);

    let function = Identifier::<Testnet3>::try_from("transfer_private").unwrap();
    let auth = process
        .authorize::<AleoV0, _>(
            &pkey,
            program.id(),
            function,
            inputs.into_iter(),
            rng,
        )
        .unwrap();

    log::info!("Setup time: {:?}ms", setup_now.elapsed().as_millis());

    log::info!("Execution started...");
    let execute_now = Instant::now();

    let (_result, mut trace) = process.execute::<AleoV0, _>(auth.clone(), rng).unwrap();

    let execute_time = execute_now.elapsed();
    log::info!("Execution time: {:?}ms", execute_time.as_millis());
    log::info!("Proof generation started...");
    let prove_now = Instant::now();

    let locator = Locator::new(*program.id(), function);
    let block_store = BlockStore::<Testnet3, BlockMemory<_>>::open(None).unwrap();
    trace.prepare(Query::from(block_store)).unwrap();
    let prove_result = trace.prove_execution::<AleoV0, _>(&locator.to_string(), rng);

    let public_inputs = payload.ask.prover_data.clone();

    match prove_result {
        Ok(prove) => {
            let prove_time = prove_now.elapsed();
            log::info!("Proof generation time: {:?}ms", prove_time.as_millis());
            let proof: &aleo_rust::Proof<Testnet3> = prove.proof().unwrap();
            log::info!("Generated Proof: {:?}", proof.clone());
            process.verify_execution(&prove).unwrap();
            log::info!("Proof verification status : {:?}", true);
            
            let proof_string = proof.to_string();
            let proof_bytes = proof_string.as_bytes();
            let value = vec![
                ethers::abi::Token::Bytes(public_inputs.to_vec()),
                ethers::abi::Token::Bytes(proof_bytes.to_vec()),
            ];
            let encoded = ethers::abi::encode(&value);
            let digest = ethers::utils::keccak256(encoded);

            let signature = signer_wallet
                .sign_message(ethers::types::H256(digest))
                .await
                .unwrap();

            let execution_response = GenerateProofResponse {
                input: Some(payload.ask.prover_data.clone()),
                proof: Some(ethers::types::Bytes::from(proof_bytes.to_vec())),
                verification_status: true,
                signature: Some("0x".to_owned() + &signature.to_string()),
            };

            return Ok(execution_response);
        }
        Err(e) => {
            println!("Error: {:?}", e);
            let ask_id = payload.ask_id;
            let value = vec![
                ethers::abi::Token::Uint(ask_id.into()),
                ethers::abi::Token::Bytes(public_inputs.to_vec()),
            ];
            let encoded = ethers::abi::encode(&value);
            let digest = ethers::utils::keccak256(encoded);

            let signature = signer_wallet
                .sign_message(ethers::types::H256(digest))
                .await
                .unwrap();

            let execution_response = GenerateProofResponse {
                input: Some(payload.ask.prover_data.clone()),
                proof: None,
                verification_status: false,
                signature: Some("0x".to_owned() + &signature.to_string()),
            };
            return Ok(execution_response);
        }
    }
}

fn get_public_inputs_for_public_market(decoded_pub_input: String) -> Result<Vec<String>, model::InputError> {
    use ethers::abi::{decode, ParamType};
    use ethers::prelude::*;

    fn decode_input(encoded_input: Bytes) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let param_types = vec![ParamType::FixedArray(Box::new(ParamType::String), 3)];
        let tokens = decode(&param_types, &encoded_input.0)?;

        if let Some(ethers::abi::Token::FixedArray(arr)) = tokens.first() {
            if arr.len() == 3 {
                let mut output = vec!["".to_string(); 3];
                for (i, token) in arr.iter().enumerate() {
                    if let ethers::abi::Token::String(u) = token {
                        output[i] = String::from(u);
                    } else {
                        return Err("Expected a U256 inside the FixedArray".into());
                    }
                }
                Ok(output)
            } else {
                Err("Unexpected number of decoded tokens inside the FixedArray".into())
            }
        } else {
            Err("Unexpected decoded token type".into())
        }
    }

    let decoded_pub_input_bytes = hex::decode(decoded_pub_input).unwrap();
    let public = decode_input(decoded_pub_input_bytes.into()).unwrap();

    let pub_input = serde_json::from_value(public.into()).unwrap();

    Ok(pub_input)
}

fn get_public_inputs_for_private_market(decoded_pub_input: String) -> Result<Vec<String>, model::InputError> {
    use ethers::abi::{decode, ParamType};
    use ethers::prelude::*;

    fn decode_input(encoded_input: Bytes) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let param_types = vec![ParamType::FixedArray(Box::new(ParamType::String), 1)];
        let tokens = decode(&param_types, &encoded_input.0)?;

        if let Some(ethers::abi::Token::FixedArray(arr)) = tokens.first() {
            if arr.len() == 1 {
                let mut output = vec!["".to_string(); 1];
                for (i, token) in arr.iter().enumerate() {
                    if let ethers::abi::Token::String(u) = token {
                        output[i] = String::from(u);
                    } else {
                        return Err("Expected a U256 inside the FixedArray".into());
                    }
                }
                Ok(output)
            } else {
                Err("Unexpected number of decoded tokens inside the FixedArray".into())
            }
        } else {
            Err("Unexpected decoded token type".into())
        }
    }

    let decoded_pub_input_bytes = hex::decode(decoded_pub_input).unwrap();
    let public = decode_input(decoded_pub_input_bytes.into()).unwrap();

    let pub_input = serde_json::from_value(public.into()).unwrap();

    Ok(pub_input)
}
