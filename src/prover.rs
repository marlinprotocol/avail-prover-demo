use crate::model;
use aleo_rust::{
    snarkvm_types::{Process, Program, Testnet3},
    AleoV0, BlockMemory, BlockStore, Locator, Query
};
use snarkvm_synthesizer::Authorization;
use ethers::signers::{LocalWallet, Signer};
use serde_json::{Value, Error};
use rand::thread_rng;
use secp256k1;
use std::{fs, str::FromStr, time::Instant};

pub struct GenerateProofResponse {
    pub input: Option<ethers::types::Bytes>,
    pub execution: Option<ethers::types::Bytes>,
    pub verification_status: bool,
    pub signature: Option<String>,
}

pub struct BenchmarkResponse {
    pub proof_generation_time: u128,
}

pub fn prove_authorization(auth: Authorization<Testnet3>) -> Result<BenchmarkResponse, model::InputError> {
    let rng = &mut thread_rng();
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

    let authorization = auth.clone().transitions();

    let program_id = authorization.last().unwrap().1.program_id();
    let function = authorization.last().unwrap().1.function_name();
    log::info!("Executing function {:?} from program {:?}", function, program_id);

    log::info!("Setup time: {:?}ms", setup_now.elapsed().as_millis());
    log::info!("Execution started...");
    let execute_now = Instant::now();

    let (_result, mut trace) = process.execute::<AleoV0, _>(auth.clone(), rng).unwrap();

    let execute_time = execute_now.elapsed();
    log::info!("Execution time: {:?}ms", execute_time.as_millis());
    log::info!("Proof generation started...");
    let prove_now = Instant::now();

    let locator = Locator::new(*program_id, *function);
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

pub async fn prove_auth(
    payload: model::ProveAuthInputs
) -> Result<GenerateProofResponse, model::InputError> {
    let rng = &mut thread_rng();
    let read_secp_private_key = fs::read("./app/secp.sec").unwrap();
    let secp_private_key = secp256k1::SecretKey::from_slice(&read_secp_private_key)
        .unwrap()
        .display_secret()
        .to_string();
    let signer_wallet = secp_private_key.parse::<LocalWallet>().unwrap();

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

    let auth_input = payload.clone().private_input;
    let secrets = String::from_utf8(auth_input).unwrap();
    let value: Value = serde_json::from_str(&secrets).unwrap();
    let authorization_structure: Result<Authorization<Testnet3>, Error> = serde_json::from_value(value);
    if authorization_structure.is_err() {
        log::error!("{:#?}", authorization_structure.err());
        return Err(model::InputError::InvalidInputs);
    }
    let authorization = authorization_structure.unwrap();
    let auth_transitions = authorization.clone().transitions();

    let function = auth_transitions.last().unwrap().1.function_name();
    let program_id = auth_transitions.last().unwrap().1.program_id();
    log::info!("Executing function {:?} from program {:?}", function, program_id);

    log::info!("Execution started...");
    let execute_now = Instant::now();

    let (_result, mut trace) = process.execute::<AleoV0, _>(authorization.clone(), rng).unwrap();

    let execute_time = execute_now.elapsed();
    log::info!("Execution time: {:?}ms", execute_time.as_millis());
    log::info!("Proof generation started...");
    let prove_now = Instant::now();

    let locator = Locator::new(*program_id, *function);
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
                execution: Some(ethers::types::Bytes::from(prove.to_string().as_bytes().to_vec())),
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
                execution: None,
                verification_status: false,
                signature: Some("0x".to_owned() + &signature.to_string()),
            };
            return Ok(execution_response);
        }
    }
}