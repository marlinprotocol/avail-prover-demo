use crate::model;
use ethers::signers::{LocalWallet, Signer};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Error, Value};
use snarkvm::{
    circuit::{AleoTestnetV0, AleoV0},
    ledger::query::Query,
    ledger::store::helpers::memory::BlockMemory,
    ledger::store::BlockStore,
    prelude::{Authorization, Execution, Locator, MainnetV0, Process, Program, TestnetV0},
};
use std::{fs, str::FromStr, time::Instant};

pub struct GenerateProofResponse {
    pub input: Option<ethers::types::Bytes>,
    pub execution: Option<ethers::types::Bytes>,
    #[allow(unused)]
    pub verification_status: bool,
    pub signature: Option<String>,
}

#[derive(Serialize, Debug, Deserialize, Clone)]
pub struct PrivateInputsTestnet {
    pub auth: Authorization<TestnetV0>,
    pub fee_auth: Authorization<TestnetV0>,
}

#[derive(Serialize, Debug, Deserialize, Clone)]
pub struct PrivateInputsMainnet {
    pub auth: Authorization<MainnetV0>,
    pub fee_auth: Authorization<MainnetV0>,
}

pub struct BenchmarkResponse {
    pub proof_generation_time: u128,
}

pub fn prove_benchmark(
    auth: Authorization<TestnetV0>,
) -> Result<BenchmarkResponse, model::InputError> {
    let rng = &mut thread_rng();
    log::info!("Setup for proof generation started...");
    let setup_now = Instant::now();

    // Defining a simple hello program with only a hello function
    let program_path = "./app/credits.txt".to_string();
    let alt_program_path = "../app/credits.txt".to_string();
    let file_content =
        fs::read_to_string(program_path).or_else(|_| fs::read_to_string(alt_program_path));
    if file_content.is_err() {
        log::error!("{:#?}", file_content.err());
        return Err(model::InputError::FileNotFound);
    }
    let test_program = file_content.unwrap();
    let program = Program::from_str(&test_program).unwrap();

    // initializing a new process
    let mut process: Process<TestnetV0> = Process::load().unwrap();
    process.add_program(&program).unwrap();

    // Check if program was added correctly
    let check_program = process.contains_program(program.id());
    assert!(check_program);

    let authorization = auth.clone().transitions();

    let program_id = authorization.last().unwrap().1.program_id();
    let function = authorization.last().unwrap().1.function_name();
    log::info!(
        "Executing function {:?} from program {:?}",
        function,
        program_id
    );

    log::info!("Setup time: {:?}ms", setup_now.elapsed().as_millis());
    log::info!("Execution started...");
    let execute_now = Instant::now();

    let (_result, mut trace) = process
        .execute::<AleoTestnetV0, _>(auth.clone(), rng)
        .unwrap();

    let execute_time = execute_now.elapsed();
    log::info!("Execution time: {:?}ms", execute_time.as_millis());
    log::info!("Proof generation started...");
    let prove_now = Instant::now();

    let locator = Locator::new(*program_id, *function);
    let block_store = BlockStore::<TestnetV0, BlockMemory<_>>::open(None).unwrap();
    trace.prepare(Query::from(block_store)).unwrap();
    let prove_result = trace.prove_execution::<AleoTestnetV0, _>(&locator.to_string(), rng);

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
            Ok(execution_response)
        }
        Err(e) => {
            log::error!("Benchmarking error: {:?}", e);
            Err(model::InputError::ExecutionFailed)
        }
    }
}

pub async fn prove_auth_mainnet(
    payload: kalypso_generator_models::models::InputPayload,
) -> Result<GenerateProofResponse, model::InputError> {
    let rng = &mut thread_rng();
    type CurrentNetwork = MainnetV0;
    type CurrentAleo = AleoV0;

    let read_secp_private_key = fs::read("./app/secp.sec").unwrap();
    let secp_private_key = secp256k1::SecretKey::from_slice(&read_secp_private_key)
        .unwrap()
        .display_secret()
        .to_string();
    let signer_wallet = secp_private_key.parse::<LocalWallet>().unwrap();

    // Loading credits program
    let multi_program_path = "./app/credits.txt".to_string();
    let alt_multi_program_path = "../app/credits.txt".to_string();
    let file_content = fs::read_to_string(multi_program_path)
        .or_else(|_| fs::read_to_string(alt_multi_program_path));
    if file_content.is_err() {
        log::error!("{:#?}", file_content.err());
        return Err(model::InputError::FileNotFound);
    }
    let test_program = file_content.unwrap();
    let program = Program::from_str(&test_program).unwrap();

    // initializing a new process
    let mut process = Process::<CurrentNetwork>::load().unwrap();
    process.add_program(&program).unwrap();

    // Check if program was added correctly
    let check_program = process.contains_program(program.id());
    assert!(check_program);

    let private_inputs = payload.clone().secrets.unwrap();
    let secrets = String::from_utf8(private_inputs).unwrap();
    let value: Value = serde_json::from_str(&secrets).unwrap();
    let public_inputs = payload.public;

    let private_input_structure: Result<PrivateInputsMainnet, Error> =
        serde_json::from_value(value);

    let private_input = private_input_structure.unwrap();
    let fee_auth = private_input.fee_auth;
    let auth = private_input.auth;
    let auth_transitions = auth.clone().transitions();

    let function = auth_transitions.last().unwrap().1.function_name();
    let program_id = auth_transitions.last().unwrap().1.program_id();

    log::info!(
        "Executing function {:?} from program {:?}",
        function,
        program_id
    );

    log::info!("Execution started...");
    let execute_now = Instant::now();

    // execute authorization
    let (_result, mut trace) = process
        .execute::<CurrentAleo, _>(auth.clone(), rng)
        .unwrap();

    // execute fee authorization
    let (_fee_result, mut fee_trace) = process
        .execute::<CurrentAleo, _>(fee_auth.clone(), rng)
        .unwrap();

    let execute_time = execute_now.elapsed();
    log::info!("Execution time: {:?}ms", execute_time.as_millis());
    log::info!("Proof generation started...");
    let prove_now = Instant::now();

    let locator = Locator::new(*program_id, *function);
    let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(None).unwrap();
    trace.prepare(Query::from(block_store.clone())).unwrap();
    fee_trace.prepare(Query::from(block_store.clone())).unwrap();
    let prove_result = trace.prove_execution::<CurrentAleo, _>(&locator.to_string(), rng);

    match prove_result {
        Ok(prove) => {
            let fee_prove_result = fee_trace.prove_fee::<CurrentAleo, _>(rng);
            // log::info!("Execution: {:?}", prove.clone());
            match fee_prove_result {
                Ok(fee) => {
                    // log::info!("Fee: {:?}", fee.clone());
                    let prove_time = prove_now.elapsed();
                    log::info!("Proof generation time: {:?}ms", prove_time.as_millis());
                    process.verify_execution(&prove).unwrap();
                    log::info!("Proof verification status : {:?}", true);
                    let deployment_or_execution_id =
                        fee.clone().deployment_or_execution_id().unwrap();
                    process
                        .verify_fee(&fee, deployment_or_execution_id)
                        .unwrap();
                    log::info!("Fee verification status: {:?}", true);

                    let execution_and_fee = json!({
                        "execution": prove.clone(),
                        "fee": fee.clone()
                    });
                    // log::info!("Execution and fee: {:?}", execution_and_fee);

                    let value = vec![
                        ethers::abi::Token::Bytes(public_inputs.to_vec()),
                        ethers::abi::Token::Bytes(
                            execution_and_fee.to_string().as_bytes().to_vec(),
                        ),
                    ];
                    let encoded = ethers::abi::encode(&value);
                    let digest = ethers::utils::keccak256(encoded);

                    let signature = signer_wallet
                        .sign_message(ethers::types::H256(digest))
                        .await
                        .unwrap();

                    let execution_response = GenerateProofResponse {
                        input: Some(ethers::types::Bytes::from(public_inputs.to_vec())),
                        execution: Some(ethers::types::Bytes::from(
                            execution_and_fee.to_string().as_bytes().to_vec(),
                        )),
                        verification_status: true,
                        signature: Some("0x".to_owned() + &signature.to_string()),
                    };

                    Ok(execution_response)
                }
                Err(e) => {
                    println!("Error: {:?}", e);
                    let execution_response = GenerateProofResponse {
                        input: Some(public_inputs.into()),
                        execution: None,
                        verification_status: false,
                        signature: None,
                    };
                    Ok(execution_response)
                }
            }
        }
        Err(e) => {
            println!("Error: {:?}", e);
            let execution_response = GenerateProofResponse {
                input: Some(public_inputs.into()),
                execution: None,
                verification_status: false,
                signature: None,
            };
            Ok(execution_response)
        }
    }
}

pub async fn prove_auth_testnet(
    payload: kalypso_generator_models::models::InputPayload,
) -> Result<GenerateProofResponse, model::InputError> {
    let rng = &mut thread_rng();
    type CurrentNetwork = TestnetV0;
    type CurrentAleo = AleoTestnetV0;

    let read_secp_private_key = fs::read("./app/secp.sec").unwrap();
    let secp_private_key = secp256k1::SecretKey::from_slice(&read_secp_private_key)
        .unwrap()
        .display_secret()
        .to_string();
    let signer_wallet = secp_private_key.parse::<LocalWallet>().unwrap();

    // Loading credits program
    let multi_program_path = "./app/credits.txt".to_string();
    let alt_multi_program_path = "../app/credits.txt".to_string();
    let file_content = fs::read_to_string(multi_program_path)
        .or_else(|_| fs::read_to_string(alt_multi_program_path));
    if file_content.is_err() {
        log::error!("{:#?}", file_content.err());
        return Err(model::InputError::FileNotFound);
    }
    let test_program = file_content.unwrap();
    let program = Program::from_str(&test_program).unwrap();

    // initializing a new process
    let mut process = Process::<CurrentNetwork>::load().unwrap();
    process.add_program(&program).unwrap();

    // Check if program was added correctly
    let check_program = process.contains_program(program.id());
    assert!(check_program);

    let private_inputs = payload.clone().secrets.unwrap();
    let secrets = String::from_utf8(private_inputs).unwrap();
    let value: Value = serde_json::from_str(&secrets).unwrap();
    let public_inputs = payload.public;
    let private_input_structure: Result<PrivateInputsTestnet, Error> =
        serde_json::from_value(value);

    let private_input = private_input_structure.unwrap();
    let fee_auth = private_input.fee_auth;
    let auth = private_input.auth;
    let auth_transitions = auth.clone().transitions();

    let function = auth_transitions.last().unwrap().1.function_name();
    let program_id = auth_transitions.last().unwrap().1.program_id();

    log::info!(
        "Executing function {:?} from program {:?}",
        function,
        program_id
    );

    log::info!("Execution started...");
    let execute_now = Instant::now();

    // execute authorization
    let (_result, mut trace) = process
        .execute::<CurrentAleo, _>(auth.clone(), rng)
        .unwrap();

    // execute fee authorization
    let (_fee_result, mut fee_trace) = process
        .execute::<CurrentAleo, _>(fee_auth.clone(), rng)
        .unwrap();

    let execute_time = execute_now.elapsed();
    log::info!("Execution time: {:?}ms", execute_time.as_millis());
    log::info!("Proof generation started...");
    let prove_now = Instant::now();

    let locator = Locator::new(*program_id, *function);
    let block_store = BlockStore::<CurrentNetwork, BlockMemory<_>>::open(None).unwrap();
    trace.prepare(Query::from(block_store.clone())).unwrap();
    fee_trace.prepare(Query::from(block_store.clone())).unwrap();
    let prove_result = trace.prove_execution::<CurrentAleo, _>(&locator.to_string(), rng);

    match prove_result {
        Ok(prove) => {
            let fee_prove_result = fee_trace.prove_fee::<CurrentAleo, _>(rng);
            // log::info!("Execution: {:?}", prove.clone());
            match fee_prove_result {
                Ok(fee) => {
                    // log::info!("Fee: {:?}", fee.clone());
                    let prove_time = prove_now.elapsed();
                    log::info!("Proof generation time: {:?}ms", prove_time.as_millis());
                    process.verify_execution(&prove).unwrap();
                    log::info!("Proof verification status : {:?}", true);
                    let deployment_or_execution_id =
                        fee.clone().deployment_or_execution_id().unwrap();
                    process
                        .verify_fee(&fee, deployment_or_execution_id)
                        .unwrap();
                    log::info!("Fee verification status: {:?}", true);

                    let execution_and_fee = json!({
                        "execution": prove.clone(),
                        "fee": fee.clone()
                    });
                    // log::info!("Execution and fee: {:?}", execution_and_fee);

                    let value = vec![
                        ethers::abi::Token::Bytes(public_inputs.to_vec()),
                        ethers::abi::Token::Bytes(
                            execution_and_fee.to_string().as_bytes().to_vec(),
                        ),
                    ];
                    let encoded = ethers::abi::encode(&value);
                    let digest = ethers::utils::keccak256(encoded);

                    let signature = signer_wallet
                        .sign_message(ethers::types::H256(digest))
                        .await
                        .unwrap();

                    let execution_response = GenerateProofResponse {
                        input: Some(ethers::types::Bytes::from(public_inputs.to_vec())),
                        execution: Some(ethers::types::Bytes::from(
                            execution_and_fee.to_string().as_bytes().to_vec(),
                        )),
                        verification_status: true,
                        signature: Some("0x".to_owned() + &signature.to_string()),
                    };

                    Ok(execution_response)
                }
                Err(e) => {
                    println!("Error: {:?}", e);
                    let execution_response = GenerateProofResponse {
                        input: Some(public_inputs.clone().into()),
                        execution: None,
                        verification_status: false,
                        signature: None,
                    };
                    Ok(execution_response)
                }
            }
        }
        Err(e) => {
            println!("Error: {:?}", e);
            let execution_response = GenerateProofResponse {
                input: Some(public_inputs.clone().into()),
                execution: None,
                verification_status: false,
                signature: None,
            };
            Ok(execution_response)
        }
    }
}

pub async fn verify_execution_proof_testnet(
    payload: Execution<TestnetV0>,
) -> Result<bool, model::InputError> {
    let rng = &mut thread_rng();
    type CurrentNetwork = TestnetV0;
    type CurrentAleo = AleoTestnetV0;
    // Loading credits program
    let multi_program_path = "./app/credits.txt".to_string();
    let alt_multi_program_path = "../app/credits.txt".to_string();
    let file_content = fs::read_to_string(multi_program_path)
        .or_else(|_| fs::read_to_string(alt_multi_program_path));
    if file_content.is_err() {
        log::error!("{:#?}", file_content.err());
        return Err(model::InputError::FileNotFound);
    }
    let test_program = file_content.unwrap();
    let program = Program::from_str(&test_program).unwrap();

    // initializing a new process
    let mut process = Process::<CurrentNetwork>::load().unwrap();
    process.add_program(&program).unwrap();

    // Check if program was added correctly
    let check_program = process.contains_program(program.id());
    assert!(check_program);

    let execution = payload.clone();

    let exec_transitions: Vec<_> = execution.transitions().collect();
    let function_name = exec_transitions.clone().last().unwrap().function_name();
    let program_id = exec_transitions.clone().last().unwrap().program_id();

    let _ = process.synthesize_key::<CurrentAleo, _>(program_id, function_name, rng);

    let verification = process.verify_execution(&payload);
    log::info!("Verifiction result: {:?}", verification);

    match verification {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

pub async fn verify_execution_proof_mainnet(
    payload: Execution<MainnetV0>,
) -> Result<bool, model::InputError> {
    let rng = &mut thread_rng();
    type CurrentNetwork = MainnetV0;
    type CurrentAleo = AleoV0;
    // Loading credits program
    let multi_program_path = "./app/credits.txt".to_string();
    let alt_multi_program_path = "../app/credits.txt".to_string();
    let file_content = fs::read_to_string(multi_program_path)
        .or_else(|_| fs::read_to_string(alt_multi_program_path));
    if file_content.is_err() {
        log::error!("{:#?}", file_content.err());
        return Err(model::InputError::FileNotFound);
    }
    let test_program = file_content.unwrap();
    let program = Program::from_str(&test_program).unwrap();

    // initializing a new process
    let mut process = Process::<CurrentNetwork>::load().unwrap();
    process.add_program(&program).unwrap();

    // Check if program was added correctly
    let check_program = process.contains_program(program.id());
    assert!(check_program);

    let execution = payload.clone();

    let exec_transitions: Vec<_> = execution.transitions().collect();
    let function_name = exec_transitions.clone().last().unwrap().function_name();
    let program_id = exec_transitions.clone().last().unwrap().program_id();

    let _ = process.synthesize_key::<CurrentAleo, _>(program_id, function_name, rng);

    let verification = process.verify_execution(&payload);
    log::info!("Verifiction result: {:?}", verification);

    match verification {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

// async fn invalid_input_response(ask_id: u64, public_inputs: Bytes) -> GenerateProofResponse {
//     log::info!("Invalid inputs received for ask ID : {}", ask_id);
//     let read_secp_private_key = fs::read("./app/secp.sec").unwrap();
//     let secp_private_key = secp256k1::SecretKey::from_slice(&read_secp_private_key)
//         .unwrap()
//         .display_secret()
//         .to_string();
//     let signer_wallet = secp_private_key.parse::<LocalWallet>().unwrap();

//     let value = vec![
//         ethers::abi::Token::Uint(ask_id.into()),
//         ethers::abi::Token::Bytes(public_inputs.to_vec()),
//     ];
//     let encoded = ethers::abi::encode(&value);
//     let digest = ethers::utils::keccak256(encoded);

//     let signature = signer_wallet
//         .sign_message(ethers::types::H256(digest))
//         .await
//         .unwrap();

//     GenerateProofResponse {
//         input: Some(public_inputs.clone()),
//         execution: None,
//         verification_status: false,
//         signature: Some("0x".to_owned() + &signature.to_string()),
//     }
// }
