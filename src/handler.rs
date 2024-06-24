use actix_web::{get, http::StatusCode, post, web, Responder};
use aleo_rust::Testnet3;
use snarkvm_synthesizer::Authorization;
use serde_json::{Value, Error};
use std::{fs, str::FromStr};

use crate::{model, prover, response::response};

// Get generator status from the supervisord
#[get("/test")]
async fn test() -> impl Responder {
    response("The Avail prover is running!!", StatusCode::OK, None)
}

#[get("/benchmark")]
async fn benchmark() -> impl Responder {
    // Fetch authorization
    let auth_path = "./app/auth_test.txt".to_string();
    let alt_auth_path = "../app/auth_test.txt".to_string();
    let file_content = fs::read_to_string(auth_path)
        .or_else(|_| fs::read_to_string(alt_auth_path));

    if file_content.is_err() {
        log::error!("{:#?}", file_content.err());
        return Err(model::InputError::FileNotFound);
    }

    let auth_value: Value = serde_json::from_str(&file_content.unwrap()).unwrap();
    let authorization_structure: Result<Authorization<Testnet3>, Error> = serde_json::from_value(auth_value);

    if authorization_structure.is_err() {
        log::error!("{:#?}", authorization_structure.err());
        return Err(model::InputError::InvalidInputs);
    }
    
    log::info!("Printing benchmarks for the avail prover");
    let benchmark_proof_generation = prover::prove_authorization(authorization_structure.unwrap());

    match benchmark_proof_generation {
        Ok(benchmarks) => {
            let proving_time = benchmarks.proof_generation_time.to_string();
            return Ok(response(
                "Proof generated, the proof generation time returned is in milliseconds",
                StatusCode::OK,
                Some(Value::String(proving_time)),
            ));
        }
        Err(e) => {
            response(
                "There was an issue benchmarking the proof generation time.",
                StatusCode::INTERNAL_SERVER_ERROR,
                None,
            );
            return Err(e);
        }
    }
}

#[post("/generateProof")]
async fn generate_proof(payload: web::Json<model::ProveAuthInputs>) -> impl Responder {
    log::info!(
        "Request received by the avail prover for ask ID : {}",
        payload.0.ask_id
    );

    let prove_result = prover::prove_auth(payload.0).await;

    match prove_result {
        Ok(prove) => {
            if prove.execution.is_some() {
                let public_inputs = prove.input.unwrap();
                let proof_bytes = prove.execution.unwrap();
                let signature = prove.signature.unwrap();
                let sig_bytes = ethers::types::Bytes::from_str(&signature).unwrap();
                let value = vec![
                    ethers::abi::Token::Bytes(public_inputs.to_vec()),
                    ethers::abi::Token::Bytes(proof_bytes.to_vec()),
                    ethers::abi::Token::Bytes(sig_bytes.to_vec()),
                ];
                let encoded = ethers::abi::encode(&value);
                let encoded_bytes: ethers::types::Bytes = encoded.into();
                return Ok(response(
                    "Proof generated",
                    StatusCode::OK,
                    Some(Value::String(encoded_bytes.to_string())),
                ));
            } else {
                let public_inputs = prove.input.unwrap();
                let signature = prove.signature.unwrap();
                let sig_bytes = ethers::types::Bytes::from_str(&signature).unwrap();
                let value = vec![
                    ethers::abi::Token::Bytes(public_inputs.to_vec()),
                    ethers::abi::Token::Bytes(sig_bytes.to_vec()),
                ];
                let encoded = ethers::abi::encode(&value);
                let encoded_bytes: ethers::types::Bytes = encoded.into();
                return Ok(response(
                    "Proof NOT generated",
                    StatusCode::BAD_REQUEST,
                    Some(Value::String(encoded_bytes.to_string())),
                ));
            }   
        }
        Err(e) => {
            response(
                "There was an issue while generating the proof.",
                StatusCode::INTERNAL_SERVER_ERROR,
                None,
            );
            return Err(e);
        }
    }
}

// Routes
pub fn routes(conf: &mut web::ServiceConfig) {
    let scope = web::scope("/api")
        .service(test)
        .service(benchmark)
        .service(generate_proof);
    conf.service(scope);
}
