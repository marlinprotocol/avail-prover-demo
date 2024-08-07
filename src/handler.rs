use crate::{
    model::{self},
    prover,
};
use actix_web::web::Data;
use actix_web::{get, http::StatusCode, post, web, HttpResponse, Responder};
use ethers::{
    core::k256::ecdsa::SigningKey,
    signers::{LocalWallet, Signer, Wallet},
};
use kalypso_helper::response::response;
use serde_json::{Error, Value};
use snarkvm::prelude::{Authorization, Execution, MainnetV0, TestnetV0};
use std::sync::{Arc, Mutex};
use std::{fs, str::FromStr};

// Get generator status from the supervisord
#[get("/test")]
async fn test() -> impl Responder {
    response(
        "The Avail prover is running!!",
        StatusCode::OK,
        Some("Avail Prover is running!".into()),
    )
}

#[get("/benchmark")]
async fn benchmark() -> impl Responder {
    // Fetch authorization
    let auth_path = "./app/auth_test.txt".to_string();
    let alt_auth_path = "../app/auth_test.txt".to_string();
    let file_content = fs::read_to_string(auth_path).or_else(|_| fs::read_to_string(alt_auth_path));
    if file_content.is_err() {
        log::error!("{:#?}", file_content.err());
        return HttpResponse::BadRequest().json(
            kalypso_generator_models::models::BenchmarkResponse {
                data: model::InputError::FileNotFound.to_string(),
                time_in_ms: 0,
            },
        );
    }

    let auth_value: Value =
        serde_json::from_str(&file_content.expect("error reading file contents"))
            .expect("error create auth_value");
    let authorization_structure: Result<Authorization<TestnetV0>, Error> =
        serde_json::from_value(auth_value);

    if authorization_structure.is_err() {
        log::error!("{:#?}", authorization_structure.err());
        return HttpResponse::BadRequest().json(
            kalypso_generator_models::models::BenchmarkResponse {
                data: model::InputError::InvalidInputs.to_string(),
                time_in_ms: 0,
            },
        );
    }

    log::info!("Printing benchmarks for the avail prover");
    let benchmark_proof_generation = prover::prove_benchmark(
        authorization_structure.expect("error creating authorization structure"),
    );

    if benchmark_proof_generation.is_err() {
        return HttpResponse::ExpectationFailed().json(
            kalypso_generator_models::models::BenchmarkResponse {
                data: "Failed".to_string(),
                time_in_ms: 0,
            },
        );
    } else {
        return HttpResponse::Ok().json(kalypso_generator_models::models::BenchmarkResponse {
            data: "Success".to_string(),
            time_in_ms: benchmark_proof_generation.unwrap().proof_generation_time,
        });
    }
}

#[post("/generateProof")]
async fn generate_proof(
    payload: web::Json<kalypso_generator_models::models::InputPayload>,
) -> impl Responder {
    log::info!("Request received by the avail prover");

    let network = {
        let prover_data: ethers::types::Bytes = payload.clone().get_public().into();
        String::from_utf8(prover_data.0.to_vec()).unwrap()
    };

    let prove_result;
    if network.contains("1u16") {
        prove_result = prover::prove_auth_testnet(payload.0).await;
    } else if network.contains("0u16") {
        prove_result = prover::prove_auth_mainnet(payload.0).await;
    } else {
        return Ok(response(
            "Network not implemented",
            StatusCode::BAD_REQUEST,
            None,
        ));
    }

    match prove_result {
        Ok(prove) => {
            if prove.execution.is_some() && prove.signature.is_some() {
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
                return Ok(HttpResponse::Ok().json(
                    kalypso_generator_models::models::GenerateProofResponse {
                        proof: encoded.to_vec(),
                    },
                ));
            } else if prove.execution.is_none() && prove.signature.is_some() {
                let signature = prove.signature.unwrap();
                return Ok(response(
                    "Invalid inputs received, signature generated",
                    StatusCode::BAD_REQUEST,
                    Some(Value::String(signature)),
                ));
            } else {
                return Ok(response(
                    "There was an issue while generating the proof.",
                    StatusCode::INTERNAL_SERVER_ERROR,
                    None,
                ));
            }
        }
        Err(e) => Err(e),
    }
}

#[post("/checkInput")]
async fn check_input_handler(
    payload: web::Json<kalypso_generator_models::models::InputPayload>,
) -> impl Responder {
    let default_response = kalypso_ivs_models::models::CheckInputResponse { valid: false };
    let private_input = payload.clone().get_plain_secrets().unwrap();

    let public_input = payload.clone().get_public();
    let public_input_str = match std::str::from_utf8(&public_input) {
        Ok(data) => data,
        Err(_) => return HttpResponse::Ok().json(default_response),
    };

    let private_input_str = match std::str::from_utf8(&private_input) {
        Ok(data) => data,
        Err(_) => return HttpResponse::Ok().json(default_response),
    };

    let auth_value_pvt: Value = match serde_json::from_str(&private_input_str) {
        Ok(data) => data,
        Err(_) => return HttpResponse::Ok().json(default_response),
    };

    let auth = &auth_value_pvt["auth"];

    if public_input_str.contains("1u16") {
        let authorization_structure: Result<Authorization<TestnetV0>, Error> =
            serde_json::from_value(auth.clone());
        check_authorization_testnet(authorization_structure, None, None).await
    } else if public_input_str.contains("0u16") {
        let authorization_structure: Result<Authorization<MainnetV0>, Error> =
            serde_json::from_value(auth.clone());
        check_authorization_mainnet(authorization_structure, None, None).await
    } else {
        return HttpResponse::Ok()
            .json(kalypso_ivs_models::models::CheckInputResponse { valid: false });
    }
}

#[post("/getAttestationForInvalidInputs")]
async fn get_attestation_for_invalid_inputs(
    payload: web::Json<kalypso_ivs_models::models::InvalidInputPayload>,
    ecies_priv_key: Data<Arc<Mutex<Vec<u8>>>>,
) -> impl Responder {
    let ecies_priv_key = { ecies_priv_key.lock().unwrap().clone() };
    let signer_wallet = get_signer(ecies_priv_key);

    let private_input = match payload.clone().get_plain_secrets() {
        Ok(data) => data,
        Err(_) => {
            return HttpResponse::NotImplemented()
                .json(kalypso_ivs_models::models::CheckInputResponse { valid: false });
        }
    };

    let private_input_str = match std::str::from_utf8(&private_input) {
        Ok(data) => data,
        Err(_) => {
            return HttpResponse::BadRequest()
                .json(kalypso_ivs_models::models::CheckInputResponse { valid: false })
        }
    };

    let auth_value: Value = match serde_json::from_str(&private_input_str) {
        Ok(data) => data,
        Err(_) => {
            return HttpResponse::Ok()
                .json(generate_invalid_input_attestation(payload.0, signer_wallet).await);
        }
    };
    let network = &auth_value["network"];
    let auth = &auth_value["auth"];
    if network.to_string().contains("1u16") {
        let authorization_structure: Result<Authorization<TestnetV0>, Error> =
            serde_json::from_value(auth.clone());
        check_authorization_testnet(
            authorization_structure,
            Some(payload.0),
            Some(signer_wallet),
        )
        .await
    } else if network.to_string().contains("0u16") {
        let authorization_structure: Result<Authorization<MainnetV0>, Error> =
            serde_json::from_value(auth.clone());
        check_authorization_mainnet(
            authorization_structure,
            Some(payload.0),
            Some(signer_wallet),
        )
        .await
    } else {
        return HttpResponse::Ok()
            .json(generate_invalid_input_attestation(payload.0, signer_wallet).await);
    }
}

#[post("/checkEncryptedInputs")]
async fn check_encrypted_input(
    payload: web::Json<kalypso_ivs_models::models::EncryptedInputPayload>,
    ecies_priv_key: Data<Arc<Mutex<Vec<u8>>>>,
) -> impl Responder {
    let payload = payload.0;
    let (signature, ivs_pub_key) = {
        let message = &payload.market_id;
        let ecies_priv_key = { ecies_priv_key.lock().unwrap().clone() };
        let signer_wallet = get_signer(ecies_priv_key);
        let digest = ethers::utils::keccak256(message.as_bytes());

        let read_secp_pub_key = fs::read("./app/secp.pub").unwrap();
        let mut modified_secp_pub_key = vec![0x04];
        modified_secp_pub_key.extend_from_slice(&read_secp_pub_key);
        let signature = signer_wallet
            .sign_hash(ethers::types::H256(digest))
            .expect("Failed signing market id for check encrypted inputs");
        (signature.to_string(), modified_secp_pub_key)
    };
    let decrypt_request_payload = kalypso_matching_engine_models::models::DecryptRequest {
        market_id: payload.market_id.to_string(),
        private_input: hex::encode(payload.encrypted_secrets),
        acl: hex::encode(payload.acl),
        signature,
        ivs_pubkey: hex::encode(ivs_pub_key),
    };

    let client = reqwest::Client::new();
    let api_response = client
        .post(&payload.me_decryption_url)
        .json(&decrypt_request_payload)
        .send()
        .await
        .unwrap();

    if api_response.status().is_success() {
        let response_payload: kalypso_matching_engine_models::models::GetRequestResponse =
            match api_response.json().await {
                Ok(data) => data,
                Err(err) => {
                    dbg!(err);
                    return response(
                        "Unable to get response from matching engine",
                        StatusCode::EXPECTATION_FAILED,
                        None,
                    );
                }
            };

        let encrypted_data = hex::decode(response_payload.encrypted_data).unwrap();
        let ecies_priv_key = { ecies_priv_key.lock().unwrap().clone() };
        let decrypted_data =
            kalypso_helper::secret_inputs_helpers::decrypt_ecies(&ecies_priv_key, &encrypted_data)
                .unwrap();

        let decrypted_secret = String::from_utf8(decrypted_data).unwrap();
        let auth_value: Value = match serde_json::from_str(&decrypted_secret) {
            Ok(data) => data,
            Err(_) => {
                return HttpResponse::Ok()
                    .json(kalypso_ivs_models::models::CheckInputResponse { valid: false });
            }
        };

        let network = &auth_value["network"];
        let auth = &auth_value["auth"];

        if network.to_string().contains("1u16") {
            let authorization_structure: Result<Authorization<TestnetV0>, Error> =
                { serde_json::from_value(auth.clone()) };
            check_authorization_testnet(authorization_structure, None, None).await
        } else if network.to_string().contains("0u16") {
            let authorization_structure: Result<Authorization<MainnetV0>, Error> =
                { serde_json::from_value(auth.clone()) };
            check_authorization_mainnet(authorization_structure, None, None).await
        } else {
            return response("Network not implemented", StatusCode::BAD_REQUEST, None);
        }
    } else {
        response(
            "Could not fetch info from matching engine",
            StatusCode::FAILED_DEPENDENCY,
            None,
        )
    }
}

#[post("/verifyInputsAndProof")]
async fn verify_inputs_and_proof(
    payload: web::Json<kalypso_ivs_models::models::VerifyInputsAndProof>,
) -> impl Responder {
    let default_response = kalypso_ivs_models::models::VerifyInputAndProofResponse {
        is_input_and_proof_valid: false,
    };
    let proof = payload.clone().proof;

    let proof_str = match std::str::from_utf8(&proof) {
        Ok(data) => data,
        Err(_) => return HttpResponse::Ok().json(default_response),
    };

    let exec_value: Value = serde_json::from_str(&proof_str).unwrap();

    let public_input = match payload.clone().public_input {
        Some(data) => data,
        None => return HttpResponse::Ok().json(default_response),
    };

    let public_input_str = match std::str::from_utf8(&public_input) {
        Ok(data) => data,
        Err(_) => return HttpResponse::Ok().json(default_response),
    };

    let auth_value_pub: Value = serde_json::from_str(&public_input_str).unwrap();
    let network = &auth_value_pub["network"];

    if network.to_string().contains("1u16") {
        let execution_structure: Result<Execution<TestnetV0>, Error> =
            serde_json::from_value(exec_value.clone());

        match execution_structure {
            Ok(exec) => {
                let verification_result =
                    prover::verify_execution_proof_testnet(exec).await.unwrap();
                if verification_result {
                    let data = kalypso_ivs_models::models::VerifyInputAndProofResponse {
                        is_input_and_proof_valid: true,
                    };
                    return HttpResponse::Ok().json(data);
                } else {
                    let data = kalypso_ivs_models::models::VerifyInputAndProofResponse {
                        is_input_and_proof_valid: false,
                    };
                    return HttpResponse::Ok().json(data);
                }
            }
            Err(_) => {
                return response(
                    "The execution input structure is invalid",
                    StatusCode::BAD_REQUEST,
                    None,
                );
            }
        }
    } else if network.to_string().contains("0u16") {
        let execution_structure: Result<Execution<MainnetV0>, Error> =
            serde_json::from_value(exec_value.clone());

        match execution_structure {
            Ok(exec) => {
                let verification_result =
                    prover::verify_execution_proof_mainnet(exec).await.unwrap();
                if verification_result {
                    let data = kalypso_ivs_models::models::VerifyInputAndProofResponse {
                        is_input_and_proof_valid: true,
                    };
                    return HttpResponse::Ok().json(data);
                } else {
                    let data = kalypso_ivs_models::models::VerifyInputAndProofResponse {
                        is_input_and_proof_valid: false,
                    };
                    return HttpResponse::Ok().json(data);
                }
            }
            Err(_) => {
                return response(
                    "The execution input structure is invalid",
                    StatusCode::BAD_REQUEST,
                    None,
                );
            }
        }
    } else {
        return response("Network not implemented", StatusCode::BAD_REQUEST, None);
    }
}

// Routes
pub fn routes(conf: &mut web::ServiceConfig) {
    let scope = web::scope("/api")
        .service(test)
        .service(benchmark)
        .service(generate_proof)
        .service(check_input_handler)
        .service(get_attestation_for_invalid_inputs)
        .service(check_encrypted_input)
        .service(verify_inputs_and_proof);
    conf.service(scope);
}

async fn generate_invalid_input_attestation(
    payload: kalypso_ivs_models::models::InvalidInputPayload,
    signer_wallet: Wallet<SigningKey>,
) -> kalypso_generator_models::models::GenerateProofResponse {
    let ask_id = payload.only_ask_id();
    let value = vec![
        ethers::abi::Token::Uint(ask_id.into()),
        ethers::abi::Token::Bytes(payload.get_public()),
    ];
    let encoded = ethers::abi::encode(&value);
    let digest = ethers::utils::keccak256(encoded);

    let signature = signer_wallet
        .sign_message(ethers::types::H256(digest))
        .await
        .unwrap();

    let response = kalypso_generator_models::models::GenerateProofResponse {
        proof: signature.to_vec(),
    };

    return response;
}

fn get_signer(ecies_priv_key: Vec<u8>) -> Wallet<SigningKey> {
    let secp_private_key = secp256k1::SecretKey::from_slice(&ecies_priv_key)
        .unwrap()
        .display_secret()
        .to_string();
    secp_private_key.parse::<LocalWallet>().unwrap()
}

async fn check_authorization_testnet(
    authorization_structure: Result<Authorization<TestnetV0>, Error>,
    ask_payload: Option<kalypso_ivs_models::models::InvalidInputPayload>,
    signer_wallet: Option<Wallet<SigningKey>>,
) -> HttpResponse {
    let default_response = kalypso_ivs_models::models::CheckInputResponse { valid: false };
    match authorization_structure {
        Ok(auth) => {
            let is_auth_empty = auth.is_empty();

            if is_auth_empty {
                if ask_payload.is_some() && signer_wallet.is_some() {
                    return HttpResponse::Ok().json(
                        generate_invalid_input_attestation(
                            ask_payload.unwrap(),
                            signer_wallet.unwrap(),
                        )
                        .await,
                    );
                } else {
                    return HttpResponse::Ok().json(default_response);
                }
            } else {
                let data = kalypso_ivs_models::models::CheckInputResponse { valid: true };
                return HttpResponse::Ok().json(data);
            }
        }
        Err(_) => {
            return HttpResponse::Ok().json(default_response);
        }
    }
}

async fn check_authorization_mainnet(
    authorization_structure: Result<Authorization<MainnetV0>, Error>,
    ask_payload: Option<kalypso_ivs_models::models::InvalidInputPayload>,
    signer_wallet: Option<Wallet<SigningKey>>,
) -> HttpResponse {
    let default_response = kalypso_ivs_models::models::CheckInputResponse { valid: false };
    match authorization_structure {
        Ok(auth) => {
            let is_auth_empty = auth.is_empty();

            if is_auth_empty {
                if ask_payload.is_some() && signer_wallet.is_some() {
                    return HttpResponse::Ok().json(
                        generate_invalid_input_attestation(
                            ask_payload.unwrap(),
                            signer_wallet.unwrap(),
                        )
                        .await,
                    );
                } else {
                    return HttpResponse::Ok().json(default_response);
                }
            } else {
                let data = kalypso_ivs_models::models::CheckInputResponse { valid: true };
                return HttpResponse::Ok().json(data);
            }
        }
        Err(_) => {
            return HttpResponse::Ok().json(default_response);
        }
    }
}
