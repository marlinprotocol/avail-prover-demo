mod handler;
mod model;
mod prover;

use actix_web::{App, HttpServer};
use dotenv::dotenv;
use std::time::Duration;

use std::env;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let port: u16 = env::var("PORT")
        .unwrap_or_else(|_| panic!("PORT must be provided in the .env file"))
        .parse::<u16>()
        .expect("PORT must be a valid number");

    let server = HttpServer::new(move || App::new().configure(handler::routes))
        .client_request_timeout(Duration::new(0, 0))
        .bind(("0.0.0.0", port))
        .unwrap_or_else(|_| panic!("Can not bind to {}", &port))
        .run();

    log::info!("avail-prover start on port {}", port);

    server.await
}

#[cfg(test)]
mod tests {
    use crate::handler;
    use actix_web::{test, App};
    use bindings::shared_types::Ask;
    use kalypso_generator_models::models::AskInputPayload;
    use kalypso_ivs_models::models::{AskPayload, EncryptedInputPayload, InputPayload};
    use log::warn;
    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};
    use tokio::fs;

    #[actix_rt::test]
    async fn test_server() {
        let app = test::init_service(App::new().service(handler::test)).await;
        let req = test::TestRequest::get().uri("/test").to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());

        let result = test::read_body(resp).await;
        let result_json: Value = serde_json::from_slice(&result).unwrap();
        let expected_json = json!({
            "message": "The Avail prover is running!!",
            "data": "Avail Prover is running!"
        });

        assert_eq!(result_json, expected_json);
    }

    #[actix_rt::test]
    async fn test_benchmark() {
        let app = test::init_service(App::new().service(handler::benchmark)).await;
        let req = test::TestRequest::get().uri("/benchmark").to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());

        let result = test::read_body(resp).await;
        let result_json: Value = serde_json::from_slice(&result).unwrap();
        let expected_message =
            "Proof generated, the proof generation time returned is in milliseconds";

        assert_eq!(result_json["message"], expected_message);
        assert!(result_json["data"].is_string());
    }

    #[actix_rt::test]
    async fn test_generate_proof() {
        let app = test::init_service(App::new().service(handler::generate_proof)).await;
        let private_input = fs::read("./app/sample_auth.txt").await.unwrap();

        let ask: Ask = Ask {
            market_id: 1.into(),
            reward: 1.into(),
            expiry: 1.into(),
            time_taken_for_proof_generation: 1.into(),
            deadline: 1.into(),
            refund_address: "0000dead0000dead0000dead0000dead0000dead".parse().unwrap(),
            prover_data: [123, 10, 32, 32, 32, 32, 34, 110, 101, 116, 119, 111, 114, 107, 34, 58, 32, 34, 49, 117, 49, 54, 34, 10, 125].into(),
        };

        let payload: AskInputPayload = AskInputPayload {
            ask,
            private_input,
            ask_id: 1,
        };
        let req = test::TestRequest::post()
            .uri("/generateProof")
            .set_json(&payload)
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());
    }

    #[actix_rt::test]
    async fn test_check_input() {
        let app = test::init_service(App::new().service(handler::check_input_handler)).await;

        let secrets = fs::read_to_string("./app/checkInput.txt").await.unwrap();
        let payload = InputPayload {
            public: "".into(),
            secrets: Some(secrets),
        };

        let req = test::TestRequest::post()
            .uri("/checkInput")
            .set_json(&payload)
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());

        let result = test::read_body(resp).await;
        let result_json: serde_json::Value = serde_json::from_slice(&result).unwrap();
        let expected_json = json!({
            "message": "Payload is valid",
            "data": "{\"is_input_valid\":true}"
        });

        assert_eq!(result_json, expected_json);
    }

    #[actix_rt::test]
    async fn test_check_wrong_input() {
        let app = test::init_service(App::new().service(handler::check_input_handler)).await;

        let secrets = "this is an invalid input".into();
        let payload = InputPayload {
            public: "".into(),
            secrets: Some(secrets),
        };

        let req = test::TestRequest::post()
            .uri("/checkInput")
            .set_json(&payload)
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_client_error());

        let result = test::read_body(resp).await;
        let result_json: serde_json::Value = serde_json::from_slice(&result).unwrap();
        let expected_json = json!({
            "message": "Invalid Authorization",
            "data": null
        });

        assert_eq!(result_json, expected_json);
    }

    #[actix_rt::test]
    async fn test_check_input_with_signature() {
        let app =
            test::init_service(App::new().service(handler::get_attestation_for_invalid_inputs))
                .await;
        let data_to_encrypt = fs::read("./app/checkInput.txt").await.unwrap();
        // bit un-intutive, but rn this seems only way to test
        let receiver_pub_key = fs::read("./app/secp.pub").await.unwrap();
        let encrypted_data =
            kalypso_helper::secret_inputs_helpers::encrypt_data_with_ecies_and_aes(
                &receiver_pub_key,
                &data_to_encrypt,
            )
            .unwrap();

        let ask: Ask = Ask {
            market_id: 1.into(),
            reward: 1.into(),
            expiry: 1.into(),
            time_taken_for_proof_generation: 1.into(),
            deadline: 1.into(),
            refund_address: "0000dead0000dead0000dead0000dead0000dead".parse().unwrap(),
            prover_data: [1, 2, 3, 4].into(),
        };
        let ask_payload = AskPayload {
            ask_id: 1,
            ask,
            encrypted_secret: hex::encode(encrypted_data.encrypted_data),
            acl: hex::encode(encrypted_data.acl_data),
        };

        let req = test::TestRequest::post()
            .uri("/getAttestationForInvalidInputs")
            .set_json(&ask_payload)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let result = test::read_body(resp).await;
        let result_json: serde_json::Value = serde_json::from_slice(&result).unwrap();
        // when payload is valid, signature is not required to be sent
        let expected_json = json!({
            "message": "Payload is valid",
            "data": "{\"is_input_valid\":true}"
        });
        assert_eq!(result_json, expected_json);
    }

    #[actix_rt::test]
    async fn test_check_wrong_input_with_signature() {
        let app =
            test::init_service(App::new().service(handler::get_attestation_for_invalid_inputs))
                .await;
        let data_to_encrypt = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4, 5]; // these are invalid inputs
                                                                              // bit un-intutive, but rn this seems only way to test
        let receiver_pub_key = fs::read("./app/secp.pub").await.unwrap();
        let encrypted_data =
            kalypso_helper::secret_inputs_helpers::encrypt_data_with_ecies_and_aes(
                &receiver_pub_key,
                &data_to_encrypt,
            )
            .unwrap();

        let ask: Ask = Ask {
            market_id: 1.into(),
            reward: 1.into(),
            expiry: 1.into(),
            time_taken_for_proof_generation: 1.into(),
            deadline: 1.into(),
            refund_address: "0000dead0000dead0000dead0000dead0000dead".parse().unwrap(),
            prover_data: [1, 2, 3, 4].into(),
        };
        let ask_payload = AskPayload {
            ask_id: 1,
            ask,
            encrypted_secret: hex::encode(encrypted_data.encrypted_data),
            acl: hex::encode(encrypted_data.acl_data),
        };

        let req = test::TestRequest::post()
            .uri("/getAttestationForInvalidInputs")
            .set_json(&ask_payload)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let result = test::read_body(resp).await;
        let result_json: serde_json::Value = serde_json::from_slice(&result).unwrap();
        // when payload is valid, signature is not required to be sent
        // below info is computed for above ask
        let expected_json = json!({
            "message": "Payload is NOT valid",
            "data": "{\"signature\":\"e8ef983340f3f23cc31c1fc8daed52b1d3a2d3b06369ec29b8a549ecab17383402575c86525a07acf237cc06c30a40158672cdb30c550f32f7263f34a5d46cf11b\",\"ask_id\":1}"
        });
        assert_eq!(result_json, expected_json);
    }

    #[actix_rt::test]
    async fn test_check_encrypted_input() {
        //tough one.
        let app = test::init_service(App::new().service(handler::check_encrypted_input)).await;
        let data_to_encrypt = fs::read("./app/checkInput.txt").await.unwrap();

        let matching_engine_pubkey =
            hex::decode(fetch_me_pub_key().await.expect("Failed fetching me pubkey"))
                .expect("is valid ecies pubkey");
        let encrypted_data =
            kalypso_helper::secret_inputs_helpers::encrypt_data_with_ecies_and_aes(
                &matching_engine_pubkey,
                &data_to_encrypt,
            )
            .expect("Unable to encrypt the data");

        let payload: EncryptedInputPayload = EncryptedInputPayload {
            acl: hex::encode(encrypted_data.acl_data),
            encrypted_secrets: hex::encode(encrypted_data.encrypted_data),
            me_decryption_url: "http://13.201.131.193:3000/decryptRequest".into(),
            market_id: "19".into(),
        };

        let req = test::TestRequest::post()
            .uri("/checkEncryptedInputs")
            .set_json(&payload)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let result = test::read_body(resp).await;
        let result_json: serde_json::Value = serde_json::from_slice(&result).unwrap();
        // when payload is valid, signature is not required to be sent
        let expected_json = json!({
            "message": "Payload is valid",
            "data": "{\"is_input_valid\":true}"
        });
        assert_eq!(result_json, expected_json);
    }

    #[actix_rt::test]
    async fn test_check_encrypted_invalid_input() {
        //tough one.
        let app = test::init_service(App::new().service(handler::check_encrypted_input)).await;
        let data_to_encrypt = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0];

        warn!("Matching Engine IP hardcoded, it should be fetched from somewhere else");

        let matching_engine_pubkey =
            hex::decode(fetch_me_pub_key().await.expect("Failed fetching me pubkey"))
                .expect("is valid ecies pubkey");
        let encrypted_data =
            kalypso_helper::secret_inputs_helpers::encrypt_data_with_ecies_and_aes(
                &matching_engine_pubkey,
                &data_to_encrypt,
            )
            .unwrap();

        let payload: EncryptedInputPayload = EncryptedInputPayload {
            acl: hex::encode(encrypted_data.acl_data),
            encrypted_secrets: hex::encode(encrypted_data.encrypted_data),
            me_decryption_url: "http://13.201.131.193:3000/decryptRequest".into(),
            market_id: "19".into(),
        };

        let req = test::TestRequest::post()
            .uri("/checkEncryptedInputs")
            .set_json(&payload)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());

        let result = test::read_body(resp).await;
        let result_json: serde_json::Value = serde_json::from_slice(&result).unwrap();
        // when payload is valid, signature is not required to be sent
        let expected_json = json!({
            "message": "Decrypted Data is not valid",
            "data": null
        });
        assert_eq!(result_json, expected_json);
    }

    async fn fetch_me_pub_key() -> Result<String, Box<dyn std::error::Error>> {
        warn!("Fetching ME publickey dynamically using matching engine client");

        let url = "http://13.201.131.193:5000/api/getMatchingEnginePublicKeys";

        let response = reqwest::get(url).await?;

        #[derive(Serialize, Debug, Deserialize)]
        pub struct MatchingEnginePublicKeys {
            pub matching_engine_public_key: String,
            pub matching_engine_ecies_public_key: String,
        }

        #[derive(Serialize, Deserialize, Debug)]
        struct JsonResponse {
            status: String,
            message: String,
            data: Option<MatchingEnginePublicKeys>,
        }

        if response.status().is_success() {
            let json_response: JsonResponse = response.json().await?;

            if let Some(data) = json_response.data {
                let pub_key_stripped = data
                    .matching_engine_ecies_public_key
                    .strip_prefix("0x")
                    .unwrap_or(&data.matching_engine_ecies_public_key);
                Ok(pub_key_stripped.to_string())
            } else {
                Err("Missing data in response".into())
            }
        } else {
            Err("Failed fetching ME keys".into())
        }
    }
}
