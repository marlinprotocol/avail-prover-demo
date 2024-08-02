mod handler;
mod model;
mod prover;
mod server;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let mut handles = vec![];

    let port: u16 = 3030;
    let port_clone = port.clone().to_string();

    let handle_1 = tokio::spawn(async {
        let listener =
            kalypso_listener::job_creator::JobCreator::simple_listener_for_confidential_prover(
                "0x704f1b9586EEf4B30C4f4658aA132bd9dE62cc5C".into(),
                hex::encode(handler::get_secp_private_key()),
                "19".into(),
                "https://arb-sepolia.g.alchemy.com/v2/cFwacd_RbVpNrezyxZEvO6AnnCuO-kxt".into(),
                "2aa70ff28eaa5ba2a57ca3f4c66d654e0386ff65a0467623b12535b22ce3f2ad".into(),
                "0xBD3700b9e4292C4842e6CB87205192Fa96e8Ed05".into(),
                "0xCf30295AfC4F12FfAC6EE96Da3607e7749881BA7".into(),
                68239483,
                421614,
                port_clone,
                false,
            );

        listener.run().await
    });
    handles.push(handle_1);

    let handle_2 = tokio::spawn(server::ProvingServer::new(port).start_server());
    handles.push(handle_2);

    for handle in handles {
        let _ = handle.await;
    }

    println!("All tasks completed or shutdown.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::handler;
    use actix_web::{test, App};
    use kalypso_ivs_models::models::EncryptedInputPayload;
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
        let expected_message = "Success";

        assert_eq!(result_json["data"], expected_message);
    }

    #[actix_rt::test]
    async fn test_generate_proof() {
        let app = test::init_service(App::new().service(handler::generate_proof)).await;
        let private_input = fs::read("./app/sample_auth.txt").await.unwrap();

        let payload = kalypso_generator_models::models::InputPayload::from_plain_secrets(
            [
                123, 10, 32, 32, 32, 32, 34, 110, 101, 116, 119, 111, 114, 107, 34, 58, 32, 34, 49,
                117, 49, 54, 34, 10, 125,
            ]
            .into(),
            private_input,
        );

        fs::write("generate_proof_payload.json", serde_json::to_string(&payload).unwrap()).await.unwrap();

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

        let secrets = fs::read("./app/checkInput.txt").await.unwrap();
        let payload =
            kalypso_generator_models::models::InputPayload::from_plain_secrets(vec![], secrets);
        fs::write("1_check_valid_input_payload.json", serde_json::to_string(&payload).unwrap()).await.unwrap();

        let req = test::TestRequest::post()
            .uri("/checkInput")
            .set_json(&payload)
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());

        let result = test::read_body(resp).await;
        let result_json: serde_json::Value = serde_json::from_slice(&result).unwrap();
        let expected_json = json!({
            "valid": true
        });

        assert_eq!(result_json, expected_json);
    }

    #[actix_rt::test]
    async fn test_check_invalid_input() {
        let app = test::init_service(App::new().service(handler::check_input_handler)).await;

        let secrets = "this is an invalid input".into();
        let payload =
            kalypso_generator_models::models::InputPayload::from_plain_secrets(vec![], secrets);

        fs::write("2_check_invalid_input_payload.json", serde_json::to_string(&payload).unwrap()).await.unwrap();

        let req = test::TestRequest::post()
            .uri("/checkInput")
            .set_json(&payload)
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());

        let result = test::read_body(resp).await;
        let result_json: serde_json::Value = serde_json::from_slice(&result).unwrap();
        let expected_json = json!({
            "valid": false
        });

        assert_eq!(result_json, expected_json);
    }

    #[actix_rt::test]
    async fn test_check_valid_input_with_signature() {
        let app =
            test::init_service(App::new().service(handler::get_attestation_for_invalid_inputs))
                .await;
        let secret_data = fs::read("./app/checkInput.txt").await.unwrap();

        let ask_payload = kalypso_ivs_models::models::InvalidInputPayload::from_plain_secrets(
            1.into(),
            [1, 2, 3, 4].into(),
            secret_data,
        );

        fs::write("3_get_attestation_for_valid_input.json", serde_json::to_string(&ask_payload).unwrap())
            .await
            .unwrap();

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
            "valid": true
        });
        assert_eq!(result_json, expected_json);
    }

    #[actix_rt::test]
    async fn test_check_invalid_input_with_signature() {
        let app =
            test::init_service(App::new().service(handler::get_attestation_for_invalid_inputs))
                .await;
        let secret_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4, 5]; // these are invalid inputs

        let ask_payload = kalypso_ivs_models::models::InvalidInputPayload::from_plain_secrets(
            1.into(),
            [1, 2, 3, 4].into(),
            secret_data,
        );

        fs::write("4_get_attestation_for_invalid_inputs_payload.json", serde_json::to_string(&ask_payload).unwrap()).await.unwrap();

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
            "proof": hex::decode("e8ef983340f3f23cc31c1fc8daed52b1d3a2d3b06369ec29b8a549ecab17383402575c86525a07acf237cc06c30a40158672cdb30c550f32f7263f34a5d46cf11b").unwrap()
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
            acl: encrypted_data.acl_data,
            encrypted_secrets: encrypted_data.encrypted_data,
            me_decryption_url: "http://13.201.131.193:3000/decryptRequest".into(),
            market_id: "19".into(),
        };

        fs::write("5_check_encrypted_input_payload.json", serde_json::to_string(&payload).unwrap()).await.unwrap();

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
            "valid": true
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
            acl: encrypted_data.acl_data,
            encrypted_secrets: encrypted_data.encrypted_data,
            me_decryption_url: "http://13.201.131.193:3000/decryptRequest".into(),
            market_id: "19".into(),
        };

        fs::write("6_check_encrypted_invalid_input_payload.json", serde_json::to_string(&payload).unwrap()).await.unwrap();

        let req = test::TestRequest::post()
            .uri("/checkEncryptedInputs")
            .set_json(&payload)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let result = test::read_body(resp).await;
        let result_json: serde_json::Value = serde_json::from_slice(&result).unwrap();
        // when payload is valid, signature is not required to be sent
        let expected_json = json!({"valid": false});
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
