mod handler;
mod model;
mod prover;
mod server;
use std::env;
use std::fs;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let mut handles = vec![];

    let port: u16 = 3030;
    let port_clone = port.clone().to_string();
    let enclave_key = hex::encode(fs::read("./app/secp.sec").unwrap());
    println!("enclave key: {}", enclave_key);

    let enclave_key_clone = enclave_key.clone();
    let handle_1 = tokio::spawn(async {
        let max_threads = env::var("MAX_THREADS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok()) // Parse the value to usize
            .unwrap_or(1);

        let start_block = env::var("START_BLOCK")
            .ok()
            .and_then(|v| v.parse::<u64>().ok()) // Parse the value to usize
            .unwrap_or(79300000);

        log::info!("Start Block: {}, Max Parallel Requests: {}", start_block, max_threads);
        
        let listener =
            kalypso_listener::job_creator::JobCreator::simple_listener_for_confidential_prover(
                "0x704f1b9586EEf4B30C4f4658aA132bd9dE62cc5C".into(),
                enclave_key_clone,
                "1".into(),
                "https://arb-sepolia.g.alchemy.com/v2/cFwacd_RbVpNrezyxZEvO6AnnCuO-kxt".into(),
                "c53dd8e14d0a4f8fa7b87c66adfc0d6197159732fd29517ea6783741423b9f54".into(),
                "0x0b6340a893B944BDc3B4F012e934b724c83abF97".into(),
                "0x5ce3e1010028C4F5687356D721e3e2B6DcEA7C25".into(),
                start_block,
                421614,
                port_clone,
                false,
                max_threads,
            );

        listener.run().await
    });
    handles.push(handle_1);

    let handle_2 = tokio::spawn(server::ProvingServer::new(enclave_key, port).start_server());
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
    use actix_web::web::Data;
    use actix_web::{test, App};
    use kalypso_ivs_models::models::EncryptedInputPayload;
    use log::warn;
    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};
    use std::sync::{Arc, Mutex};
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
        let enclave_key = fs::read("./app/secp.sec").await.unwrap();
        let enclave_key = Arc::new(Mutex::new(enclave_key));

        let app = test::init_service(
            App::new()
                .service(handler::generate_proof)
                .app_data(Data::new(enclave_key)),
        )
        .await;
        let private_input = fs::read("./app/sample_auth.txt").await.unwrap();

        let payload = kalypso_generator_models::models::InputPayload::from_plain_secrets(
            [
                123, 10, 32, 32, 32, 32, 34, 110, 101, 116, 119, 111, 114, 107, 34, 58, 32, 34, 49,
                117, 49, 54, 34, 10, 125,
            ]
            .into(),
            private_input,
        );

        fs::write(
            "generate_proof_payload.json",
            serde_json::to_string(&payload).unwrap(),
        )
        .await
        .unwrap();

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
        let payload = kalypso_generator_models::models::InputPayload::from_plain_secrets(
            [
                123, 10, 32, 32, 32, 32, 34, 110, 101, 116, 119, 111, 114, 107, 34, 58, 32, 34, 49,
                117, 49, 54, 34, 10, 125,
            ]
            .into(),
            secrets,
        );
        fs::write(
            "1_check_valid_input_payload.json",
            serde_json::to_string(&payload).unwrap(),
        )
        .await
        .unwrap();

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
        let payload = kalypso_generator_models::models::InputPayload::from_plain_secrets(
            [
                123, 10, 32, 32, 32, 32, 34, 110, 101, 116, 119, 111, 114, 107, 34, 58, 32, 34, 49,
                117, 49, 54, 34, 10, 125,
            ]
            .into(),
            secrets,
        );

        fs::write(
            "2_check_invalid_input_payload.json",
            serde_json::to_string(&payload).unwrap(),
        )
        .await
        .unwrap();

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
        let enclave_key = fs::read("./app/secp.sec").await.unwrap();
        let enclave_key = Arc::new(Mutex::new(enclave_key));
        let app = test::init_service(
            App::new()
                .service(handler::get_attestation_for_invalid_inputs)
                .app_data(Data::new(enclave_key)),
        )
        .await;
        let secret_data = fs::read("./app/checkInput.txt").await.unwrap();

        let ask_payload = kalypso_ivs_models::models::InvalidInputPayload::from_plain_secrets(
            1.into(),
            [1, 2, 3, 4].into(),
            secret_data,
        );

        fs::write(
            "3_get_attestation_for_valid_input.json",
            serde_json::to_string(&ask_payload).unwrap(),
        )
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
        let enclave_key = fs::read("./app/secp.sec").await.unwrap();
        let enclave_key = Arc::new(Mutex::new(enclave_key));
        let app = test::init_service(
            App::new()
                .service(handler::get_attestation_for_invalid_inputs)
                .app_data(Data::new(enclave_key)),
        )
        .await;
        let secret_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4, 5]; // these are invalid inputs

        let ask_payload = kalypso_ivs_models::models::InvalidInputPayload::from_plain_secrets(
            1.into(),
            [1, 2, 3, 4].into(),
            secret_data,
        );

        fs::write(
            "4_get_attestation_for_invalid_inputs_payload.json",
            serde_json::to_string(&ask_payload).unwrap(),
        )
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
        // below info is computed for above ask
        let expected_json = json!({
            "proof": hex::decode("e8ef983340f3f23cc31c1fc8daed52b1d3a2d3b06369ec29b8a549ecab17383402575c86525a07acf237cc06c30a40158672cdb30c550f32f7263f34a5d46cf11b").unwrap()
        });
        assert_eq!(result_json, expected_json);
    }

    #[actix_rt::test]
    async fn test_check_encrypted_input() {
        //tough one.
        let enclave_key = fs::read("./app/secp.sec").await.unwrap();
        let enclave_key = Arc::new(Mutex::new(enclave_key));

        let app = test::init_service(
            App::new()
                .service(handler::check_encrypted_input)
                .app_data(Data::new(enclave_key)),
        )
        .await;
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
            market_id: "1".into(),
            public_inputs: None,
        };

        fs::write(
            "5_check_encrypted_input_payload.json",
            serde_json::to_string(&payload).unwrap(),
        )
        .await
        .unwrap();

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
    async fn test_check_encrypted_input_compressed() {
        //tough one.
        let enclave_key = fs::read("./app/secp.sec").await.unwrap();
        let enclave_key = Arc::new(Mutex::new(enclave_key));

        let app = test::init_service(
            App::new()
                .service(handler::check_encrypted_input)
                .app_data(Data::new(enclave_key)),
        )
        .await;

        let acl_data = vec![
            4, 236, 220, 178, 8, 65, 243, 32, 179, 4, 185, 86, 222, 85, 26, 11, 85, 238, 174, 166,
            80, 13, 20, 73, 1, 127, 128, 55, 93, 165, 222, 204, 31, 189, 223, 38, 232, 48, 200,
            104, 63, 245, 233, 245, 226, 30, 32, 46, 81, 229, 99, 244, 69, 62, 157, 66, 225, 48,
            179, 59, 209, 32, 119, 210, 129, 65, 224, 79, 171, 228, 29, 118, 133, 249, 151, 207,
            64, 14, 200, 69, 93, 159, 61, 123, 206, 157, 20, 8, 144, 91, 206, 214, 104, 108, 16,
            72, 151, 126, 25, 66, 124, 60, 229, 239, 170, 113, 89, 172, 63, 116, 97, 2, 189, 248,
            175, 25, 39, 247, 52, 123, 212, 214, 130, 241, 130, 211, 167, 137, 196,
        ];

        let encrypted_data = vec![
            113, 50, 34, 239, 15, 235, 113, 23, 243, 212, 1, 172, 95, 139, 248, 99, 172, 169, 82,
            114, 73, 201, 109, 204, 12, 244, 186, 240, 34, 30, 238, 3, 221, 97, 23, 107, 44, 186,
            102, 37, 11, 89, 7, 38, 173, 60, 136, 255, 77, 40, 210, 67, 107, 132, 60, 195, 156,
            111, 83, 65, 64, 81, 159, 233, 214, 62, 105, 91, 37, 85, 92, 32, 88, 181, 223, 166,
            195, 98, 10, 239, 213, 191, 250, 171, 73, 166, 79, 186, 200, 106, 250, 9, 131, 188,
            144, 65, 97, 229, 251, 168, 221, 69, 144, 113, 57, 164, 163, 121, 224, 66, 225, 10, 0,
            9, 193, 59, 110, 159, 187, 87, 207, 62, 183, 177, 228, 255, 146, 198, 147, 111, 20, 62,
            28, 211, 50, 213, 26, 49, 53, 211, 32, 75, 20, 31, 94, 47, 137, 203, 145, 160, 60, 132,
            219, 203, 82, 178, 177, 205, 176, 20, 182, 8, 169, 82, 173, 171, 205, 104, 35, 18, 167,
            23, 173, 34, 137, 138, 185, 181, 230, 10, 137, 105, 213, 13, 172, 228, 84, 26, 7, 213,
            30, 1, 25, 14, 232, 156, 98, 119, 210, 139, 57, 181, 207, 240, 71, 147, 26, 54, 121,
            74, 80, 62, 163, 93, 40, 254, 133, 248, 214, 59, 175, 207, 21, 170, 121, 22, 76, 210,
            81, 190, 41, 25, 83, 74, 73, 142, 214, 76, 51, 19, 77, 147, 169, 170, 134, 198, 163,
            113, 173, 7, 78, 230, 30, 219, 94, 10, 232, 72, 76, 75, 215, 157, 124, 192, 110, 13,
            26, 86, 180, 215, 209, 147, 17, 59, 85, 242, 198, 255, 183, 143, 225, 80, 34, 152, 238,
            48, 88, 138, 224, 39, 182, 29, 135, 240, 218, 112, 175, 99, 91, 15, 87, 220, 137, 78,
            140, 125, 89, 1, 66, 30, 125, 101, 184, 81, 63, 175, 220, 123, 137, 254, 170, 240, 247,
            153, 177, 245, 122, 146, 99, 252, 195, 85, 232, 87, 52, 200, 34, 120, 46, 117, 11, 190,
            65, 218, 176, 3, 166, 153, 156, 212, 136, 121, 238, 31, 72, 210, 138, 104, 32, 105,
            230, 237, 90, 182, 234, 163, 228, 94, 162, 193, 160, 47, 99, 19, 71, 54, 245, 239, 253,
            250, 84, 128, 3, 245, 232, 17, 124, 175, 143, 199, 216, 122, 66, 107, 46, 62, 198, 134,
            134, 157, 209, 231, 44, 192, 102, 243, 69, 190, 196, 191, 220, 120, 176, 253, 24, 70,
            141, 226, 29, 100, 248, 201, 175, 227, 112, 46, 206, 101, 61, 164, 17, 145, 75, 26,
            242, 157, 189, 29, 230, 175, 62, 113, 19, 181, 202, 51, 188, 196, 229, 82, 22, 247,
            175, 177, 154, 98, 96, 179, 167, 13, 78, 45, 91, 126, 157, 174, 166, 82, 237, 21, 45,
            20, 61, 134, 23, 15, 124, 180, 97, 135, 22, 202, 204, 10, 43, 220, 255, 76, 176, 166,
            243, 247, 116, 62, 161, 230, 6, 1, 10, 242, 200, 174, 193, 89, 228, 185, 139, 10, 90,
            104, 62, 226, 74, 238, 6, 127, 176, 70, 83, 12, 130, 255, 1, 208, 79, 201, 220, 102,
            247, 182, 133, 6, 131, 221, 119, 185, 153, 141, 119, 249, 234, 210, 174, 55, 41, 191,
            250, 80, 103, 60, 218, 135, 203, 36, 19, 145, 52, 7, 38, 53, 39, 27, 162, 76, 102, 89,
            132, 244, 221, 82, 104, 5, 167, 231, 232, 13, 153, 169, 44, 174, 70, 90, 218, 166, 121,
            238, 118, 151, 210, 214, 93, 214, 231, 21, 129, 69, 101, 100, 53, 158, 65, 48, 42, 99,
            124, 194, 69, 201, 194, 120, 120, 192, 240, 26, 181, 37, 178, 153, 12, 56, 160, 219,
            245, 56, 53, 121, 113, 98, 76, 73, 235, 48, 130, 129, 183, 118, 32, 15, 105, 242, 30,
            201, 45, 238, 107, 23, 198, 11, 218, 1, 113, 111, 158, 237, 123, 125, 169, 104, 181,
            252, 1, 49, 251, 12, 149, 106, 157, 162, 232, 247, 71, 78, 231, 193, 254, 137, 223,
            115, 114, 119, 154, 161, 186, 40, 195, 222, 192, 78, 38, 227, 158, 209, 248, 7, 198,
            195, 67, 55, 26, 174, 26, 116, 106, 30, 191, 139, 29, 83, 191, 219, 26, 255, 194, 109,
            247, 103, 183, 125, 104, 241, 195, 204, 161, 60, 94, 32, 82, 185, 243, 17, 43, 76, 57,
            164, 76, 236, 42, 221, 58, 171, 124, 31, 215, 90, 106, 144, 112, 110, 121, 173, 137,
            237, 63, 48, 64, 32, 214, 154, 157, 206, 6, 239, 196, 206, 227, 242, 178, 19, 60, 129,
            189, 190, 241, 199, 97, 103, 47, 193, 229, 74, 214, 67, 112, 96, 88, 235, 31, 160, 23,
            77, 9, 169, 36, 124, 30, 236, 37, 37, 93, 237, 198, 239, 89, 56, 100, 196, 84, 44, 37,
            247, 225, 35, 80, 112, 165, 57, 213, 172, 148, 228, 123, 105, 18, 90, 65, 48, 68, 187,
            15, 83, 120, 215, 34, 231, 123, 96, 24, 235, 57, 117, 222, 97, 182, 203, 21, 193, 67,
            174, 64, 46, 105, 248, 9, 203, 76, 9, 216, 123, 16, 248, 21, 13, 28, 46, 49, 145, 9,
            56, 153, 55, 119, 25, 242, 185, 88, 84, 0, 81, 179, 177, 251, 159, 159, 77, 138, 81,
            224, 95, 162, 107, 15, 76, 5, 23, 87, 130, 136, 241, 100, 189, 1, 190, 170, 87, 5, 115,
            217, 66, 113, 2, 119, 140, 243, 30, 45, 196, 111, 43, 104, 150, 80, 142, 105, 130, 129,
            144, 15, 78, 112, 92, 7, 124, 223, 213, 3, 157, 196, 182, 185, 202, 102, 5, 219, 198,
            113, 152, 62, 168, 21, 211, 121, 140, 58, 233, 118, 194, 144, 7, 36, 59, 70, 254, 82,
            166, 192, 159, 170, 108, 0, 212, 123, 192, 138, 68, 17, 54, 103, 224, 106, 2, 211, 112,
            225, 61, 196, 241, 137, 194, 59, 117, 234, 159, 46, 183, 83, 87, 119, 215, 149, 19, 97,
            229, 9, 154, 147, 59, 229, 6, 249, 60, 37, 127, 29, 81, 231, 241, 209, 209, 4, 243,
            244, 82, 218, 106, 128, 128, 73, 218, 235, 99, 24, 27, 148, 220, 136, 236, 149, 151,
            142, 148, 155, 166, 242, 157, 61, 80, 83, 37, 156, 20, 125, 52, 242, 222, 43, 83, 87,
            107, 69, 149, 57, 154, 53, 136, 170, 130, 218, 252, 176, 244, 196, 62, 86, 224, 214,
            94, 225, 254, 127, 89, 87, 224, 252, 136, 141, 122, 81, 155, 85, 93, 152, 80, 166, 231,
            57, 7, 36, 114, 102, 47, 55, 196, 250, 106, 246, 138, 40, 178, 87, 105, 162, 253, 60,
            33, 8, 194, 235, 166, 210, 62, 192, 102, 76, 229, 235, 64, 200, 182, 21, 83, 111, 173,
            112, 156, 252, 140, 217, 249, 165, 34, 69, 8, 91, 23, 152, 23, 150, 60, 91, 142, 76,
            125, 6, 118, 152, 77, 165, 232, 136, 177, 45, 65, 93, 2, 27, 6, 128, 126, 31, 88, 59,
            61, 241, 173, 45, 93, 16, 176, 245, 129, 232, 61, 79, 173, 136, 132, 64, 145, 99, 205,
            42, 14, 88, 4, 113, 136, 233, 214, 203, 137, 119, 16, 75, 69, 46, 43, 214, 26, 4, 192,
            149, 127, 98, 193, 210, 78, 200, 68, 80, 131, 70, 41, 70, 157, 145, 3, 87, 47, 26, 193,
            243, 92, 85, 132, 33, 205, 42, 184, 185, 200, 121, 53, 119, 68, 194, 249, 80, 65, 33,
            109, 116, 247, 89, 64, 143, 74, 182, 183, 22, 5, 231, 184, 90, 252, 204, 109, 107, 145,
            132, 93, 189, 101, 95, 18, 209, 227, 111, 211, 107, 112, 59, 84, 91, 36, 31, 54, 53,
            67, 159, 165, 102, 13, 109, 90, 62, 14, 208, 244, 194, 10, 14, 115, 63, 75, 172, 48,
            133, 162, 56, 190, 41, 105, 10, 58, 81, 7, 107, 189, 103, 181, 110, 209, 70, 185, 48,
            11, 40, 10, 128, 84, 171, 132, 250, 106, 63, 117, 132, 6, 242, 126, 58, 50, 18, 202,
            16, 71, 231, 56, 224, 122, 4, 217, 38, 119, 1, 141, 17, 167, 63, 113, 170, 235, 67,
            251, 221, 232, 255, 109, 220, 37, 249, 232, 248, 108, 254, 131, 143, 17, 63, 110, 161,
            13, 208, 45, 185, 224, 238, 105, 118, 19, 26, 220, 226, 75, 251, 63, 79, 14, 152, 104,
            66, 248, 80, 177, 63, 124, 219, 93, 96, 155, 207, 211, 255, 72, 199, 50, 11, 1, 44, 58,
            67, 145, 61, 78, 198, 117, 10, 89, 46, 207, 131, 53, 26, 117, 147, 254, 113, 97, 130,
            24, 199, 221, 33, 114, 221, 184, 13, 79, 229, 107, 98, 171, 209, 108, 135, 18, 225, 56,
            68, 116, 68, 42, 31, 112, 170, 133, 250, 186, 177, 247, 100, 194, 54, 26, 189, 78, 129,
            192, 163, 229, 130, 217, 33, 207, 124, 31, 109, 137, 52, 14, 253, 152, 210, 241, 248,
            138, 30, 230, 46, 165, 53, 190, 46, 30, 212, 80, 210, 117, 251, 0, 229, 5, 137, 210,
            144, 79, 110, 137, 129, 151, 117, 116, 12, 249, 76, 35, 244, 119, 112, 21, 255, 45,
            100, 34, 236, 144, 206, 181, 49, 21, 219, 2, 196, 175, 2, 251, 172, 29, 228, 174, 36,
            113, 172, 231, 197, 0, 203, 75, 133, 238, 58, 83, 38, 250, 146, 147, 155, 255, 31, 21,
            73, 137, 55, 8, 200, 73, 73, 249, 129, 210, 244, 234, 126, 242, 112, 9, 14, 202, 41,
            188, 94, 162, 204, 224, 73, 7, 48, 22, 73, 86, 250, 55, 196, 178, 39, 128, 112, 3, 76,
            201, 148, 27, 172, 78, 31, 113, 17, 192, 25, 239, 49, 197, 225, 191, 96, 219, 62, 54,
            202, 106, 52, 207,
        ];

        let payload: EncryptedInputPayload = EncryptedInputPayload {
            acl: acl_data,
            encrypted_secrets: encrypted_data,
            me_decryption_url: "http://13.201.131.193:3000/decryptRequest".into(),
            market_id: "1".into(),
            public_inputs: None,
        };

        fs::write(
            "5_check_encrypted_input_payload_compressed.json",
            serde_json::to_string(&payload).unwrap(),
        )
        .await
        .unwrap();

        let req = test::TestRequest::post()
            .uri("/checkEncryptedInputs")
            .set_json(&payload)
            .to_request();

        let resp = test::call_service(&app, req).await;
        dbg!(resp.status());
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
        let enclave_key = fs::read("./app/secp.sec").await.unwrap();
        let enclave_key = Arc::new(Mutex::new(enclave_key));

        let app = test::init_service(
            App::new()
                .service(handler::check_encrypted_input)
                .app_data(Data::new(enclave_key)),
        )
        .await;
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
            market_id: "1".into(),
            public_inputs: None,
        };

        fs::write(
            "6_check_encrypted_invalid_input_payload.json",
            serde_json::to_string(&payload).unwrap(),
        )
        .await
        .unwrap();

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
