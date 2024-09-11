use crate::handler;
use actix_web::web::Data;
use actix_web::{App, HttpServer};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;

pub struct ProvingServer {
    enclave_key: Arc<Mutex<Vec<u8>>>,
    port: u16,
    semaphore: Arc<Semaphore>,
}

impl ProvingServer {
    pub fn new(enclave_key: String, port: u16) -> Self {
        log::warn!("Trying to spin up new proving server");
        let semaphore = Arc::new(Semaphore::new(1));
        let enclave_key = hex::decode(enclave_key).unwrap();
        let enclave_key = Arc::new(Mutex::new(enclave_key));
        ProvingServer {
            enclave_key,
            port,
            semaphore,
        }
    }
    pub async fn start_server(self) -> anyhow::Result<()> {
        log::warn!("Trying to start proving server");
        HttpServer::new(move || {
            App::new()
                .app_data(Data::new(self.enclave_key.clone()))
                .app_data(Data::new(self.semaphore.clone()))
                .configure(handler::routes)
        })
        .client_request_timeout(Duration::new(0, 0))
        .bind(("localhost", self.port))
        .unwrap_or_else(|_| panic!("Can not bind to {}", &self.port))
        .run()
        .await
        .unwrap();

        Ok(())
    }
}
