mod handler;
mod model;
mod prover;
mod response;

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
