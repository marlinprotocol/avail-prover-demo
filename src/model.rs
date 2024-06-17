use actix_web::{
    error,
    http::{header::ContentType, StatusCode},
    HttpResponse,
};
use bindings::shared_types::Ask;
use derive_more::{Display, Error};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Debug, Deserialize, Clone)]
pub struct ProverInputs {
    pub ask: Ask,
    pub private_input: Vec<u8>,
    pub ask_id: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProverConfig {
    pub private_key: String,
    pub query_url: String,
    pub secret: String,
}

#[derive(Debug, Display, Error)]
pub enum InputError {
    #[display(fmt = "file not found")]
    FileNotFound,

    #[display(fmt = "incorrect config")]
    BadConfigData,

    #[display(fmt = "execution failed")]
    ExecutionFailed,

    #[display(fmt = "invalid inputs")]
    InvalidInputs,
}

impl error::ResponseError for InputError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .insert_header(ContentType::html())
            .body(self.to_string())
    }

    fn status_code(&self) -> StatusCode {
        match *self {
            InputError::FileNotFound => StatusCode::NOT_FOUND,
            InputError::BadConfigData => StatusCode::NOT_ACCEPTABLE,
            InputError::ExecutionFailed => StatusCode::NOT_IMPLEMENTED,
            InputError::InvalidInputs => StatusCode::BAD_REQUEST,
        }
    }
}
