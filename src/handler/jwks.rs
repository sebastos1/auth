use crate::AppState;
use crate::error::AppError;
use axum::Json;
use axum::extract::State;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;

#[derive(Serialize)]
pub struct JwksResponse {
    keys: Vec<JwkKey>,
}

#[derive(Serialize)]
struct JwkKey {
    kty: String,
    #[serde(rename = "use")] // use is reserved
    key_use: String,
    kid: String,
    alg: String,
    n: String,
    e: String,
}

pub async fn get(State(app_state): State<AppState>) -> Result<Json<JwksResponse>, AppError> {
    let jwks = JwksResponse {
        keys: vec![JwkKey {
            kty: "RSA".to_string(),
            key_use: "sig".to_string(),
            kid: "main".to_string(),
            alg: "RS256".to_string(),
            n: URL_SAFE_NO_PAD.encode(app_state.jwk.n.to_bytes_be()),
            e: URL_SAFE_NO_PAD.encode(app_state.jwk.e.to_bytes_be()),
        }],
    };

    Ok(Json(jwks))
}
