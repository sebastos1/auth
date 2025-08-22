use sha2::{Sha256, Digest};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::{SystemRandom, SecureRandom};
use crate::{client, error::{AppError, OptionExt}};
use sea_orm::*;
use tracing::debug;

pub fn generate_random_string(length: usize) -> String {
    let rng = SystemRandom::new();
    let mut bytes = vec![0u8; length];
    rng.fill(&mut bytes).unwrap();
    URL_SAFE_NO_PAD.encode(&bytes).chars().take(length).collect()
}

pub fn verify_pkce(code_verifier: &str, code_challenge: &str) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let hash = hasher.finalize();
    let computed_challenge = URL_SAFE_NO_PAD.encode(hash);
    computed_challenge == code_challenge
}

pub async fn validate_client_origin(
    client_id: &str,
    headers: &axum::http::HeaderMap,
    db: &DatabaseConnection,
) -> Result<client::Model, AppError> {
    let client = client::Entity::find_by_id(client_id).one(db).await?
        .or_bad_request(format!("Invalid client_id: {}", client_id))?;
    
    // #[cfg(debug_assertions)]
    // {
    //     return Ok(client);
    // }

    let origin = headers.get("origin").and_then(|h| h.to_str().ok());
    let forwarded_host = headers.get("x-forwarded-host").and_then(|h| h.to_str().ok());
    
    let effective_origin = forwarded_host
        .map(|h| format!("https://{}", h))
        .or_else(|| origin.map(String::from))
        .or_bad_request("Origin or X-Forwarded-Host header required")?;

    let authorized_origins = client.get_authorized_origins()?;
    if !authorized_origins.contains(&effective_origin) {
        return Err(AppError::forbidden(format!("Origin not authorized: {}", effective_origin)));
    }

    Ok(client)
}