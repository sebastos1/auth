use crate::{
    IS_PRODUCTION, client,
    error::{AppError, OptionExt},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use redis::AsyncCommands;
use ring::rand::{SecureRandom, SystemRandom};
use sea_orm::*;
use sha2::{Digest, Sha256};
use std::time::SystemTime;
use std::{collections::HashMap, sync::RwLock, time::UNIX_EPOCH};

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
    let client = client::Entity::find_by_id(client_id)
        .one(db)
        .await?
        .or_bad_request(format!("Invalid client_id: {}", client_id))?;

    if !*IS_PRODUCTION {
        return Ok(client);
    }

    let origin = headers.get("origin").and_then(|h| h.to_str().ok());
    let forwarded_host = headers.get("x-forwarded-host").and_then(|h| h.to_str().ok());

    let effective_origin = forwarded_host
        .map(|h| format!("https://{}", h))
        .or_else(|| origin.map(String::from))
        .or_bad_request("Origin or X-Forwarded-Host header required")?;

    let authorized_origins = client.get_authorized_origins()?;
    if !authorized_origins.contains(&effective_origin) {
        return Err(AppError::forbidden(format!(
            "Origin not authorized: {}",
            effective_origin
        )));
    }

    Ok(client)
}

// in memory csrf store, debug only
use std::sync::LazyLock;
static CSRF_TOKENS: LazyLock<RwLock<HashMap<String, u64>>> = LazyLock::new(|| RwLock::new(HashMap::new()));

pub async fn generate_csrf_token() -> String {
    let token = generate_random_string(32);

    if *IS_PRODUCTION {
        if let Ok(mut conn) = crate::get_redis_connection().await {
            let key = format!("csrf:{}", token);
            let _: Result<(), _> = conn.set_ex(key, "1", 3600).await; // 1 hour expiry
        }
    } else {
        let expiry = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 3600;
        if let Ok(mut tokens) = CSRF_TOKENS.write() {
            tokens.insert(token.clone(), expiry);
        }
    }

    token
}

pub async fn validate_csrf_token(token: &str) -> bool {
    if *IS_PRODUCTION {
        if let Ok(mut conn) = crate::get_redis_connection().await {
            let key = format!("csrf:{}", token);
            let result: Result<String, _> = conn.get_del(key).await;
            return result.is_ok();
        }
        false
    } else {
        let mut tokens = match CSRF_TOKENS.write() {
            Ok(tokens) => tokens,
            Err(_) => return false,
        };
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        tokens.retain(|_, &mut expiry| expiry > now);
        tokens.remove(token).is_some()
    }
}
