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

pub async fn get_client(client_id: &str, db: &DatabaseConnection) -> Result<client::Model, AppError> {
    let client = client::Entity::find_by_id(client_id)
        .one(db)
        .await?
        .or_bad_request(format!("Invalid client_id: {}", client_id))?;

    if !*IS_PRODUCTION {
        return Ok(client);
    }

    Ok(client)
}

pub fn validate_redirect_uri(client: &client::Model, redirect_uri: &str) -> Result<(), AppError> {
    let auth_base = if *crate::IS_PRODUCTION {
        "https://auth.sjallabong.eu"
    } else {
        "http://localhost:3001"
    };

    if redirect_uri == format!("{}/success", auth_base) {
        return Ok(());
    }

    let redirect_uris = client.get_redirect_uris()?;
    if !redirect_uris.contains(&redirect_uri.to_string()) {
        return Err(AppError::bad_request(format!("Invalid redirect_uri: {}", redirect_uri)));
    }
    Ok(())
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
