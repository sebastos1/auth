use jsonwebtoken::{encode, Header, EncodingKey};
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::error::AppError;

#[derive(Debug, Serialize, Deserialize)]
struct IdTokenClaims {
    sub: String, // subject (user id)
    iss: String, // issuer (this server)
    aud: String, // audience (client id)
    exp: u64, // expiration
    iat: u64, // issued at
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
}

pub fn create_id_token(
    user: &crate::user::Model,
    client_id: &str, 
    scopes: &str,
) -> Result<String, AppError> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    let claims = IdTokenClaims {
        sub: user.id.clone(),
        iss: "https://auth.sjallabong.eu".to_string(),
        aud: client_id.to_string(),
        exp: now + 3600, // 1 hour
        iat: now,
        email: if scopes.contains("email") { Some(user.email.clone()) } else { None },
        username: if scopes.contains("profile") { Some(user.username.clone()) } else { None },
    };

    let header = Header::default();
    let key = EncodingKey::from_secret("todo".as_ref());
    
    encode(&header, &claims, &key).map_err(AppError::from)
}