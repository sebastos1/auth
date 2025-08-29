use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::error::AppError;

#[derive(Debug, Serialize, Deserialize)]
pub enum TokenType {
    IdToken,
    AccessToken,
}

#[derive(Debug, Serialize, Deserialize)]
struct BaseClaims {
    sub: String,
    iss: String, 
    aud: String,
    exp: u64,
    iat: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct AccessTokenClaims {
    #[serde(flatten)]
    base: BaseClaims,
    scope: String,
    username: String,
    avatar_url: Option<String>,
    country: Option<String>,
    is_admin: bool,
    is_moderator: bool,
    is_member: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct IdTokenClaims {
    #[serde(flatten)]
    base: BaseClaims,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
}

pub fn create_jwt(
    user: &crate::user::Model,
    client_id: &str,
    token_type: TokenType,
    scopes: &str,
    encoding_key: &EncodingKey,
) -> Result<String, AppError> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    let base = BaseClaims {
        sub: user.id.clone(),
        iss: "https://auth.sjallabong.eu".to_string(),
        aud: client_id.to_string(),
        exp: now + 3600,
        iat: now,
    };
    
    match token_type {
        TokenType::AccessToken => {
            let claims = AccessTokenClaims {
                base,
                scope: scopes.to_string(),
                username: user.username.clone(),
                avatar_url: user.avatar_url.clone(),
                country: user.country.clone(),
                is_admin: user.is_admin,
                is_moderator: user.is_moderator,
                is_member: user.is_member,
            };
            
            let header = Header::new(Algorithm::RS256);
            encode(&header, &claims, encoding_key).map_err(AppError::from)
        },
        TokenType::IdToken => {
            let claims = IdTokenClaims {
                base,
                email: if scopes.contains("email") { Some(user.email.clone()) } else { None },
                username: if scopes.contains("profile") { Some(user.username.clone()) } else { None },
                // more to come
            };

            let header = Header::new(Algorithm::RS256);
            encode(&header, &claims, encoding_key).map_err(AppError::from)
        }
    }
}
