use crate::error::AppError;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rsa::RsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct Jwk {
    pub encoding_key: EncodingKey,
    pub n: rsa::BigUint,
    pub e: rsa::BigUint,
}

pub fn generate_jwk() -> Jwk {
    let private_key = std::fs::read("private_key.pem").expect("Failed to read private key");
    let public_key_pem = std::fs::read_to_string("public_key.pem").expect("Failed to read public key");
    let encoding_key = EncodingKey::from_rsa_pem(&private_key).expect("Failed to parse private key");
    let public_key = RsaPublicKey::from_public_key_pem(&public_key_pem).expect("Failed to parse public key");
    Jwk {
        encoding_key,
        n: public_key.n().clone(),
        e: public_key.e().clone(),
    }
}

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
    #[serde(skip_serializing_if = "Option::is_none")]
    country: Option<String>,
}

pub fn create_jwt(
    user: &crate::user::Model,
    client_id: &str,
    token_type: TokenType,
    scopes: &str,
    encoding_key: &EncodingKey,
) -> Result<String, AppError> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let mut issuer = "https://auth.sjallabong.eu";

    if !*crate::IS_PRODUCTION {
        issuer = "http://localhost:3001";
    }

    let base = BaseClaims {
        sub: user.id.clone(),
        iss: issuer.to_string(),
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
        }
        TokenType::IdToken => {
            let claims = IdTokenClaims {
                base,
                email: if scopes.contains("email") {
                    Some(user.email.clone())
                } else {
                    None
                },
                username: if scopes.contains("profile") {
                    Some(user.username.clone())
                } else {
                    None
                },
                country: if scopes.contains("profile") {
                    user.country.clone()
                } else {
                    None
                },
            };

            let header = Header::new(Algorithm::RS256);
            encode(&header, &claims, encoding_key).map_err(AppError::from)
        }
    }
}
