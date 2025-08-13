
use axum::{Json, Form, http::{StatusCode, HeaderMap}, extract::State};
use sea_orm::*;
use serde::{Deserialize, Serialize};
use chrono::Utc;
use anyhow::Result;
use base64::engine::general_purpose;
use base64::Engine;
use crate::errors::{AuthError, error_json, ErrorResponse};
use crate::util::generate_random_string;

#[derive(Deserialize)]
pub struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    refresh_token: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

#[derive(Serialize)]
pub struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    refresh_token: String,
    scope: String,
}

fn extract_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let auth_header = headers.get("authorization")?.to_str().ok()?;
    let encoded = auth_header.strip_prefix("Basic ")?;
    let decoded = general_purpose::STANDARD.decode(encoded).ok()?;
    let credentials = String::from_utf8(decoded).ok()?;
    
    let mut parts = credentials.splitn(2, ':');
    let client_id = parts.next()?.to_string();
    let client_secret = parts.next()?.to_string();
    
    Some((client_id, client_secret))
}

pub async fn post(
    headers: HeaderMap,
    State(db): State<DatabaseConnection>,
    Form(req): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, (StatusCode, Json<ErrorResponse>)> {
    let (client_id, client_secret) = if let Some((id, secret)) = extract_basic_auth(&headers) {
        (id, secret)
    } else {
        (
            req.client_id.clone().ok_or_else(|| error_json(AuthError::InvalidClient))?,
            req.client_secret.clone().ok_or_else(|| error_json(AuthError::InvalidClient))?
        )
    };

    let client = crate::client::Entity::find_by_id(&client_id).one(&db).await
        .map_err(|_| error_json(AuthError::ServerError))?.ok_or_else(|| error_json(AuthError::InvalidClient))?;

    if client.client_secret != client_secret {
        return Err(error_json(AuthError::InvalidClient));
    }

    match req.grant_type.as_str() {
        "authorization_code" => handle_authorization_code(&db, req, client_id).await,
        "refresh_token" => handle_refresh_token(&db, req, client_id).await,
        _ => Err(error_json(AuthError::UnsupportedGrantType)),
    }
}

async fn handle_authorization_code(
    db: &DatabaseConnection,
    req: TokenRequest,
    client_id: String,
) -> Result<Json<TokenResponse>, (StatusCode, Json<ErrorResponse>)> {
    let code = req.code.ok_or_else(|| error_json(AuthError::InvalidRequest))?;
    let redirect_uri = req.redirect_uri.ok_or_else(|| error_json(AuthError::InvalidRequest))?;

    let auth_code = crate::auth_code::Entity::find_by_id(&code).one(db).await
        .map_err(|_| error_json(AuthError::ServerError))?.ok_or_else(|| error_json(AuthError::InvalidGrant))?;

    if auth_code.expires_at < Utc::now() {
        return Err(error_json(AuthError::InvalidGrant));
    }

    if auth_code.client_id != client_id || auth_code.redirect_uri != redirect_uri {
        return Err(error_json(AuthError::InvalidGrant));
    }

    let access_token = generate_random_string(64);
    let refresh_token = generate_random_string(64);

    let token_model = crate::access_token::ActiveModel {
        token: Set(access_token.clone()),
        client_id: Set(client_id.clone()),
        user_id: Set(auth_code.user_id.clone()),
        scopes: Set(auth_code.scopes.clone()),
        ..Default::default()
    };
    token_model.insert(db).await.map_err(|_| error_json(AuthError::ServerError))?;

    let refresh_model = crate::refresh_token::ActiveModel {
        token: Set(refresh_token.clone()),
        access_token: Set(access_token.clone()),
        client_id: Set(client_id),
        user_id: Set(auth_code.user_id),
        scopes: Set(auth_code.scopes.clone()),
        ..Default::default()
    };
    refresh_model.insert(db).await.map_err(|_| error_json(AuthError::ServerError))?;

    crate::auth_code::Entity::delete_by_id(&code).exec(db).await
        .map_err(|_| error_json(AuthError::ServerError))?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token,
        scope: auth_code.scopes,
    }))
}

async fn handle_refresh_token(
    db: &DatabaseConnection,
    req: TokenRequest,
    client_id: String,
) -> Result<Json<TokenResponse>, (StatusCode, Json<ErrorResponse>)> {
    let refresh_token = req.refresh_token.ok_or_else(|| error_json(AuthError::InvalidRequest))?;

    let refresh_record = crate::refresh_token::Entity::find_by_id(&refresh_token).one(db).await
        .map_err(|_| error_json(AuthError::ServerError))?.ok_or_else(|| error_json(AuthError::InvalidGrant))?;

    if refresh_record.expires_at < Utc::now() {
        return Err(error_json(AuthError::InvalidGrant));
    }

    if refresh_record.client_id != client_id {
        return Err(error_json(AuthError::InvalidGrant));
    }

    // revoke old token
    crate::access_token::Entity::delete_by_id(&refresh_record.access_token).exec(db).await
        .map_err(|_| error_json(AuthError::ServerError))?;

    let new_access_token = generate_random_string(64);
    let new_refresh_token = generate_random_string(64);

    let token_model = crate::access_token::ActiveModel {
        token: Set(new_access_token.clone()),
        client_id: Set(client_id.clone()),
        user_id: Set(refresh_record.user_id.clone()),
        scopes: Set(refresh_record.scopes.clone()),
        ..Default::default()
    };
    token_model.insert(db).await.map_err(|_| error_json(AuthError::ServerError))?;

    let updated_refresh = crate::refresh_token::ActiveModel {
        token: Set(new_refresh_token.clone()),
        access_token: Set(new_access_token.clone()),
        client_id: Set(client_id),
        user_id: Set(refresh_record.user_id),
        scopes: Set(refresh_record.scopes.clone()),
        ..Default::default()
    };
    
    crate::refresh_token::Entity::delete_by_id(&refresh_token).exec(db).await
        .map_err(|_| error_json(AuthError::ServerError))?;
    
    updated_refresh.insert(db).await.map_err(|_| error_json(AuthError::ServerError))?;

    Ok(Json(TokenResponse {
        access_token: new_access_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token: new_refresh_token,
        scope: refresh_record.scopes,
    }))
}