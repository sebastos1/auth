use axum::{extract::State, http::HeaderMap, Form, Json};
use sea_orm::*;
use serde::{Deserialize, Serialize};
use crate::error::{AppError, OptionExt};

#[derive(Deserialize)]
pub struct TokenRequest {
    client_id: String,
    grant_type: String,
    code: Option<String>,
    refresh_token: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: String,
}

#[derive(Serialize)]
pub struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    refresh_token: String,
    scope: String,
}

pub async fn post(
    State(db): State<DatabaseConnection>,
    headers: HeaderMap,
    Form(req): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let _client = crate::util::validate_client_origin(&req.client_id, &headers, &db).await?;

    match req.grant_type.as_str() {
        "authorization_code" => handle_authorization_code(&db, req).await,
        "refresh_token" => handle_refresh_token(&db, req).await,
        _ => Err(AppError::bad_request("Unsupported grant_type")),
    }
}

async fn handle_authorization_code(
    db: &DatabaseConnection,
    req: TokenRequest,
) -> Result<Json<TokenResponse>, AppError> {
    let code = req.code.or_bad_request("Missing parameter: code")?;
    let redirect_uri = req.redirect_uri.or_bad_request("Missing redirect URI")?;
    
    let (access_token, refresh_token, scopes) = crate::token::auth::Entity::exchange_for_tokens(
        &code, &req.client_id, &redirect_uri, &req.code_verifier, db
    ).await?;
    
    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token,
        scope: scopes,
    }))
}

async fn handle_refresh_token(
    db: &DatabaseConnection,
    req: TokenRequest,
) -> Result<Json<TokenResponse>, AppError> {
    let refresh_token = req.refresh_token.or_bad_request("Missing refresh token")?;

    let (access_token, new_refresh_token, scopes) = crate::token::refresh::Entity::refresh_tokens(
        &refresh_token,
        &req.client_id,
        db,
    )
    .await?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token: new_refresh_token,
        scope: scopes,
    }))
}