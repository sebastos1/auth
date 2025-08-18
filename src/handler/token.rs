use axum::{Form, Json, extract::State, http::StatusCode};
use sea_orm::*;
use serde::{Deserialize, Serialize};


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
    Form(req): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, StatusCode> {
    let _client = crate::client::Entity::find_by_id(&req.client_id)
        .one(&db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::BAD_REQUEST)?;

    match req.grant_type.as_str() {
        "authorization_code" => handle_authorization_code(&db, req).await,
        "refresh_token" => handle_refresh_token(&db, req).await,
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

async fn handle_authorization_code(
    db: &DatabaseConnection,
    req: TokenRequest,
) -> Result<Json<TokenResponse>, StatusCode> {
    let code = req.code.ok_or(StatusCode::BAD_REQUEST)?;
    let redirect_uri = req.redirect_uri.ok_or(StatusCode::BAD_REQUEST)?;
    
    let (access_token, refresh_token, scopes) = crate::token::auth::Entity::exchange_for_tokens(
        &code, &req.client_id, &redirect_uri, &req.code_verifier, db
    ).await.map_err(|_| StatusCode::BAD_REQUEST)?;
    
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
) -> Result<Json<TokenResponse>, StatusCode> {
    let refresh_token = req.refresh_token.ok_or(StatusCode::BAD_REQUEST)?;

    let (access_token, new_refresh_token, scopes) = crate::token::refresh::Entity::refresh_tokens(
        &refresh_token,
        &req.client_id,
        db,
    )
    .await
    .map_err(|_| StatusCode::BAD_REQUEST)?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token: new_refresh_token,
        scope: scopes,
    }))
}