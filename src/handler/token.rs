use crate::{util::generate_random_string};
use axum::{Form, Json, extract::State, http::StatusCode};
use sea_orm::*;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

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

fn verify_pkce(code_verifier: &str, code_challenge: &str) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let hash = hasher.finalize();
    let computed_challenge = URL_SAFE_NO_PAD.encode(&hash);
    computed_challenge == code_challenge
}

async fn handle_authorization_code(
    db: &DatabaseConnection,
    req: TokenRequest,
) -> Result<Json<TokenResponse>, StatusCode> {
    let code = req.code.ok_or(StatusCode::BAD_REQUEST)?;
    let redirect_uri = req.redirect_uri.ok_or(StatusCode::BAD_REQUEST)?;

    let auth_code = crate::token::auth::Entity::verify(&code, db)
        .await
        .ok()
        .flatten()
        .ok_or(StatusCode::BAD_REQUEST)?;

    if auth_code.client_id != req.client_id || auth_code.redirect_uri != redirect_uri {
        return Err(StatusCode::BAD_REQUEST);
    }

    if !verify_pkce(&req.code_verifier, &auth_code.code_challenge) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let access_token = generate_random_string(64);
    let refresh_token = generate_random_string(64);

    let token_model = crate::token::access::ActiveModel {
        token: Set(access_token.clone()),
        client_id: Set(req.client_id.clone()),
        user_id: Set(auth_code.user_id.clone()),
        scopes: Set(auth_code.scopes.clone()),
        ..Default::default()
    };

    let refresh_model = crate::token::refresh::ActiveModel {
        token: Set(refresh_token.clone()),
        access_token: Set(access_token.clone()),
        client_id: Set(req.client_id),
        user_id: Set(auth_code.user_id),
        scopes: Set(auth_code.scopes.clone()),
        ..Default::default()
    };

    if token_model.insert(db).await.is_err()
        || refresh_model.insert(db).await.is_err()
        || crate::token::auth::Entity::delete_by_id(&code).exec(db).await.is_err()
    {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

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
) -> Result<Json<TokenResponse>, StatusCode> {
    let refresh_token = req.refresh_token.ok_or(StatusCode::BAD_REQUEST)?;

    let refresh_record = crate::token::refresh::Entity::verify(&refresh_token, db)
        .await
        .ok()
        .flatten()
        .ok_or(StatusCode::BAD_REQUEST)?;

    if refresh_record.client_id != req.client_id {
        return Err(StatusCode::BAD_REQUEST);
    }

    let new_access_token = generate_random_string(64);
    let new_refresh_token = generate_random_string(64);

    let token_model = crate::token::access::ActiveModel {
        token: Set(new_access_token.clone()),
        client_id: Set(req.client_id.clone()),
        user_id: Set(refresh_record.user_id.clone()),
        scopes: Set(refresh_record.scopes.clone()),
        ..Default::default()
    };

    let updated_refresh = crate::token::refresh::ActiveModel {
        token: Set(new_refresh_token.clone()),
        access_token: Set(new_access_token.clone()),
        client_id: Set(req.client_id),
        user_id: Set(refresh_record.user_id),
        scopes: Set(refresh_record.scopes.clone()),
        ..Default::default()
    };

    if crate::token::access::Entity::delete_by_id(&refresh_record.access_token)
        .exec(db)
        .await
        .is_err()
        || crate::token::refresh::Entity::delete_by_id(&refresh_token)
            .exec(db)
            .await
            .is_err()
        || token_model.insert(db).await.is_err()
        || updated_refresh.insert(db).await.is_err()
    {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(Json(TokenResponse {
        access_token: new_access_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token: new_refresh_token,
        scope: refresh_record.scopes,
    }))
}
