use crate::{
    AppState,
    error::{AppError, OptionExt},
};
use axum::{Form, Json, extract::State, http::HeaderMap};
use sea_orm::*;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
}

pub async fn post(
    State(app_state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let client = crate::util::validate_client_origin(&form.client_id, &headers, &app_state.db).await?;
    crate::util::validate_redirect_uri(&client, &form.redirect_uri.clone().unwrap_or_default())?;
    match form.grant_type.as_str() {
        "authorization_code" => handle_authorization_code(&app_state.db, form).await,
        "refresh_token" => handle_refresh_token(&app_state.db, form).await,
        _ => Err(AppError::bad_request("Unsupported grant_type")),
    }
}

async fn handle_authorization_code(
    db: &DatabaseConnection,
    form: TokenRequest,
) -> Result<Json<TokenResponse>, AppError> {
    let code = form.code.or_bad_request("Missing parameter: code")?;
    let redirect_uri = form.redirect_uri.or_bad_request("Missing redirect URI")?;
    let (access_token, refresh_token, scopes, user) =
        crate::token::auth::Entity::exchange_for_tokens(&code, &form.client_id, &redirect_uri, &form.code_verifier, db)
            .await?;

    let id_token = if scopes.contains("openid") {
        Some(crate::jwt::create_id_token(&user, &form.client_id, &scopes)?)
    } else {
        None
    };

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token,
        scope: scopes,
        id_token
    }))
}

async fn handle_refresh_token(db: &DatabaseConnection, form: TokenRequest) -> Result<Json<TokenResponse>, AppError> {
    let refresh_token = form.refresh_token.or_bad_request("Missing refresh token")?;

    let (access_token, new_refresh_token, scopes, user) =
        crate::token::refresh::Entity::refresh_tokens(&refresh_token, &form.client_id, db).await?;

    let id_token = if scopes.contains("openid") {
        Some(crate::jwt::create_id_token(&user, &form.client_id, &scopes)?)
    } else {
        None
    };

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        refresh_token: new_refresh_token,
        scope: scopes,
        id_token
    }))
}
