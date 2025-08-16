use crate::{middleware::client::AuthenticatedClient, util::generate_random_string};
use axum::{Extension, Form, Json, extract::State, http::StatusCode};
use sea_orm::*;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    refresh_token: Option<String>,
    redirect_uri: Option<String>,
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
    Extension(auth_client): Extension<AuthenticatedClient>,
    State(db): State<DatabaseConnection>,
    Form(req): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, StatusCode> {
    match req.grant_type.as_str() {
        "authorization_code" => handle_authorization_code(&db, req, auth_client.client_id).await,
        "refresh_token" => handle_refresh_token(&db, req, auth_client.client_id).await,
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

async fn handle_authorization_code(
    db: &DatabaseConnection,
    req: TokenRequest,
    client_id: String,
) -> Result<Json<TokenResponse>, StatusCode> {
    let code = req.code.ok_or(StatusCode::BAD_REQUEST)?;
    let redirect_uri = req.redirect_uri.ok_or(StatusCode::BAD_REQUEST)?;

    let auth_code = crate::token::auth::Entity::verify(&code, db)
        .await
        .ok()
        .flatten()
        .ok_or(StatusCode::BAD_REQUEST)?;

    if auth_code.client_id != client_id || auth_code.redirect_uri != redirect_uri {
        return Err(StatusCode::BAD_REQUEST);
    }

    let access_token = generate_random_string(64);
    let refresh_token = generate_random_string(64);

    let token_model = crate::token::access::ActiveModel {
        token: Set(access_token.clone()),
        client_id: Set(client_id.clone()),
        user_id: Set(auth_code.user_id.clone()),
        scopes: Set(auth_code.scopes.clone()),
        ..Default::default()
    };

    let refresh_model = crate::token::refresh::ActiveModel {
        token: Set(refresh_token.clone()),
        access_token: Set(access_token.clone()),
        client_id: Set(client_id),
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
    client_id: String,
) -> Result<Json<TokenResponse>, StatusCode> {
    let refresh_token = req.refresh_token.ok_or(StatusCode::BAD_REQUEST)?;

    let refresh_record = crate::token::refresh::Entity::verify(&refresh_token, db)
        .await
        .ok()
        .flatten()
        .ok_or(StatusCode::BAD_REQUEST)?;

    if refresh_record.client_id != client_id {
        return Err(StatusCode::BAD_REQUEST);
    }

    let new_access_token = generate_random_string(64);
    let new_refresh_token = generate_random_string(64);

    let token_model = crate::token::access::ActiveModel {
        token: Set(new_access_token.clone()),
        client_id: Set(client_id.clone()),
        user_id: Set(refresh_record.user_id.clone()),
        scopes: Set(refresh_record.scopes.clone()),
        ..Default::default()
    };

    let updated_refresh = crate::token::refresh::ActiveModel {
        token: Set(new_refresh_token.clone()),
        access_token: Set(new_access_token.clone()),
        client_id: Set(client_id),
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
