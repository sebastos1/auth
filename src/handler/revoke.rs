use axum::{Form, http::{StatusCode, HeaderMap}, extract::State};
use sea_orm::*;
use serde::Deserialize;
use base64::engine::general_purpose;
use base64::Engine;
use crate::errors::{AuthError, error_json, ErrorResponse};

#[derive(Deserialize)]
pub struct RevokeRequest {
    token: String,
    client_id: Option<String>,
    client_secret: Option<String>,
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
    Form(req): Form<RevokeRequest>,
) -> Result<StatusCode, (StatusCode, axum::Json<ErrorResponse>)> {
    let (client_id, client_secret) = if let Some((id, secret)) = extract_basic_auth(&headers) {
        (id, secret)
    } else {
        (
            req.client_id.ok_or_else(|| error_json(AuthError::InvalidClient))?,
            req.client_secret.ok_or_else(|| error_json(AuthError::InvalidClient))?
        )
    };

    let client = crate::client::Entity::find_by_id(&client_id).one(&db).await
        .map_err(|_| error_json(AuthError::ServerError))?.ok_or_else(|| error_json(AuthError::InvalidClient))?;

    if client.client_secret != client_secret {
        return Err(error_json(AuthError::InvalidClient));
    }

    // revoke as access token first
    if let Ok(Some(access_token)) = crate::access_token::Entity::find_by_id(&req.token).one(&db).await {
        if access_token.client_id == client_id {
            crate::access_token::Entity::delete_by_id(&req.token).exec(&db).await
                .map_err(|_| error_json(AuthError::ServerError))?;
            
            if let Ok(Some(refresh_token)) = crate::refresh_token::Entity::find()
                .filter(crate::refresh_token::Column::AccessToken.eq(&req.token))
                .one(&db).await 
            {
                crate::refresh_token::Entity::delete_by_id(&refresh_token.token).exec(&db).await
                    .map_err(|_| error_json(AuthError::ServerError))?;
            }
            
            return Ok(StatusCode::OK);
        }
    }

    // revoke as refresh token
    if let Ok(Some(refresh_token)) = crate::refresh_token::Entity::find_by_id(&req.token).one(&db).await {
        if refresh_token.client_id == client_id {
            crate::refresh_token::Entity::delete_by_id(&req.token).exec(&db).await
                .map_err(|_| error_json(AuthError::ServerError))?;
            
            crate::access_token::Entity::delete_by_id(&refresh_token.access_token).exec(&db).await
                .map_err(|_| error_json(AuthError::ServerError))?;
            
            return Ok(StatusCode::OK);
        }
    }

    Ok(StatusCode::OK)
}