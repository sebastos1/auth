use crate::errors::{AuthError, ErrorResponse, error_json};
use axum::{
    Form,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use sea_orm::*;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct RevokeRequest {
    token: String,
    client_id: Option<String>,
    client_secret: Option<String>,
}

pub async fn post(
    headers: HeaderMap,
    State(db): State<DatabaseConnection>,
    Form(req): Form<RevokeRequest>,
) -> Result<StatusCode, (StatusCode, axum::Json<ErrorResponse>)> {
    let (client_id, client_secret) = if let Some((id, secret)) = crate::util::extract_basic_auth(&headers) {
        (id, secret)
    } else {
        (
            req.client_id
                .ok_or_else(|| error_json(AuthError::InvalidClient))?,
            req.client_secret
                .ok_or_else(|| error_json(AuthError::InvalidClient))?,
        )
    };

    let client = crate::client::Entity::find_by_id(&client_id)
        .one(&db)
        .await
        .map_err(|_| error_json(AuthError::ServerError))?
        .ok_or_else(|| error_json(AuthError::InvalidClient))?;

    if client.client_secret != client_secret {
        return Err(error_json(AuthError::InvalidClient));
    }

    // revoke as access token first
    let access_token = crate::token::access::Entity::find_by_id(&req.token)
        .one(&db)
        .await
        .map_err(|_| error_json(AuthError::ServerError))?;

    if let Some(token) = access_token{
        if token.client_id == client_id {
            crate::token::access::Entity::delete_by_id(&req.token)
                .exec(&db)
                .await
                .map_err(|_| error_json(AuthError::ServerError))?;

            if let Ok(Some(refresh_token)) = crate::token::refresh::Entity::find()
                .filter(crate::token::refresh::Column::AccessToken.eq(&req.token))
                .one(&db)
                .await
            {
                crate::token::refresh::Entity::delete_by_id(&refresh_token.token)
                    .exec(&db)
                    .await
                    .map_err(|_| error_json(AuthError::ServerError))?;
            }

            return Ok(StatusCode::OK);
        }
    }

    // revoke as refresh token
    let refresh_token = crate::token::refresh::Entity::find_by_id(&req.token)
        .one(&db)
        .await
        .map_err(|_| error_json(AuthError::ServerError))?;

    if let Some(token) = refresh_token {
        if token.client_id == client_id {
            crate::token::refresh::Entity::delete_by_id(&req.token)
                .exec(&db)
                .await
                .map_err(|_| error_json(AuthError::ServerError))?;

            crate::token::access::Entity::delete_by_id(&token.access_token)
                .exec(&db)
                .await
                .map_err(|_| error_json(AuthError::ServerError))?;

            return Ok(StatusCode::OK);
        }
    }

    Ok(StatusCode::OK)
}
