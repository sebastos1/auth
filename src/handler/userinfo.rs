use axum::{Json, http::{StatusCode, HeaderMap}, extract::State};
use sea_orm::*;
use serde::Serialize;
use chrono::Utc;
use anyhow::Result;

#[derive(Serialize)]
pub struct UserInfoResponse {
    sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_admin: Option<bool>,
}

pub async fn get(
    headers: HeaderMap,
    State(db): State<DatabaseConnection>,
) -> Result<Json<UserInfoResponse>, StatusCode> {
    let auth_header = headers.get("authorization").ok_or(StatusCode::UNAUTHORIZED)?
        .to_str().map_err(|_| StatusCode::UNAUTHORIZED)?;

    let token = auth_header.strip_prefix("Bearer ").ok_or(StatusCode::UNAUTHORIZED)?;

    let access_token = crate::access_token::Entity::find_by_id(token).one(&db).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?.ok_or(StatusCode::UNAUTHORIZED)?;

    if access_token.expires_at < Utc::now() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let scopes: Vec<&str> = access_token.scopes.split_whitespace().collect();
    let has_openid = scopes.contains(&"openid");
    let has_profile = scopes.contains(&"profile");
    let has_email = scopes.contains(&"email");

    if !has_openid {
        return Err(StatusCode::FORBIDDEN);
    }

    let user = crate::user::Entity::find_by_id(&access_token.user_id).one(&db).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?.ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let response = UserInfoResponse {
        sub: user.id,
        email: if has_email { Some(user.email) } else { None },
        username: if has_profile { Some(user.username) } else { None },
        is_admin: if has_profile { Some(user.is_admin) } else { None },
    };

    Ok(Json(response))
}