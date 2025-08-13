use anyhow::Result;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use sea_orm::*;
use serde::Serialize;

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
    let auth_header = crate::util::extract_bearer_token(&headers)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let access_token = crate::token::access::Entity::verify(auth_header, &db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let scopes: Vec<&str> = access_token.scopes.split_whitespace().collect();
    let has_openid = scopes.contains(&"openid");
    let has_profile = scopes.contains(&"profile");
    let has_email = scopes.contains(&"email");

    if !has_openid {
        return Err(StatusCode::FORBIDDEN);
    }

    let user = crate::user::Entity::find_by_id(&access_token.user_id)
        .one(&db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let response = UserInfoResponse {
        sub: user.id,
        email: if has_email { Some(user.email) } else { None },
        username: if has_profile {
            Some(user.username)
        } else {
            None
        },
        is_admin: if has_profile {
            Some(user.is_admin)
        } else {
            None
        },
    };

    Ok(Json(response))
}
