use crate::error::AppError;
use axum::{Extension, Json};
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
    #[serde(skip_serializing_if = "Option::is_none")]
    country: Option<String>,
}

pub async fn get(
    Extension(auth_user): Extension<crate::middleware::user::AuthenticatedUser>,
) -> Result<Json<UserInfoResponse>, AppError> {
    if !auth_user.has_openid() {
        return Err(AppError::forbidden("OpenID scope required"));
    }

    let response = UserInfoResponse {
        sub: auth_user.user.id.clone(),
        email: if auth_user.has_email() {
            Some(auth_user.user.email.clone())
        } else {
            None
        },
        username: if auth_user.has_profile() {
            Some(auth_user.user.username.clone())
        } else {
            None
        },
        is_admin: if auth_user.has_profile() {
            Some(auth_user.user.is_admin)
        } else {
            None
        },
        country: if auth_user.has_profile() {
            auth_user.user.country
        } else {
            None
        },
    };

    Ok(Json(response))
}
