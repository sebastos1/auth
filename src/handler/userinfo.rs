use crate::error::AppError;
use axum::{Extension, Json};
use serde::Serialize;

#[derive(Serialize)]
pub struct UserInfoResponse {
    id: String, // sub
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    avatar_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bio: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_admin: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_moderator: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_member: Option<bool>,
}

impl UserInfoResponse {
    fn new(id: String) -> Self {
        Self {
            id,
            email: None,
            username: None,
            country: None,
            avatar_url: None,
            bio: None,
            is_admin: None,
            is_moderator: None,
            is_member: None,
        }
    }
}

pub async fn get(
    Extension(auth_user): Extension<crate::middleware::user::AuthenticatedUser>,
) -> Result<Json<UserInfoResponse>, AppError> {
    if !auth_user.has_openid() {
        return Err(AppError::forbidden("OpenID scope required"));
    }

    let mut user_info = UserInfoResponse::new(auth_user.user.id.to_string());

    if auth_user.has_email() {
        user_info.email = Some(auth_user.user.email.clone());
    }

    if auth_user.has_profile() {
        user_info.username = Some(auth_user.user.username.clone());
        user_info.country = auth_user.user.country.clone();
        user_info.avatar_url = auth_user.user.avatar_url.clone();
        user_info.bio = auth_user.user.bio.clone();
    }

    if auth_user.has_roles() {
        user_info.is_admin = Some(auth_user.user.is_admin);
        user_info.is_moderator = Some(auth_user.user.is_moderator);
        user_info.is_member = Some(auth_user.user.is_member);
    }

    Ok(Json(user_info))
}
