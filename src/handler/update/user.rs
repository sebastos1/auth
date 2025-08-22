use axum::{Extension, Json, extract::State};
use chrono::Utc;
use sea_orm::*;
use serde::{Deserialize, Serialize};
use crate::error::{AppError, OptionExt};

#[derive(Deserialize)]
pub struct UpdateUserRequest {
    pub user_id: String,
    pub email: Option<String>,
    pub username: Option<String>,
    pub country: Option<String>,
    pub avatar_url: Option<String>,
    pub bio: Option<String>,
    pub is_moderator: Option<bool>,
    pub is_admin: Option<bool>,
    pub is_active: Option<bool>,
}

#[derive(Serialize)]
pub struct UpdateUserResponse {
    pub success: bool,
    pub user: crate::user::Model,
}

pub async fn patch(
    Extension(auth_user): Extension<crate::middleware::user::AuthenticatedUser>,
    State(db): State<DatabaseConnection>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<UpdateUserResponse>, AppError> {
    if req.user_id != auth_user.user.id && !auth_user.user.is_admin {
        return Err(AppError::forbidden("Insufficient permissions to update this user"));
    }

    let user = crate::user::Entity::find_by_id(&req.user_id)
        .one(&db).await?
        .or_not_found(format!("User not found: {}", req.user_id))?;

    let mut user_update: crate::user::ActiveModel = user.into();

    if let Some(email) = req.email {
        user_update.email = Set(email);
    }
    if let Some(username) = req.username {
        user_update.username = Set(username);
    }
    if let Some(country) = req.country {
        user_update.country = Set(Some(country));
    }
    if let Some(avatar_url) = req.avatar_url {
        user_update.avatar_url = Set(Some(avatar_url));
    }
    if let Some(bio) = req.bio {
        user_update.bio = Set(Some(bio));
    }

    if auth_user.user.is_admin {
        if let Some(is_moderator) = req.is_moderator {
            user_update.is_moderator = Set(is_moderator);
        }
        if let Some(is_admin) = req.is_admin {
            user_update.is_admin = Set(is_admin);
        }
        if let Some(is_active) = req.is_active {
            user_update.is_active = Set(is_active);
        }
    }

    user_update.updated_at = Set(Utc::now());

    let updated_user = user_update
        .update(&db).await?;

    Ok(Json(UpdateUserResponse {
        success: true,
        user: updated_user,
    }))
}
