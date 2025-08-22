use axum::{Form, extract::State, http::StatusCode};
use sea_orm::*;
use serde::Deserialize;
use crate::error::{AppError, OptionExt};
use crate::token::{access, refresh};

#[derive(Deserialize)]
pub struct RevokeRequest {
    token: String,
    client_id: String,
}

pub async fn post(
    State(db): State<DatabaseConnection>,
    Form(req): Form<RevokeRequest>,
) -> Result<StatusCode, AppError> {
    crate::client::Entity::find_by_id(&req.client_id)
        .one(&db).await?
        .or_bad_request(format!("Invalid client_id: {}", req.client_id))?;

    if access::Entity::revoke(&req.token, &req.client_id, &db).await? {
        return Ok(StatusCode::OK);
    }

    refresh::Entity::revoke(&req.token, &req.client_id, &db).await?;
    Ok(StatusCode::OK)
}