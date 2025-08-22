use crate::AppState;
use crate::error::{AppError, OptionExt};
use crate::token::{access, refresh};
use axum::{Form, extract::State, http::StatusCode};
use sea_orm::*;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct RevokeRequest {
    token: String,
    client_id: String,
}

pub async fn post(State(app_state): State<AppState>, Form(form): Form<RevokeRequest>) -> Result<StatusCode, AppError> {
    crate::client::Entity::find_by_id(&form.client_id)
        .one(&app_state.db)
        .await?
        .or_bad_request(format!("Invalid client_id: {}", form.client_id))?;

    if access::Entity::revoke(&form.token, &form.client_id, &app_state.db).await? {
        return Ok(StatusCode::OK);
    }

    refresh::Entity::revoke(&form.token, &form.client_id, &app_state.db).await?;
    Ok(StatusCode::OK)
}
