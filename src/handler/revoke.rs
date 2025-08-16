use crate::middleware::client::AuthenticatedClient;
use axum::{Extension, Form, extract::State, http::StatusCode};
use sea_orm::*;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct RevokeRequest {
    token: String,
}

pub async fn post(
    Extension(auth_client): Extension<AuthenticatedClient>,
    State(db): State<DatabaseConnection>,
    Form(req): Form<RevokeRequest>,
) -> StatusCode {
    // revoke as access token first
    if let Ok(Some(token)) = crate::token::access::Entity::find_by_id(&req.token).one(&db).await {
        if token.client_id == auth_client.client_id {
            let _ = crate::token::access::Entity::delete_by_id(&req.token).exec(&db).await;

            if let Ok(Some(refresh_token)) = crate::token::refresh::Entity::find()
                .filter(crate::token::refresh::Column::AccessToken.eq(&req.token))
                .one(&db)
                .await
            {
                let _ = crate::token::refresh::Entity::delete_by_id(&refresh_token.token)
                    .exec(&db)
                    .await;
            }

            return StatusCode::OK;
        }
    }

    // revoke as refresh token
    if let Ok(Some(token)) = crate::token::refresh::Entity::find_by_id(&req.token).one(&db).await {
        if token.client_id == auth_client.client_id {
            let _ = crate::token::refresh::Entity::delete_by_id(&req.token).exec(&db).await;
            let _ = crate::token::access::Entity::delete_by_id(&token.access_token)
                .exec(&db)
                .await;
            return StatusCode::OK;
        }
    }

    StatusCode::OK
}
