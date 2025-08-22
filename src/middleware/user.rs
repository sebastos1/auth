use axum::{extract::{Request, State}, http::HeaderMap, middleware::Next, response::Response};
use sea_orm::*;
use crate::error::{AppError, OptionExt};

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user: crate::user::Model,
    pub access_token: crate::token::access::Model,
}

impl AuthenticatedUser {
    pub fn has_scope(&self, scope: &str) -> bool {
        self.access_token.scopes.split_whitespace().any(|s| s == scope)
    }

    pub fn has_openid(&self) -> bool {
        self.has_scope("openid")
    }

    pub fn has_profile(&self) -> bool {
        self.has_scope("profile")
    }

    pub fn has_email(&self) -> bool {
        self.has_scope("email")
    }
}

pub async fn user_auth_middleware(
    State(db): State<DatabaseConnection>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .or_unauthorized("Bearer token required")?;

    let access_token = crate::token::access::Entity::verify(token, &db).await?.or_unauthorized("Invalid or expired token")?;

    let user = crate::user::Entity::find_by_id(&access_token.user_id).one(&db).await?.or_unauthorized("User not found")?;

    let auth_user = AuthenticatedUser { user, access_token };

    request.extensions_mut().insert(auth_user);
    Ok(next.run(request).await)
}
