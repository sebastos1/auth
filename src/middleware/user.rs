use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use sea_orm::*;

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

fn extract_bearer_token(headers: &axum::http::HeaderMap) -> Result<&str, StatusCode> {
    headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)
}

pub async fn user_auth_middleware(
    State(db): State<DatabaseConnection>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = extract_bearer_token(&headers).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let access_token = crate::token::access::Entity::verify(token, &db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let user = crate::user::Entity::find_by_id(&access_token.user_id)
        .one(&db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let auth_user = AuthenticatedUser { user, access_token };

    request.extensions_mut().insert(auth_user);
    Ok(next.run(request).await)
}
