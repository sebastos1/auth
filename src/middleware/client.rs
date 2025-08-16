use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use base64::Engine;
use base64::engine::general_purpose;
use sea_orm::*;

#[derive(Debug, Clone)]
pub struct AuthenticatedClient {
    pub client_id: String,
}

fn extract_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let auth_header = headers.get("authorization")?.to_str().ok()?;
    let encoded = auth_header.strip_prefix("Basic ")?;
    let decoded = general_purpose::STANDARD.decode(encoded).ok()?;
    let credentials = String::from_utf8(decoded).ok()?;

    let mut parts = credentials.splitn(2, ":");
    let client_id = parts.next()?.to_string();
    let client_secret = parts.next()?.to_string();

    Some((client_id, client_secret))
}

pub async fn client_auth_middleware(
    State(db): State<DatabaseConnection>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let (client_id, client_secret) = extract_basic_auth(&headers).ok_or(StatusCode::UNAUTHORIZED)?;

    let client = crate::client::Entity::find_by_id(&client_id)
        .one(&db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if client.client_secret != client_secret {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let auth_client = AuthenticatedClient {
        client_id: client_id.clone(),
    };

    request.extensions_mut().insert(auth_client);
    Ok(next.run(request).await)
}
