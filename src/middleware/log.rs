use axum::{extract::Request, middleware::Next, response::Response};
use log::info;

pub async fn log_request(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let host = request
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    info!("{} {} from {}", method, uri, host);

    next.run(request).await
}
