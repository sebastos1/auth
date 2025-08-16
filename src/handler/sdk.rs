use askama::Template;
use axum::http::Response;
use reqwest::{StatusCode, header};

pub async fn get() -> Result<Response<String>, StatusCode> {
    let auth_server_url = std::env::var("AUTH_SERVER_URL").unwrap_or_else(|_| "http://localhost:3001".to_string());
    let template = crate::templates::SdkTemplate { auth_server_url };
    let sdk_content = template.render().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "application/javascript")
        .body(sdk_content.into())
        .unwrap())
}
