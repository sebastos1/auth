use askama::Template;
use axum::http::Response;
use reqwest::{StatusCode, header};

pub async fn get() -> Result<Response<String>, StatusCode> {
    let sdk_content = crate::templates::SdkTemplate.render().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "application/javascript")
        .body(sdk_content.into())
        .unwrap())
}
