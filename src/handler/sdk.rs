use askama::Template;
use axum::http::Response;
use reqwest::header;
use anyhow::Context;
use crate::error::AppError;

pub async fn get() -> Result<Response<String>, AppError> {
    let sdk_content = crate::templates::SdkTemplate.render().context("Failed to render SDK template")?;
    Ok(Response::builder().header(header::CONTENT_TYPE, "application/javascript").body(sdk_content)?)
}