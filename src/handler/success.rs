use axum::{response::Html, extract::Query, http::StatusCode};
use serde::Deserialize;
use askama::Template;
use crate::templates::SuccessTemplate;

#[derive(Deserialize)]
pub struct SuccessQuery {
    code: Option<String>,
    error: Option<String>,
}

pub async fn get(
    Query(params): Query<SuccessQuery>,
) -> Result<Html<String>, StatusCode> {
    let template = SuccessTemplate {
        code: params.code,
        error: params.error,
    };
    
    let html = template.render().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Html(html))
}