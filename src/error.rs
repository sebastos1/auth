use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Json,
};
use serde_json::json;
use askama::Template;
use crate::templates::ErrorTemplate;

#[derive(Debug)]
pub enum AppError {
    NotFound(String),
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    Internal(anyhow::Error),
}

impl AppError {
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }
    
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::BadRequest(msg.into())
    }
    
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::Unauthorized(msg.into())
    }
    
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::Forbidden(msg.into())
    }

    fn status_and_message(&self) -> (StatusCode, String) {
        match self {
            AppError::NotFound(msg) => {
                tracing::debug!("404 Not Found: {}", msg);
                (StatusCode::NOT_FOUND, format_message(msg))
            },
            AppError::BadRequest(msg) => {
                tracing::debug!("400 Bad Request: {}", msg);
                (StatusCode::BAD_REQUEST, format_message(msg))
            },
            AppError::Unauthorized(msg) => {
                tracing::debug!("401 Unauthorized: {}", msg);
                (StatusCode::UNAUTHORIZED, format_message(msg))
            },
            AppError::Forbidden(msg) => {
                tracing::debug!("403 Forbidden: {}", msg);
                (StatusCode::FORBIDDEN, format_message(msg))
            },
            AppError::Internal(err) => {
                tracing::error!("Internal error: {}", err);
                (StatusCode::INTERNAL_SERVER_ERROR, format_message(err.to_string().as_str())) // dw bout it
            }
        }
    }

    pub fn html_error(self) -> Response {
        let (status, message) = self.status_and_message();
        let template = ErrorTemplate { status_code: status.as_u16(), message };
        match template.render() {
            Ok(html) => (status, Html(html)).into_response(),
            Err(_) => (status, "Error occurred").into_response(),
        }
    }
}

fn format_message(msg: &str) -> String {
    if *crate::IS_PRODUCTION {
        "Oh no!".to_string()
    } else {
        msg.to_string()
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = self.status_and_message();
        (status, Json(json!({ "error": message }))).into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(err: E) -> Self {
        Self::Internal(err.into())
    }
}

pub trait OptionExt<T> {
    fn or_bad_request(self, msg: impl Into<String>) -> Result<T, AppError>;
    fn or_not_found(self, msg: impl Into<String>) -> Result<T, AppError>;
    fn or_unauthorized(self, msg: impl Into<String>) -> Result<T, AppError>;
}

impl<T> OptionExt<T> for Option<T> {
    fn or_bad_request(self, msg: impl Into<String>) -> Result<T, AppError> {
        self.ok_or_else(|| AppError::bad_request(msg))
    }
    
    fn or_not_found(self, msg: impl Into<String>) -> Result<T, AppError> {
        self.ok_or_else(|| AppError::not_found(msg))
    }
    
    fn or_unauthorized(self, msg: impl Into<String>) -> Result<T, AppError> {
        self.ok_or_else(|| AppError::unauthorized(msg))
    }
}

pub enum FormResponse<T> {
    Success(T),
    ValidationErrors(Html<String>),
}

impl<T: IntoResponse> IntoResponse for FormResponse<T> {
    fn into_response(self) -> Response {
        match self {
            FormResponse::Success(response) => response.into_response(),
            FormResponse::ValidationErrors(html) => html.into_response(),
        }
    }
}

pub struct HtmlError(pub AppError);

impl IntoResponse for HtmlError {
    fn into_response(self) -> Response {
        self.0.html_error()
    }
}

impl<E: Into<AppError>> From<E> for HtmlError {
    fn from(err: E) -> Self {
        Self(err.into())
    }
}