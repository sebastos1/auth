use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Json,
};
use serde_json::json;
use askama::Template;
use crate::{templates::ErrorTemplate, IS_PRODUCTION};

#[derive(Debug)]
pub enum AppError {
    // explicit api errors
    NotFound(String),
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    
    // catch-all
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
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::NotFound(msg) => {
                tracing::debug!("404 Not Found: {}", msg);
                (StatusCode::NOT_FOUND, msg)
            },
            AppError::BadRequest(msg) => {
                tracing::debug!("400 Bad Request: {}", msg);
                (StatusCode::BAD_REQUEST, msg)
            },
            AppError::Unauthorized(msg) => {
                tracing::debug!("401 Unauthorized: {}", msg);
                (StatusCode::UNAUTHORIZED, msg)
            },
            AppError::Forbidden(msg) => {
                tracing::debug!("403 Forbidden: {}", msg);
                (StatusCode::FORBIDDEN, msg)
            },
            AppError::Internal(err) => {
                tracing::error!(
                    error = %err,
                    error_chain = ?err.chain().collect::<Vec<_>>(),
                    "Internal server error occurred"
                );
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            }
        };

        let body = Json(json!({ "error": message }));
        (status, body).into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self::Internal(err.into())
    }
}

pub trait OptionExt<T> {
    fn or_bad_request(self, msg: impl Into<String>) -> Result<T, AppError>;
    fn or_not_found(self, msg: impl Into<String>) -> Result<T, AppError>;
    // fn or_forbidden(self, msg: impl Into<String>) -> Result<T, AppError>;
    fn or_unauthorized(self, msg: impl Into<String>) -> Result<T, AppError>;
}

impl<T> OptionExt<T> for Option<T> {
    fn or_bad_request(self, msg: impl Into<String>) -> Result<T, AppError> {
        self.ok_or_else(|| AppError::bad_request(msg))
    }
    
    fn or_not_found(self, msg: impl Into<String>) -> Result<T, AppError> {
        self.ok_or_else(|| AppError::not_found(msg))
    }
    
    // fn or_forbidden(self, msg: impl Into<String>) -> Result<T, AppError> {
    //     self.ok_or_else(|| AppError::forbidden(msg))
    // }
    
    fn or_unauthorized(self, msg: impl Into<String>) -> Result<T, AppError> {
        self.ok_or_else(|| AppError::unauthorized(msg))
    }
}

// for form errors (register, login)
pub enum FormResponse<T> {
    Success(T),
    ValidationErrors(axum::response::Html<String>),
}

impl<T: IntoResponse> IntoResponse for FormResponse<T> {
    fn into_response(self) -> Response {
        match self {
            FormResponse::Success(response) => response.into_response(),
            FormResponse::ValidationErrors(html) => html.into_response(),
        }
    }
}