use axum::{response::{Html, Redirect}, http::StatusCode};
use askama::Template;
use serde::Serialize;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum AuthError {
    InvalidRequest,
    UnauthorizedClient,
    AccessDenied,
    UnsupportedResponseType,
    InvalidScope,
    ServerError,
    TemporarilyUnavailable,
    InvalidClient,
    InvalidGrant,
    UnsupportedGrantType,
}

impl AuthError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::AccessDenied => "access_denied",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope => "invalid_scope",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnsupportedGrantType => "unsupported_grant_type",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "The request is missing a required parameter, includes an invalid parameter value, or is otherwise malformed.",
            Self::UnauthorizedClient => "The client is not authorized to request an authorization code using this method.",
            Self::AccessDenied => "The resource owner or authorization server denied the request.",
            Self::UnsupportedResponseType => "The authorization server does not support obtaining an authorization code using this method.",
            Self::InvalidScope => "The requested scope is invalid, unknown, or malformed.",
            Self::ServerError => "The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
            Self::TemporarilyUnavailable => "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.",
            Self::InvalidClient => "Client authentication failed.",
            Self::InvalidGrant => "The provided authorization grant is invalid, expired, revoked, or does not match the redirection URI used in the authorization request.",
            Self::UnsupportedGrantType => "The authorization grant type is not supported by the authorization server.",
        }
    }

    pub fn http_status(&self) -> StatusCode {
        match self {
            Self::InvalidClient => StatusCode::UNAUTHORIZED,
            Self::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::TemporarilyUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::BAD_REQUEST,
        }
    }
}

#[derive(Template)]
#[template(path = "error.html")]
pub struct ErrorTemplate {
    pub error: String,
    pub description: String,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub error_description: String,
}

pub fn error_redirect(error: AuthError, redirect_uri: &str, state: Option<&str>) -> Result<Redirect, StatusCode> {
    let mut url = url::Url::parse(redirect_uri).map_err(|_| StatusCode::BAD_REQUEST)?;
    url.query_pairs_mut().append_pair("error", error.code()).append_pair("error_description", error.description());
    if let Some(state) = state {
        url.query_pairs_mut().append_pair("state", state);
    }
    Ok(Redirect::to(&url.to_string()))
}

pub fn error_page(error: AuthError) -> Result<Html<String>, StatusCode> {
    let template = ErrorTemplate {
        error: error.code().to_string(),
        description: error.description().to_string(),
    };
    let html = template.render().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Html(html))
}

pub fn error_json(error: AuthError) -> (StatusCode, axum::Json<ErrorResponse>) {
    (
        error.http_status(),
        axum::Json(ErrorResponse {
            error: error.code().to_string(),
            error_description: error.description().to_string(),
        })
    )
}