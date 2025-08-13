use crate::templates::RegisterTemplate;
use anyhow::Result;
use askama::Template;
use axum::{
    Form,
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::{Html, Redirect},
};
use bcrypt::{DEFAULT_COST, hash};
use chrono::{DateTime, Utc};
use sea_orm::*;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use validator::Validate;

#[derive(Deserialize, Validate)]
pub struct CreateUserRequest {
    #[validate(email(message = "Invalid email format"))]
    email: String,
    #[validate(length(min = 3, max = 30, message = "Username must be 3-30 characters"))]
    username: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    password: String,
}

async fn get_country_from_ip(ip: &str) -> Option<String> {
    let ip = if ip == "::1" || ip == "127.0.0.1" || ip.is_empty() {
        "72.229.28.185" // testing
    } else {
        ip
    };

    let url = format!("https://ipapi.co/{}/country/", ip);

    match reqwest::get(&url).await {
        Ok(response) => match response.text().await {
            Ok(country) => {
                if country == "Undefined" || country.trim().is_empty() {
                    None
                } else {
                    Some(country.trim().to_string())
                }
            }
            Err(_) => None,
        },
        Err(_) => None,
    }
}

#[derive(Serialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub username: String,
    pub created_at: DateTime<Utc>,
}

pub async fn get() -> Result<Html<String>, StatusCode> {
    let template = RegisterTemplate {
        title: "Register".to_string(),
        error: None,
    };

    let html = template
        .render()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Html(html))
}

pub async fn post(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(db): State<DatabaseConnection>,
    Form(req): Form<CreateUserRequest>,
) -> Result<Redirect, Html<String>> {
    if let Err(errors) = req.validate() {
        let error_msg = errors
            .field_errors()
            .values()
            .flat_map(|errs| errs.iter())
            .map(|err| err.message.as_ref().unwrap().to_string())
            .collect::<Vec<_>>()
            .join(", ");

        let template = RegisterTemplate {
            title: "Register - OAuth2 Server".to_string(),
            error: Some(error_msg),
        };

        let html = template
            .render()
            .map_err(|_| Html("Template error".to_string()))?;
        return Err(Html(html));
    }

    let password_hash = hash(req.password, DEFAULT_COST)
        .map_err(|_| Html("Password hashing failed".to_string()))?;

    let country = get_country_from_ip(&addr.ip().to_string()).await;

    let user = crate::user::ActiveModel {
        email: Set(req.email.clone()),
        username: Set(req.username.clone()),
        password_hash: Set(password_hash),
        is_admin: Set(false),
        is_active: Set(true),
        country: Set(country),
        ..Default::default()
    };

    match user.insert(&db).await {
        Ok(_) => Ok(Redirect::to("/?registered=true")),
        Err(_) => {
            let template = RegisterTemplate {
                title: "Register - OAuth2 Server".to_string(),
                error: Some("Email or username already exists".to_string()),
            };

            let html = template
                .render()
                .map_err(|_| Html("Template error".to_string()))?;
            Err(Html(html))
        }
    }
}