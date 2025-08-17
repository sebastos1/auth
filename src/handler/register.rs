use crate::{templates::RegisterTemplate};
use crate::handler::geoloc::get_country_from_ip;
use askama::Template;
use axum::{
    extract::{ConnectInfo, Query, State}, response::{Html, Redirect}, Form
};
use bcrypt::{DEFAULT_COST, hash};
use log::{error, info};
use reqwest::StatusCode;
use sea_orm::*;
use serde::Deserialize;
use std::{collections::HashMap, net::SocketAddr};

#[derive(Deserialize)]
pub struct CreateUserRequest {
    email: String,
    username: String,
    password: String,
    client_id: String,
    redirect_uri: String,
    state: Option<String>,
    scopes: String,
}

#[derive(Deserialize)]
pub struct RegisterQuery {
    client_id: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
}

// this needs the client id and allat in order to login after
pub async fn get(Query(oauth_params): Query<RegisterQuery>) -> Result<Html<String>, StatusCode> {
    let template = RegisterTemplate {
        errors: HashMap::new(),
        email: String::new(),
        username: String::new(),
        client_id: oauth_params.client_id.unwrap_or_default(),
        redirect_uri: oauth_params.redirect_uri.unwrap_or_default(),
        state: oauth_params.state.unwrap_or_default(),
        scopes: oauth_params.scope.unwrap_or_default(),
    };
    
    template.render().map(Html).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn validate_format(req: &CreateUserRequest) -> HashMap<String, String> {
    let mut errors = HashMap::new();

    if req.email.is_empty() || !req.email.contains('@') {
        errors.insert("email".to_string(), "Please enter a valid email address".to_string());
    }

    if req.username.len() < 3 || req.username.len() > 30 {
        errors.insert(
            "username".to_string(),
            "Username must be between 3 and 30 characters".to_string(),
        );
    }

    if req.password.len() < 8 {
        errors.insert(
            "password".to_string(),
            "Password must be at least 8 characters".to_string(),
        );
    }

    errors
}

async fn validate_database(req: &CreateUserRequest, db: &DatabaseConnection) -> HashMap<String, String> {
    let mut errors = HashMap::new();

    match crate::user::Entity::find()
        .filter(
            Condition::any()
                .add(crate::user::Column::Email.eq(&req.email))
                .add(crate::user::Column::Username.eq(&req.username)),
        )
        .one(db)
        .await
    {
        Ok(Some(existing)) => {
            if existing.email == req.email {
                errors.insert("email".to_string(), "This email is already registered".to_string());
            }
            if existing.username == req.username {
                errors.insert("username".to_string(), "This username is already taken".to_string());
            }
        }
        Ok(None) => {}
        Err(e) => {
            error!("Database error during user lookup: {}", e);
            errors.insert("general".to_string(), "Server error. Please try again.".to_string());
        }
    }

    errors
}

// redirects if successful, returns html form the form if fails
pub async fn post(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(db): State<DatabaseConnection>,
    Form(req): Form<CreateUserRequest>,
) -> Result<Redirect, Html<String>> {
    let render_error = |errors: HashMap<String, String>| {
        let template = RegisterTemplate {
            errors,
            email: req.email.clone(),
            username: req.username.clone(),
            client_id: req.client_id.clone(),
            redirect_uri: req.redirect_uri.clone(),
            state: req.state.clone().unwrap_or_default(),
            scopes: req.scopes.clone(),
        };
        Html(template.render().unwrap())
    };

    // check format fast first
    let format_errors = validate_format(&req);
    if !format_errors.is_empty() {
        return Err(render_error(format_errors));
    }

    // db check
    let db_errors = validate_database(&req, &db).await;
    if !db_errors.is_empty() {
        return Err(render_error(db_errors));
    }

    let password_hash = match hash(req.password, DEFAULT_COST) {
        Ok(hash) => hash,
        Err(e) => {
            error!("Password hashing failed: {}", e);
            let mut errors = HashMap::new();
            errors.insert(
                "general".to_string(),
                "Registration failed. Please try again.".to_string(),
            );
            return Err(render_error(errors));
        }
    };

    let country = get_country_from_ip(&addr.ip().to_string()).await;

    let user = crate::user::ActiveModel {
        email: Set(req.email.clone()),
        username: Set(req.username.clone()),
        password_hash: Set(password_hash),
        country: Set(country),
        ..Default::default()
    };

    match user.insert(&db).await {
        Ok(_) => {
            info!("Registered user: {}", req.username);
            let redirect_url = format!(
                "/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}",
                urlencoding::encode(&req.client_id),
                urlencoding::encode(&req.redirect_uri), 
                urlencoding::encode(&req.scopes),
                urlencoding::encode(&req.state.unwrap_or_default())
            );
            Ok(Redirect::to(&redirect_url))
        }
        Err(e) => {
            error!("Failed to create user: {}", e);
            let mut errors = HashMap::new();
            errors.insert(
                "general".to_string(),
                "Registration failed. Please try again.".to_string(),
            );
            Err(render_error(errors))
        }
    }
}
