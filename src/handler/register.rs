use crate::{templates::RegisterTemplate};
use crate::handler::geoloc::{get_country_from_ip, get_forwarded_ip};
use askama::Template;
use axum::http::HeaderMap;
use axum::{extract::{ConnectInfo, Query, State}, response::{Html, Redirect}, Form};
use bcrypt::{DEFAULT_COST, hash};
use sea_orm::*;
use serde::Deserialize;
use std::{collections::HashMap, net::SocketAddr};
use crate::error::{AppError, FormResponse};

#[derive(Deserialize)]
pub struct CreateUserRequest {
    email: String,
    username: String,
    password: String,
    client_id: String,
    redirect_uri: String,
    state: String,
    scopes: String,
    code_challenge: String,
    code_challenge_method: String,
}

#[derive(Deserialize)]
pub struct RegisterQuery {
    client_id: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: String,
    code_challenge: String,
    code_challenge_method: String,
}

// this needs the client id and allat in order to login after
pub async fn get(Query(oauth_params): Query<RegisterQuery>) -> Result<Html<String>, AppError> {
    let template = RegisterTemplate {
        errors: HashMap::new(),
        email: String::new(),
        username: String::new(),
        client_id: oauth_params.client_id.unwrap_or_default(),
        redirect_uri: oauth_params.redirect_uri.unwrap_or_default(),
        state: oauth_params.state,
        scopes: oauth_params.scope.unwrap_or_default(),
        code_challenge: oauth_params.code_challenge,
        code_challenge_method: oauth_params.code_challenge_method,
    };
    Ok(Html(template.render()?))
}

fn validate_format(req: &CreateUserRequest) -> HashMap<String, String> {
    let mut errors = HashMap::new();

    if req.email.is_empty() || !req.email.contains('@') {
        errors.insert("email".to_string(), "Please enter a valid email address".to_string());
    }

    if req.username.len() < 3 || req.username.len() > 30 {
        errors.insert("username".to_string(), "Username must be between 3 and 30 characters".to_string());
    }

    if req.password.len() < 8 {
        errors.insert("password".to_string(), "Password must be at least 8 characters".to_string());
    }

    errors
}

async fn validate_database(req: &CreateUserRequest, db: &DatabaseConnection) -> Result<HashMap<String, String>, AppError> {
    let mut errors = HashMap::new();

    let existing = crate::user::Entity::find()
        .filter(
            Condition::any()
                .add(crate::user::Column::Email.eq(&req.email))
                .add(crate::user::Column::Username.eq(&req.username)),
        )
        .one(db).await?;

    if let Some(existing_user) = existing {
        if existing_user.email == req.email {
            errors.insert("email".to_string(), "This email is already registered".to_string());
        }
        if existing_user.username == req.username {
            errors.insert("username".to_string(), "This username is already taken".to_string());
        }
    }

    Ok(errors)
}

// redirects if successful, returns html form the form if fails
pub async fn post(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(db): State<DatabaseConnection>,
    Form(req): Form<CreateUserRequest>,
) -> Result<FormResponse<Redirect>, AppError> {
    let render_error = |errors: HashMap<String, String>| -> Result<FormResponse<Redirect>, AppError> {
        let template = RegisterTemplate {
            errors,
            email: req.email.clone(),
            username: req.username.clone(),
            client_id: req.client_id.clone(),
            redirect_uri: req.redirect_uri.clone(),
            state: req.state.clone(),
            scopes: req.scopes.clone(),
            code_challenge: req.code_challenge.clone(),
            code_challenge_method: req.code_challenge_method.clone(),
        };
        let rendered = template.render()?;
        Ok(FormResponse::ValidationErrors(Html(rendered)))
    };

    // check format fast first
    let format_errors = validate_format(&req);
    if !format_errors.is_empty() {
        return render_error(format_errors);
    }

    // db check
    let db_errors = validate_database(&req, &db).await?;
    if !db_errors.is_empty() {
        return render_error(db_errors);
    }

    let password_hash = hash(req.password, DEFAULT_COST)?;

    let ip = get_forwarded_ip(&headers).unwrap_or_else(|| addr.ip().to_string());
    let country = get_country_from_ip(&ip).await;

    let user = crate::user::ActiveModel {
        email: Set(req.email.clone()),
        username: Set(req.username.clone()),
        password_hash: Set(password_hash),
        country: Set(country),
        ..Default::default()
    };
    
    user.insert(&db).await?;

    let redirect_url = format!(
        "/authorize?client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method={}",
        urlencoding::encode(&req.client_id),
        urlencoding::encode(&req.redirect_uri), 
        urlencoding::encode(&req.scopes),
        urlencoding::encode(&req.state),
        urlencoding::encode(&req.code_challenge),
        urlencoding::encode(&req.code_challenge_method)
    );
    
    Ok(FormResponse::Success(Redirect::to(&redirect_url)))
}