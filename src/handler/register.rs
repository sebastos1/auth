use crate::AppState;
use crate::error::{AppError, FormResponse, HtmlError};
use crate::handler::geoloc::{get_country_from_ip, get_forwarded_ip};
use crate::templates::RegisterTemplate;
use askama::Template;
use axum::http::HeaderMap;
use axum::{
    Form,
    extract::{ConnectInfo, Query, State},
    response::{Html, Redirect},
};
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
    state: String,
    scopes: String,
    code_challenge: String,
    code_challenge_method: String,
    csrf_token: String,
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
pub async fn get(Query(oauth_params): Query<RegisterQuery>) -> Result<Html<String>, HtmlError> {
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
        csrf_token: crate::util::generate_csrf_token().await,
    };
    Ok(Html(template.render()?))
}

#[derive(PartialEq, Eq, Hash)]
enum InputError {
    Email,
    Username,
    Password,
}

fn validate_format(req: &CreateUserRequest) -> HashMap<String, String> {
    let mut errors = HashMap::new();

    if req.email.is_empty() || !req.email.contains('@') {
        errors.insert(InputError::Email, "Please enter a valid email address");
    }

    if req.username.trim() != req.username {
        errors.insert(InputError::Username, "Username cannot start or end with spaces");
    }

    let username = req.username.trim();
    if username.contains("  ") {
        errors.insert(InputError::Username, "Username cannot contain consecutive spaces");
    }

    fn is_valid_username(c: char) -> bool {
        c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ' ' | '\'')
    }

    if !username.chars().all(is_valid_username) {
        errors.insert(InputError::Username, "Something not allowed in username");
    }

    if username.len() < 3 || username.len() > 24 {
        errors.insert(InputError::Username, "Username must be 3-24 characters");
    }

    if req.password.len() < 6 || req.password.len() > 128 {
        errors.insert(InputError::Password, "Password must be 6+ characters long");
    }

    errors
        .into_iter()
        .map(|(k, v)| {
            let key = match k {
                InputError::Email => "email",
                InputError::Username => "username",
                InputError::Password => "password",
            };
            (key.to_string(), v.to_string())
        })
        .collect()
}

async fn validate_database(
    req: &CreateUserRequest,
    db: &DatabaseConnection,
) -> Result<HashMap<String, String>, AppError> {
    let mut errors = HashMap::new();

    let existing = crate::user::Entity::find()
        .filter(
            Condition::any()
                .add(crate::user::Column::Email.eq(&req.email))
                .add(crate::user::Column::Username.eq(&req.username)),
        )
        .one(db)
        .await?;

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
    State(app_state): State<AppState>,
    Form(form): Form<CreateUserRequest>,
) -> Result<FormResponse<Redirect>, HtmlError> {
    let render_error = async |errors: HashMap<String, String>| -> Result<FormResponse<Redirect>, HtmlError> {
        let template = RegisterTemplate {
            errors,
            email: form.email.clone(),
            username: form.username.clone(),
            client_id: form.client_id.clone(),
            redirect_uri: form.redirect_uri.clone(),
            state: form.state.clone(),
            scopes: form.scopes.clone(),
            code_challenge: form.code_challenge.clone(),
            code_challenge_method: form.code_challenge_method.clone(),
            csrf_token: crate::util::generate_csrf_token().await,
        };
        let rendered = template.render()?;
        Ok(FormResponse::ValidationErrors(Html(rendered)))
    };

    if !crate::util::validate_csrf_token(&form.csrf_token).await {
        let mut errors = HashMap::new();
        errors.insert("csrf".to_string(), "Invalid request, try again".to_string());
        return render_error(errors).await;
    }

    // check format fast first
    let format_errors = validate_format(&form);
    if !format_errors.is_empty() {
        return render_error(format_errors).await;
    }

    // db check
    let db_errors = validate_database(&form, &app_state.db).await?;
    if !db_errors.is_empty() {
        return render_error(db_errors).await;
    }

    let password_hash = app_state.password.hash(&form.password)?;

    let ip = get_forwarded_ip(&headers).unwrap_or_else(|| addr.ip().to_string());
    let country = get_country_from_ip(&ip).await;

    let user = crate::user::ActiveModel {
        email: Set(form.email.clone()),
        username: Set(form.username.clone()),
        password_hash: Set(password_hash),
        country: Set(country),
        ..Default::default()
    };

    user.insert(&app_state.db).await?;

    let redirect_url = format!(
        "/authorize?client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method={}",
        urlencoding::encode(&form.client_id),
        urlencoding::encode(&form.redirect_uri),
        urlencoding::encode(&form.scopes),
        urlencoding::encode(&form.state),
        urlencoding::encode(&form.code_challenge),
        urlencoding::encode(&form.code_challenge_method)
    );

    Ok(FormResponse::Success(Redirect::to(&redirect_url)))
}
