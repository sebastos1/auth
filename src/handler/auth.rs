use std::collections::HashMap;
use crate::templates::LoginTemplate;
use crate::util::generate_random_string;
use askama::Template;
use axum::{
    Form,
    extract::{Query, State},
    http::StatusCode,
    response::{Html, Redirect},
};
use bcrypt::verify;
use log::{error, info};
use sea_orm::*;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct LoginForm {
    login: String, // username, email optionally?
    password: String,

    client_id: String,
    redirect_uri: String,
    state: Option<String>,
    scopes: String,
    code_challenge: String,
    code_challenge_method: String,
}

#[derive(Deserialize, Debug)]
pub struct AuthorizeQuery {
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    state: String,
    code_challenge: String,
    code_challenge_method: String,
}

fn validate_login_format(form: &LoginForm) -> HashMap<String, String> {
    let mut errors = HashMap::new();

    if form.login.trim().is_empty() {
        errors.insert("login".to_string(), "Username or email is required".to_string());
    }

    if form.password.is_empty() {
        errors.insert("password".to_string(), "Password is required".to_string());
    }

    errors
}

async fn authenticate_user(form: &LoginForm, db: &DatabaseConnection) -> Result<crate::user::Model, String> {
    let user = match crate::user::Entity::find()
        .filter(
            Condition::any()
                .add(crate::user::Column::Email.eq(&form.login))
                .add(crate::user::Column::Username.eq(&form.login)),
        )
        .one(db)
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) => return Err("Invalid username or password".to_string()),
        Err(e) => {
            error!("Database error during login: {e}");
            return Err("Server error. Please try again.".to_string());
        }
    };

    match verify(&form.password, &user.password_hash) {
        Ok(true) => Ok(user),
        Ok(false) => Err("Invalid username or password".to_string()),
        Err(e) => {
            error!("Password verification error: {e}");
            Err("Server error. Please try again.".to_string())
        }
    }
}

pub async fn get(
    Query(params): Query<AuthorizeQuery>,
    State(db): State<DatabaseConnection>,
) -> Result<Html<String>, StatusCode> {
    if params.code_challenge_method != "S256" {
        error!("Invalid code_challenge_method: {}", params.code_challenge_method);
        return Err(StatusCode::BAD_REQUEST);
    }

    if params.code_challenge.is_empty() || params.state.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let client = match crate::client::Entity::find_by_id(&params.client_id).one(&db).await {
        Ok(Some(client)) => client,
        Ok(None) => return Err(StatusCode::BAD_REQUEST),
        Err(e) => {
            error!("Database error finding client: {e}");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let requested_scopes: Vec<String> = params
        .scope
        .as_deref()
        .unwrap_or("openid")
        .split_whitespace()
        .map(std::string::ToString::to_string)
        .collect();

    let allowed_scopes = match client.get_allowed_scopes() {
        Ok(scopes) => scopes,
        Err(e) => {
            error!("Error getting allowed scopes: {e}");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    for scope in &requested_scopes {
        if !allowed_scopes.contains(scope) {
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    let template = LoginTemplate {
        client_id: params.client_id,
        redirect_uri: params.redirect_uri,
        state: params.state,
        scopes: requested_scopes.join(" "),
        errors: HashMap::new(),
        login: String::new(),

        code_challenge: params.code_challenge,
        code_challenge_method: params.code_challenge_method,
    };

    template
        .render()
        .map(Html)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

pub async fn post(State(db): State<DatabaseConnection>, Form(form): Form<LoginForm>) -> Result<Redirect, Html<String>> {
    let render_error = |errors: HashMap<String, String>| {
        let template = LoginTemplate {
            client_id: form.client_id.clone(),
            redirect_uri: form.redirect_uri.clone(),
            state: form.state.clone().unwrap_or_default(),
            scopes: form.scopes.clone(),
            errors,
            login: form.login.clone(),
            code_challenge: form.code_challenge.clone(),
            code_challenge_method: form.code_challenge_method.clone(),
        };
        Html(template.render().unwrap())
    };

    let format_errors = validate_login_format(&form);
    if !format_errors.is_empty() {
        return Err(render_error(format_errors));
    }

    let user = match authenticate_user(&form, &db).await {
        Ok(user) => user,
        Err(error_msg) => {
            let mut errors = HashMap::new();
            errors.insert("general".to_string(), error_msg);
            return Err(render_error(errors));
        }
    };

    info!("User authenticated: {}", user.username);

    let code = generate_random_string(32);
    let auth_code = crate::token::auth::ActiveModel {
        code: Set(code.clone()),
        client_id: Set(form.client_id.clone()),
        user_id: Set(user.id),
        redirect_uri: Set(form.redirect_uri.clone()),
        scopes: Set(form.scopes.clone()),
        code_challenge: Set(form.code_challenge.clone()),
        code_challenge_method: Set(form.code_challenge_method.clone()),
        ..Default::default()
    };

    if let Err(e) = auth_code.insert(&db).await {
        error!("Failed to create auth code: {e}");
        let mut errors = HashMap::new();
        errors.insert("general".to_string(), "Server error. Please try again.".to_string());
        return Err(render_error(errors));
    }

    let mut redirect_url = match url::Url::parse(&form.redirect_uri) {
        Ok(url) => url,
        Err(e) => {
            error!("Invalid redirect URI: {e}");
            let mut errors = HashMap::new();
            errors.insert("general".to_string(), "Invalid redirect URI".to_string());
            return Err(render_error(errors));
        }
    };

    redirect_url.query_pairs_mut().append_pair("code", &code);
    if let Some(state) = &form.state {
        redirect_url.query_pairs_mut().append_pair("state", state);
    }

    Ok(Redirect::to(redirect_url.as_ref()))
}
