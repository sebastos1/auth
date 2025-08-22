use std::collections::HashMap;
use crate::AppState;
use crate::{error::FormResponse, templates::LoginTemplate};
use crate::util::generate_random_string;
use askama::Template;
use axum::{
    extract::{Query, State}, http::HeaderMap, response::{Html, Redirect}, Form
};
use sea_orm::*;
use serde::Deserialize;
use tracing::info;
use anyhow::Context;
use crate::error::{AppError, HtmlError, OptionExt};

#[derive(Deserialize, Debug)]
pub struct LoginForm {
    login: String, // username
    password: String,

    client_id: String,
    redirect_uri: String,
    state: Option<String>,
    scopes: String,
    code_challenge: String,
    code_challenge_method: String,
    csrf_token: String,
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
        errors.insert("login".to_string(), "Username is required".to_string());
    }

    if form.password.is_empty() {
        errors.insert("password".to_string(), "Password is required".to_string());
    }

    errors
}

async fn authenticate_user(form: &LoginForm, app_state: &AppState) -> Result<crate::user::Model, AppError> {
    let user = crate::user::Entity::find().filter(crate::user::Column::Username.eq(&form.login))
        .one(&app_state.db).await?.or_unauthorized("Invalid username or password")?;

    if app_state.password.verify(&form.password, &user.password_hash)? {
        Ok(user)
    } else {
        Err(AppError::unauthorized("Invalid username or password"))
    }
}

pub async fn get(
    Query(params): Query<AuthorizeQuery>,
    State(app_state): State<AppState>,
    headers: HeaderMap,
) -> Result<Html<String>, HtmlError> {
    info!(
        client_id = %params.client_id,
        scopes = ?params.scope,
        "Authorization request started"
    );

    if params.code_challenge_method != "S256" {
        return Err(AppError::bad_request(format!("Invalid code challenge method: {}", params.code_challenge_method)).into());
    }

    if params.code_challenge.is_empty() || params.state.is_empty() {
        return Err(AppError::bad_request("Missing code challenge or state").into());
    }

    let client = crate::util::validate_client_origin(&params.client_id, &headers, &app_state.db).await?;
    info!("Client origin validated successfully");

    let requested_scopes: Vec<String> = params.scope
        .as_deref().unwrap_or("openid")
        .split_whitespace().map(String::from).collect();

    let allowed_scopes = client.get_allowed_scopes()?;
    for scope in &requested_scopes {
        if !allowed_scopes.contains(scope) {
            return Err(AppError::bad_request(format!("Scope '{}' not allowed for client '{}'", scope, params.client_id)).into());
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
        csrf_token: crate::util::generate_csrf_token().await,
    };

    Ok(Html(template.render()?))
}

pub async fn post(
    State(app_state): State<AppState>,
    Form(form): Form<LoginForm>
) -> Result<FormResponse<Redirect>, HtmlError> {
    let render_error = async |errors: HashMap<String, String>| -> Result<FormResponse<Redirect>, HtmlError> {
        let template = LoginTemplate {
            client_id: form.client_id.clone(),
            redirect_uri: form.redirect_uri.clone(),
            state: form.state.clone().unwrap_or_default(),
            scopes: form.scopes.clone(),
            errors,
            login: form.login.clone(),
            code_challenge: form.code_challenge.clone(),
            code_challenge_method: form.code_challenge_method.clone(),
            csrf_token: crate::util::generate_csrf_token().await,
        };
        let rendered = template.render()?;
        Ok(FormResponse::ValidationErrors(Html(rendered)))
    };

    let format_errors = validate_login_format(&form);
    if !format_errors.is_empty() {
        return render_error(format_errors).await;
    }

    if !crate::util::validate_csrf_token(&form.csrf_token).await {
        let mut errors = HashMap::new();
        errors.insert("csrf".to_string(), "Invalid request, try again".to_string());
        return render_error(errors).await;
    }

    let user = match authenticate_user(&form, &app_state).await {
        Ok(user) => user,
        Err(AppError::Unauthorized(msg)) => {
            let mut errors = HashMap::new();
            errors.insert("general".to_string(), msg);
            return render_error(errors).await;
        }
        Err(e) => return Err(e.into()),
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

    auth_code.insert(&app_state.db).await.context("Failed to create auth code")?;

    let mut redirect_url = url::Url::parse(&form.redirect_uri).context("Invalid redirect URI")?;

    redirect_url.query_pairs_mut().append_pair("code", &code);
    if let Some(state) = &form.state {
        redirect_url.query_pairs_mut().append_pair("state", state);
    }

    Ok(FormResponse::Success(Redirect::to(redirect_url.as_ref())))
}
