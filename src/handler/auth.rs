use crate::AppState;
use crate::error::{AppError, HtmlError, OptionExt};
use crate::util::generate_random_string;
use crate::{error::FormResponse, templates::LoginTemplate};
use anyhow::Context;
use askama::Template;
use axum::extract::ConnectInfo;
use axum::http::HeaderMap;
use axum::{
    Form,
    extract::{Query, State},
    response::{Html, Redirect},
};
use sea_orm::*;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use tracing::info;

#[derive(Deserialize, Debug, Clone)]
pub struct OAuthParams {
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub scope: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
}

#[derive(Deserialize, Debug)]
pub struct LoginForm {
    login: String, // username
    password: String,
    csrf_token: String,
    #[serde(flatten)]
    pub oauth: OAuthParams,
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
    let user = crate::user::Entity::find()
        .filter(crate::user::Column::Username.eq(&form.login))
        .one(&app_state.db)
        .await?
        .or_unauthorized("Invalid username or password")?;

    if app_state.password.verify(&form.password, &user.password_hash)? {
        Ok(user)
    } else {
        Err(AppError::unauthorized("Invalid username or password"))
    }
}

pub async fn get(
    Query(oauth): Query<OAuthParams>,
    State(app_state): State<AppState>,
) -> Result<Html<String>, HtmlError> {
    info!(
        client_id = %oauth.client_id,
        scopes = ?oauth.scope,
        "Authorization request started"
    );

    if oauth.code_challenge_method != "S256" {
        return Err(AppError::bad_request(format!(
            "Invalid code challenge method: {}",
            oauth.code_challenge_method
        ))
        .into());
    }

    if oauth.code_challenge.is_empty() || oauth.state.is_empty() {
        return Err(AppError::bad_request("Missing code challenge or state").into());
    }

    let client = crate::util::get_client(&oauth.client_id, &app_state.db).await?;

    crate::util::validate_redirect_uri(&client, &oauth.redirect_uri)?;

    let requested_scopes: Vec<String> = oauth.scope.split_whitespace().map(String::from).collect();

    let allowed_scopes = client.get_allowed_scopes()?;
    for scope in &requested_scopes {
        if !allowed_scopes.contains(scope) {
            return Err(AppError::bad_request(format!(
                "Scope '{}' not allowed for client '{}'",
                scope, oauth.client_id
            ))
            .into());
        }
    }

    let template = LoginTemplate {
        client_id: oauth.client_id,
        redirect_uri: oauth.redirect_uri,
        state: oauth.state,
        scope: oauth.scope,
        errors: HashMap::new(),
        login: String::new(),
        code_challenge: oauth.code_challenge,
        code_challenge_method: oauth.code_challenge_method,
        csrf_token: crate::util::generate_csrf_token().await,
    };

    Ok(Html(template.render()?))
}

pub async fn post(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(app_state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> Result<FormResponse<Redirect>, HtmlError> {
    let oauth = &form.oauth;
    let render_error =
        async |errors: HashMap<String, String>, form: &LoginForm| -> Result<FormResponse<Redirect>, HtmlError> {
            let template = LoginTemplate {
                client_id: oauth.client_id.clone(),
                redirect_uri: oauth.redirect_uri.clone(),
                state: oauth.state.clone(),
                scope: oauth.scope.clone(),
                errors,
                login: form.login.clone(),
                code_challenge: oauth.code_challenge.clone(),
                code_challenge_method: oauth.code_challenge_method.clone(),
                csrf_token: crate::util::generate_csrf_token().await,
            };
            Ok(FormResponse::ValidationErrors(Html(template.render()?)))
        };

    let format_errors = validate_login_format(&form);
    if !format_errors.is_empty() {
        return render_error(format_errors, &form).await;
    }

    if !crate::util::validate_csrf_token(&form.csrf_token).await {
        let mut errors = HashMap::new();
        errors.insert("csrf".to_string(), "Invalid request, try again".to_string());
        return render_error(errors, &form).await;
    }

    let user = match authenticate_user(&form, &app_state).await {
        Ok(user) => user,
        Err(AppError::Unauthorized(msg)) => {
            let mut errors = HashMap::new();
            errors.insert("general".to_string(), msg);
            return render_error(errors, &form).await;
        }
        Err(e) => return Err(e.into()),
    };

    let code = generate_random_string(32);
    let auth_code = crate::token::auth::ActiveModel {
        code: Set(code.clone()),
        client_id: Set(form.oauth.client_id.clone()),
        user_id: Set(user.id.clone()),
        redirect_uri: Set(form.oauth.redirect_uri.clone()),
        scopes: Set(form.oauth.scope.clone()),
        code_challenge: Set(form.oauth.code_challenge.clone()),
        code_challenge_method: Set(form.oauth.code_challenge_method.clone()),
        ..Default::default()
    };

    auth_code
        .insert(&app_state.db)
        .await
        .context("Failed to create auth code")?;

    let mut redirect_url = url::Url::parse(&form.oauth.redirect_uri).context("Invalid redirect URI")?;

    let client = crate::client::Entity::find_by_id(&form.oauth.client_id)
        .one(&app_state.db)
        .await?
        .or_bad_request(format!("Invalid client_id: {}", form.oauth.client_id))?;
    crate::util::validate_redirect_uri(&client, &form.oauth.redirect_uri)?;

    redirect_url.query_pairs_mut().append_pair("code", &code);
    redirect_url.query_pairs_mut().append_pair("state", &form.oauth.state);

    // if a user doesn't have a country, quick check. should only realistically happen on register, and
    // NEVER if they already have a country!!!!! + it can be changed by them later :)
    if user.country.is_none() {
        let user_ip = crate::handler::geoloc::get_forwarded_ip(&headers).unwrap_or_else(|| addr.ip().to_string());
        let user_id = user.id.clone();
        let db = app_state.db.clone();
        tokio::spawn(async move {
            if let Some(country) = crate::handler::geoloc::get_country_from_ip(&user_ip).await {
                let _ = crate::user::Entity::update_country(&user_id, &country, &db).await;
            }
        });
    }

    Ok(FormResponse::Success(Redirect::to(redirect_url.as_ref())))
}
