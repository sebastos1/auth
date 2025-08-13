use axum::{Form, http::StatusCode, extract::{Query, State}, response::{Html, Redirect}};
use sea_orm::*;
use serde::Deserialize;
use anyhow::Result;
use bcrypt::verify;
use validator::Validate;
use askama::Template;
use crate::{errors::{AuthError, error_redirect, error_page}, templates::LoginTemplate};
use crate::util::generate_random_string;

#[derive(Deserialize, Validate)]
pub struct LoginForm {
    #[validate(length(min = 1, message = "Login is required"))]
    login: String, // username, email optionally
    #[validate(length(min = 1, message = "Password is required"))]
    password: String,
    client_id: String,
    redirect_uri: String,
    state: Option<String>,
    scopes: String,
}

#[derive(Deserialize)]
pub struct AuthorizeQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    state: Option<String>,
}

pub async fn get(
    Query(params): Query<AuthorizeQuery>,
    State(db): State<DatabaseConnection>,
) -> Result<Html<String>, (StatusCode, Html<String>)> {
    if params.response_type != "code" {
        let error_page = error_page(AuthError::UnsupportedResponseType)
            .map_err(|status| (status, Html("Error".to_string())))?;
        return Err((StatusCode::BAD_REQUEST, error_page));
    }

    let client = crate::client::Entity::find_by_id(&params.client_id).one(&db).await
        .map_err(|_| {
            let error_page = error_page(AuthError::ServerError).unwrap();
            (StatusCode::INTERNAL_SERVER_ERROR, error_page)
        })?
        .ok_or_else(|| {
            let error_page = error_page(AuthError::UnauthorizedClient).unwrap();
            (StatusCode::BAD_REQUEST, error_page)
        })?;

    let requested_scopes: Vec<String> = params.scope
        .as_deref().unwrap_or("openid")
        .split_whitespace().map(|s| s.to_string())
        .collect();

    let allowed_scopes = client.get_allowed_scopes()
        .map_err(|_| {
            let error_page = error_page(AuthError::ServerError).unwrap();
            (StatusCode::INTERNAL_SERVER_ERROR, error_page)
        })?;

    for scope in &requested_scopes {
        if !allowed_scopes.contains(scope) {
            let error_page = error_page(AuthError::InvalidScope).unwrap();
            return Err((StatusCode::BAD_REQUEST, error_page));
        }
    }

    let template = LoginTemplate {
        title: "Login - OAuth2 Server".to_string(),
        client_id: params.client_id,
        redirect_uri: params.redirect_uri,
        state: params.state.unwrap_or_default(),
        scopes: requested_scopes.join(" "),
    };
    
    let html = template.render().map_err(|_| {
        let error_page = error_page(AuthError::ServerError).unwrap();
        (StatusCode::INTERNAL_SERVER_ERROR, error_page)
    })?;
    
    Ok(Html(html))
}

pub async fn post(
    State(db): State<DatabaseConnection>,
    Form(form): Form<LoginForm>,
) -> Result<Redirect, Redirect> {
    let user = crate::user::Entity::find()
        .filter(Condition::any()
            .add(crate::user::Column::Email.eq(&form.login))
            .add(crate::user::Column::Username.eq(&form.login)))
        .one(&db).await
        .map_err(|_| error_redirect(
            AuthError::ServerError, 
            &form.redirect_uri, 
            form.state.as_deref()
        ).unwrap())?
        .ok_or_else(|| error_redirect(
            AuthError::AccessDenied, 
            &form.redirect_uri, 
            form.state.as_deref()
        ).unwrap())?;

    let valid = verify(&form.password, &user.password_hash)
        .map_err(|_| error_redirect(
            AuthError::ServerError, 
            &form.redirect_uri, 
            form.state.as_deref()
        ).unwrap())?;

    if !valid {
        return Err(error_redirect(
            AuthError::AccessDenied, 
            &form.redirect_uri, 
            form.state.as_deref()
        ).unwrap());
    }

    let code = generate_random_string(32);
    let auth_code = crate::auth_code::ActiveModel {
        code: Set(code.clone()),
        client_id: Set(form.client_id),
        user_id: Set(user.id),
        redirect_uri: Set(form.redirect_uri.clone()),
        scopes: Set(form.scopes.clone()),
        ..Default::default()
    };
    
    auth_code.insert(&db).await.map_err(|_| error_redirect(
        AuthError::ServerError, 
        &form.redirect_uri, 
        form.state.as_deref()
    ).unwrap())?;

    let mut redirect_url = url::Url::parse(&form.redirect_uri)
        .map_err(|_| error_redirect(
            AuthError::InvalidRequest, 
            &form.redirect_uri, 
            form.state.as_deref()
        ).unwrap())?;
    
    redirect_url.query_pairs_mut().append_pair("code", &code);
    if let Some(state) = &form.state {
        redirect_url.query_pairs_mut().append_pair("state", state);
    }

    Ok(Redirect::to(&redirect_url.to_string()))
}