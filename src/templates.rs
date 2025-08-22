use std::collections::HashMap;

use askama::Template;

#[derive(Template)]
#[template(path = "register.html")]
pub struct RegisterTemplate {
    pub errors: HashMap<String, String>,

    // preserve
    pub email: String,
    pub username: String,

    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub scopes: String,
    pub code_challenge: String,
    pub code_challenge_method: String,

    pub csrf_token: String,
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub errors: HashMap<String, String>,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub scopes: String,
    pub code_challenge: String,
    pub code_challenge_method: String,

    // preserve
    pub login: String,

    pub csrf_token: String,
}

// injects the auth server url into the sdk so it knows where to send requests
#[derive(Template)]
#[template(path = "sdk.js", escape = "none")]
pub struct SdkTemplate;

#[derive(Template)]
#[template(path = "error.html")]
pub struct ErrorTemplate {
    pub status_code: u16,
    pub message: String,
}
