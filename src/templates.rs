use std::collections::HashMap;

use askama::Template;

#[derive(Template)]
#[template(path = "register.html")]
pub struct RegisterTemplate {
    pub errors: HashMap<String, String>,
    // preserve
    pub email: String,
    pub username: String,
    pub csrf_token: String,

    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub scope: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub errors: HashMap<String, String>,
    pub login: String, // preserve
    pub csrf_token: String,

    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub scope: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
}

#[derive(Template)]
#[template(path = "error.html")]
pub struct ErrorTemplate {
    pub status_code: u16,
    pub message: String,
}
