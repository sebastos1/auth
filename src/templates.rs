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
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub errors: HashMap<String, String>,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub scopes: String,

    // preserve
    pub login: String,
}

// injects the auth server url into the sdk so it knows where to send requests
#[derive(Template)]
#[template(path = "sdk.js", escape = "none")]
pub struct SdkTemplate {
    pub auth_server_url: String,
}
