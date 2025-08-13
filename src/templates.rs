use askama::Template;

#[derive(Template)]
#[template(path = "register.html")]
pub struct RegisterTemplate {
    pub title: String,
    pub error: Option<String>,
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub title: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub scopes: String,
}

#[derive(Template)]
#[template(path = "error.html")]
pub struct ErrorTemplate {
    pub error: String,
    pub description: String,
}

#[derive(Template)]
#[template(path = "success.html")]
pub struct SuccessTemplate {
    pub code: Option<String>,
    pub error: Option<String>,
}
