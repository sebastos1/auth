use axum::{extract::Query, response::Html};

#[derive(serde::Deserialize)]
pub struct SuccessQuery {
    code: Option<String>,
    error: Option<String>,
    state: Option<String>,
}

pub async fn get(Query(params): Query<SuccessQuery>) -> Html<String> {
    let message_type = if params.code.is_some() {
        "AUTH_SUCCESS"
    } else {
        "AUTH_ERROR"
    };

    Html(format!(
        r#"<script>
            window.opener.postMessage({{
                type: "{}",
                code: "{}",
                error: "{}",
                state: "{}"
            }}, "*");
            window.close();
        </script>"#,
        message_type,
        params.code.unwrap_or_default(),
        params.error.unwrap_or_default(),
        params.state.unwrap_or_default()
    ))
}
