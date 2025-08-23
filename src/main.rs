use anyhow::Result;
use axum::{
    Router, middleware as axum_mw,
    routing::{get, patch, post},
};
use std::time::Duration;
use std::{net::SocketAddr, sync::Arc};
use tower::ServiceBuilder;
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use tower_http::{limit::RequestBodyLimitLayer, timeout::TimeoutLayer, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod clients;
mod db;
mod entity;
mod error;
mod handler;
mod middleware;
mod password;
mod templates;
mod util;
use entity::{client, token, user};

use std::sync::LazyLock;

static IS_PRODUCTION: LazyLock<bool> = LazyLock::new(|| std::env::var("AUTH_ENV").unwrap_or_else(|_| "development".to_string()) == "production");

async fn get_redis_connection() -> Result<redis::aio::ConnectionManager, redis::RedisError> {
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    let client = redis::Client::open(redis_url)?;
    redis::aio::ConnectionManager::new(client).await
}

#[derive(Clone)]
pub struct AppState {
    pub db: sea_orm::DatabaseConnection,
    pub password: password::PasswordService,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "auth=debug,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // todo:
    // redirect uri validation

    let db = db::init_db().await?;

    let app_state = AppState {
        db: db.clone(),
        password: password::PasswordService::default(),
    };

    // basic rate limit
    let rate_limit_config = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(5)
            .burst_size(10)
            .finish()
            .unwrap(),
    );

    let app = Router::new()
        .route("/", get(|| async { "hello from sjallabong" }))
        .route("/token", post(handler::token::post))
        .route("/authorize", get(handler::auth::get).post(handler::auth::post))
        .route("/register", get(handler::register::get).post(handler::register::post))
        .route("/revoke", post(handler::revoke::post))
        .layer(GovernorLayer::new(rate_limit_config))
        .merge(
            Router::new()
                .route("/userinfo", get(handler::userinfo::get))
                .route("/update/user", patch(handler::update::user::patch))
                .layer(axum_mw::from_fn_with_state(
                    app_state.clone(),
                    middleware::user::user_auth_middleware,
                )),
        )
        .route("/success", get(handler::success::get))
        .route("/sdk", get(handler::sdk::get))
        .route("/geolocate", get(handler::geoloc::get))
        .with_state(app_state)
        .layer(axum_mw::from_fn(middleware::security::headers))
        .layer(ServiceBuilder::new().into_inner())
        .layer(TraceLayer::new_for_http())
        .layer(
            ServiceBuilder::new()
                .layer(TimeoutLayer::new(Duration::from_secs(30)))
                .into_inner(),
        )
        .layer(RequestBodyLimitLayer::new(1024 * 1024))
        .layer(middleware::security::cors_layer());

    let addr = SocketAddr::from(([0, 0, 0, 0], 3001));
    println!("Listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;

    Ok(())
}
