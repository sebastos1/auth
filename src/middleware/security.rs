use axum::{
    extract::Request,
    http::{HeaderValue, Method, header},
    middleware::Next,
    response::Response,
};
use std::time::Duration;
use tower_http::cors::{AllowOrigin, CorsLayer};

pub fn cors_layer() -> CorsLayer {
    if *crate::IS_PRODUCTION {
        CorsLayer::new()
            .allow_origin(AllowOrigin::list([
                "https://sjallabong.eu".parse::<HeaderValue>().unwrap(),
                "https://pool.sjallabong.eu".parse::<HeaderValue>().unwrap(),
            ]))
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers([
                header::CONTENT_TYPE,
                header::AUTHORIZATION,
                "x-forwarded-host".parse::<header::HeaderName>().unwrap(),
                "x-forwarded-for".parse::<header::HeaderName>().unwrap(),
            ])
            .allow_credentials(true)
            .max_age(Duration::from_secs(3600))
    } else {
        CorsLayer::very_permissive()
    }
}

pub async fn headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();

    let csp = if *crate::IS_PRODUCTION {
        "default-src 'self'; \
        script-src 'self' 'unsafe-inline'; \
        style-src 'self' 'unsafe-inline'; \
        img-src 'self' data: https:; \
        form-action 'self'; \
        frame-ancestors 'none'; \
        base-uri 'self'"
    } else {
        "default-src 'self' 'unsafe-inline' 'unsafe-eval'; \
        img-src 'self' data: http: https:; \
        form-action 'self'; \
        frame-ancestors 'none'"
    };

    headers.insert(header::CONTENT_SECURITY_POLICY, csp.parse().unwrap());

    headers.insert("x-frame-options", "DENY".parse().unwrap());
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("x-xss-protection", "1; mode=block".parse().unwrap());
    headers.insert(
        header::REFERRER_POLICY,
        "strict-origin-when-cross-origin".parse().unwrap(),
    );

    // Only add HSTS in production
    if *crate::IS_PRODUCTION {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            "max-age=31536000; includeSubDomains".parse().unwrap(),
        );
    }

    response
}
