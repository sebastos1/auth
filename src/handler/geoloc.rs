use axum::http::HeaderMap;
use axum::{extract::Query, Json};
use serde::Deserialize;
use std::net::IpAddr;
use std::str::FromStr;

use crate::IS_PRODUCTION;

#[derive(Deserialize)]
pub struct GeolocateQuery {
    ip: String,
}

pub async fn get(Query(params): Query<GeolocateQuery>) -> Json<Option<String>> {
    let country = get_country_from_ip(&params.ip).await;
    Json(country)
}

pub async fn get_country_from_ip(ip_str: &str) -> Option<String> {
    println!("Geolocating IP: {ip_str}");

    if !*IS_PRODUCTION {
        return Some("NO".to_string());
    }

    let ip = IpAddr::from_str(ip_str).ok()?;
    let reader = maxminddb::Reader::open_readfile("GeoLite2-Country.mmdb").ok()?;
    
    let country_data = reader.lookup::<maxminddb::geoip2::Country>(ip).ok()??;
    country_data.country?.iso_code.map(std::string::ToString::to_string)
}

// get ip from headers
pub fn get_forwarded_ip(headers: &HeaderMap) -> Option<String> {
    if let Some(cf_ip) = headers.get("cf-connecting-ip")
        .and_then(|h| h.to_str().ok()) {
        return Some(cf_ip.to_string());
    }
    
    if let Some(forwarded) = headers.get("x-forwarded-for")
        .and_then(|h| h.to_str().ok()) {
        return forwarded.split(',').next().map(|ip| ip.trim().to_string());
    }
    
    headers.get("x-real-ip").and_then(|h| h.to_str().ok()).map(|ip| ip.to_string())
}