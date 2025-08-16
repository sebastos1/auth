use axum::{extract::Query, Json};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Deserialize)]
pub struct GeolocateQuery {
    ip: String,
}

#[derive(Serialize)]
pub struct GeolocateResponse {
    country: Option<String>,
}

pub async fn get(Query(params): Query<GeolocateQuery>) -> Json<GeolocateResponse> {
    let country = get_country_from_ip_maxmind(&params.ip).await;
    Json(GeolocateResponse { country })
}

async fn get_country_from_ip_maxmind(ip_str: &str) -> Option<String> {
    let ip_str = if ip_str == "::1" || ip_str == "127.0.0.1" || ip_str.is_empty() {
        "72.229.28.185"
    } else {
        ip_str
    };

    println!("Geolocating IP: {}", ip_str);

    let ip = IpAddr::from_str(ip_str).ok()?;
    let reader = maxminddb::Reader::open_readfile("GeoLite2-Country.mmdb").ok()?;
    
    let country_data = reader.lookup::<maxminddb::geoip2::Country>(ip).ok()??;
    country_data.country?.iso_code.map(|code| code.to_string())
}