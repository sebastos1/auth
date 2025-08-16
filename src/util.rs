use rand::Rng;

pub fn generate_random_string(length: usize) -> String {
    let charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();

    (0..length)
        .map(|_| {
            let idx = rng.random_range(0..charset.len());
            charset[idx] as char
        })
        .collect()
}

pub async fn get_country_from_ip(ip: &str) -> Option<String> {
    let ip = if ip == "::1" || ip == "127.0.0.1" || ip.is_empty() {
        "72.229.28.185" // testing
    } else {
        ip
    };

    let url = format!("https://ipapi.co/{}/country/", ip);

    let response = reqwest::get(&url).await.ok()?;
    let country = response.text().await.ok()?;
    let country = country.trim();
    println!("Country for IP {}: {}", ip, country);
    if country == "Undefined" || country.is_empty() {
        None
    } else {
        Some(country.to_string())
    }
}
