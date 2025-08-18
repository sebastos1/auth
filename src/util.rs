use sha2::{Sha256, Digest};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::{SystemRandom, SecureRandom};

pub fn generate_random_string(length: usize) -> String {
    let rng = SystemRandom::new();
    let mut bytes = vec![0u8; length];
    rng.fill(&mut bytes).unwrap();
    URL_SAFE_NO_PAD.encode(&bytes).chars().take(length).collect()
}

pub fn verify_pkce(code_verifier: &str, code_challenge: &str) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let hash = hasher.finalize();
    let computed_challenge = URL_SAFE_NO_PAD.encode(hash);
    computed_challenge == code_challenge
}