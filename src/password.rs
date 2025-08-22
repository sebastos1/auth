use anyhow::{Result, anyhow};
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};

#[derive(Clone)]
pub struct PasswordService {
    argon2: Argon2<'static>,
    pepper: String,
}

impl Default for PasswordService {
    fn default() -> Self {
        let params = Params::new(
            15000, // owasp recommends 19432
            2,
            1,
            Some(32),
        )
        .expect("Invalid Argon2 config");
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let pepper = std::env::var("PASSWORD_PEPPER").unwrap_or_else(|_| "asdfadsfdsafadsfadsfadsasdf".to_string());
        Self { argon2, pepper }
    }
}

impl PasswordService {
    pub fn hash(&self, password: &str) -> Result<String> {
        let peppered = format!("{}{}", password, self.pepper);

        let salt = SaltString::generate(&mut OsRng);
        let hash = self
            .argon2
            .hash_password(peppered.as_bytes(), &salt)
            .map_err(|e| anyhow!("Password hashing failed: {}", e))?;

        Ok(hash.to_string())
    }

    pub fn verify(&self, password: &str, hash: &str) -> Result<bool> {
        let peppered = format!("{}{}", password, self.pepper);

        let parsed_hash = PasswordHash::new(hash).map_err(|e| anyhow!("Invalid hash format: {}", e))?;

        match self.argon2.verify_password(peppered.as_bytes(), &parsed_hash) {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(e) => Err(anyhow!("Verification failed: {}", e)),
        }
    }
}
