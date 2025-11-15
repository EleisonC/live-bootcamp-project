use std::error::Error;
use argon2::{
    password_hash::SaltString, Algorithm, Argon2, Params, PasswordHash, PasswordHasher,
    Version,
};
use argon2::password_hash::rand_core::OsRng;
use crate::domain::Password;

// For password hashes (stored in DB)
#[derive(Debug, Clone, PartialEq)]
pub struct HashPassword(String);

impl HashPassword {
    pub fn parse(hash: String) -> Result<HashPassword, String> {
        // No validation - hashes are already validated by the hashing algorithm
        if let Ok(hashed_string) = PasswordHash::new(hash.as_ref()) {
            Ok(Self(hashed_string.to_string()))
        } else {
            Err("Failed to parse string to a HashPassword type".to_owned())
        }
        
    }
    
    pub async fn new(password: Password) -> Result<HashPassword, String> {
        if let Ok(password_hash) = compute_password_hash(password.as_ref().to_owned()).await  {
            Ok(Self(password_hash))
        } else  {
            Err("Password hash failed.".to_owned())
        }
    }
}

impl AsRef<str> for HashPassword {
    fn as_ref(&self) -> &str {
        &self.0.as_str()
    }
}

pub async fn compute_password_hash(password: String) -> Result<String, Box<dyn Error + Send + Sync>> {
    let result = tokio::task::spawn_blocking(move || {
        let salt: SaltString = SaltString::generate(&mut OsRng);
        let password_hash = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None)?,
        )
            .hash_password(password.as_bytes(), &salt)?
            .to_string();

        Ok(password_hash)
    })
        .await;

    result?
}

#[cfg(test)]
mod tests {
    use super::HashPassword;
    use argon2::{
        password_hash::{rand_core::OsRng, SaltString},
        Algorithm, Argon2, Params, PasswordHasher, Version,
    };

    #[test]
    fn can_parse_valid_argon2_hash() {
        // Arrange - Create a valid Argon2 hash
        let raw_password = "TestPassword123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None).unwrap(),
        );

        let hash_string = argon2
            .hash_password(raw_password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        // Act
        let hash_password = HashPassword::parse(hash_string.clone()).unwrap();

        // Assert
        assert_eq!(hash_password.as_ref(), hash_string.as_str());
        assert!(hash_password.as_ref().starts_with("$argon2id$v=19$"));
    }

    #[test]
    fn cannot_parse_invalid_hash_string() {
        // Arrange - Invalid hash format
        let invalid_hash = "not-a-valid-hash".to_string();

        // Act
        let result = HashPassword::parse(invalid_hash);

        // Assert
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Failed to parse string to a HashPassword type"
        );
    }

    #[test]
    fn hash_password_preserves_phc_format() {
        // Arrange
        let raw_password = "SecurePass456";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None).unwrap(),
        );

        let original_hash = argon2
            .hash_password(raw_password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        // Act
        let hash_password = HashPassword::parse(original_hash.clone()).unwrap();

        // Assert - Verify PHC string format is preserved
        let stored = hash_password.as_ref();
        assert!(stored.starts_with("$argon2id$"));
        assert!(stored.contains("$m=15000"));
        assert!(stored.contains("t=2"));
        assert!(stored.contains("p=1"));

        // Verify the hash can be parsed back by argon2
        assert!(argon2::PasswordHash::new(stored).is_ok());
    }
}