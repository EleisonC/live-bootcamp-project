#[derive(Debug, Clone, PartialEq)]
pub struct Password(String);
use argon2::PasswordHash;

impl Password {
    pub fn parse(s: String) -> Result<Password, String> {
        if validate_password(&s) {
            Ok(Self(s))
        } else {
            Err("Failed to parse string to a Password type".to_owned())
        }
    }
    /// Construct a `Password` instance from a cryptographically valid Argon2 `PasswordHash`.
    /// This is used when retrieving users from storage, not for validation.
    pub fn from_password_hash(hash: PasswordHash) -> Password {
        // `PasswordHash` implements Display — its string form is the PHC string.
        Self(hash.to_string())
    }
}

fn validate_password(s: &str) -> bool {
    s.len() >= 8
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Password;

    use fake::faker::internet::en::Password as FakePassword;
    use fake::Fake;
    use quickcheck::Gen;
    use rand::SeedableRng;
    use argon2::{
        password_hash::{SaltString, rand_core::OsRng}, Algorithm, Argon2,
        Params, PasswordHash, PasswordHasher, Version,
    };

    #[test]
    fn empty_string_is_rejected() {
        let password = "".to_owned();
        assert!(Password::parse(password).is_err());
    }
    #[test]
    fn string_less_than_8_characters_is_rejected() {
        let password = "1234567".to_owned();
        assert!(Password::parse(password).is_err());
    }
    fn can_build_password_from_valid_hash() {
        let raw_password = "StrongPass123".to_owned();

        // Match production parameters exactly
        let salt: SaltString = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None).unwrap(),
        );

        let password_hash = argon2
            .hash_password(raw_password.as_bytes(), &salt).unwrap()
            .to_string();

        let parsed_hash = PasswordHash::new(password_hash.as_ref()).unwrap();

        // Act
        let password =
            Password::from_password_hash(parsed_hash);

        // Assert
        let stored_value = password.as_ref();
        assert!(stored_value.starts_with("$argon2id$v=19$m=15000"));
        assert!(stored_value.contains("p=1"));
    }

    #[derive(Debug, Clone)]
    struct ValidPasswordFixture(pub String);

    impl quickcheck::Arbitrary for ValidPasswordFixture {
        fn arbitrary(g: &mut Gen) -> Self {
            let seed: u64 = g.size() as u64;
            let mut rng = rand::rngs::SmallRng::seed_from_u64(seed);
            let password = FakePassword(8..30).fake_with_rng(&mut rng);
            Self(password)
        }
    }
    #[quickcheck_macros::quickcheck]
    fn valid_passwords_are_parsed_successfully(valid_password: ValidPasswordFixture) -> bool {
        Password::parse(valid_password.0).is_ok()
    }
}
