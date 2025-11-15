use std::collections::HashMap;
use argon2::{
    Argon2, PasswordHash, PasswordVerifier,
};
use crate::domain::{Email, Password, User, UserStore, UserStoreError};

#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<Email, User>,
}

#[async_trait::async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if self.users.contains_key(&user.email) {
            return Err(UserStoreError::UserAlreadyExists);
        }
        self.users.insert(user.email.clone(), user);
        Ok(())
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        match self.users.get(email) {
            Some(user) => Ok(user.clone()),
            None => Err(UserStoreError::UserNotFound),
        }
    }

    async fn validate_user(
        &self,
        email: &Email,
        password: &Password,
    ) -> Result<(), UserStoreError> {
        let user = self.users.get(email).ok_or(UserStoreError::UserNotFound)?;

        let expected_password_hash = user.password.as_ref().to_owned();
        let password_candidate = password.as_ref().to_owned();

        tokio::task::spawn_blocking(move || {
            let parsed_hash = PasswordHash::new(&expected_password_hash)
                .map_err(|_| UserStoreError::UnexpectedError)?;

            Argon2::default()
                .verify_password(password_candidate.as_bytes(), &parsed_hash)
                .map_err(|_| UserStoreError::InvalidCredentials)
        })
            .await
            .map_err(|_| UserStoreError::UnexpectedError)?
    }
}


#[cfg(test)]
mod tests {
    use crate::domain::HashPassword;
    use super::*;

    #[tokio::test]
    async fn test_add_user() {
        let mut user_store = HashmapUserStore::default();
        let password = HashPassword::new(Password::parse("password".to_owned()).unwrap()).await.unwrap();
        let user = User {
            email: Email::parse("test@example.com".to_owned()).unwrap(),
            password,
            requires_2fa: false,
        };

        // Test adding a new user
        let result = user_store.add_user(user.clone()).await;
        assert!(result.is_ok());

        // Test adding an existing user
        let result = user_store.add_user(user).await;
        assert_eq!(result, Err(UserStoreError::UserAlreadyExists));
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut user_store = HashmapUserStore::default();
        let email = Email::parse("test@example.com".to_owned()).unwrap();

        let password = HashPassword::new(Password::parse("password".to_owned()).unwrap()).await.unwrap();
        let user = User {
            email: email.clone(),
            password,
            requires_2fa: false,
        };

        // Test getting a user that exists
        user_store.users.insert(email.clone(), user.clone());
        let result = user_store.get_user(&email).await;
        assert_eq!(result, Ok(user));

        // Test getting a user that doesn't exist
        let result = user_store
            .get_user(&Email::parse("nonexistent@example.com".to_owned()).unwrap())
            .await;

        assert_eq!(result, Err(UserStoreError::UserNotFound));
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut user_store = HashmapUserStore::default();
        let email = Email::parse("test@example.com".to_owned()).unwrap();
        let password = Password::parse("password".to_owned()).unwrap();
        let hash_password = HashPassword::new(password.clone()).await.unwrap();

        let user = User {
            email: email.clone(),
            password: hash_password,
            requires_2fa: false,
        };

        // Test validating a user that exists with correct password
        user_store.users.insert(email.clone(), user.clone());
        let result = user_store.validate_user(&email, &password).await;
        assert_eq!(result, Ok(()));

        // Test validating a user that exists with incorrect password
        let wrong_password = Password::parse("wrongpassword".to_owned()).unwrap();
        let result = user_store.validate_user(&email, &wrong_password).await;
        assert_eq!(result, Err(UserStoreError::InvalidCredentials));

        // Test validating a user that doesn't exist
        let result = user_store
            .validate_user(
                &Email::parse("nonexistent@example.com".to_string()).unwrap(),
                &Password::parse("password".to_owned()).unwrap(),
            )
            .await;

        assert_eq!(result, Err(UserStoreError::UserNotFound));
    }
}
