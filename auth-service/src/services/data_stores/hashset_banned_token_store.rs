use std::collections::HashSet;

use secrecy::{ExposeSecret, SecretString};

use crate::domain::data_stores::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default)]
pub struct HashsetBannedTokenStore {
    tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn add_token(&mut self, token: SecretString) -> Result<(), BannedTokenStoreError> {
        self.tokens.insert(token.expose_secret().to_owned());
        Ok(())
    }

    async fn contains_token(&self, token: &SecretString) -> Result<bool, BannedTokenStoreError> {
        Ok(self.tokens.contains(token.expose_secret()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_add_token() {
        let mut store = HashsetBannedTokenStore::default();
        let token = SecretString::new("test_token".to_owned().into_boxed_str());

        let result = store.add_token(token.to_owned()).await;

        assert!(result.is_ok());
        assert!(store.tokens.contains(token.expose_secret()));
    }

    #[tokio::test]
    async fn test_contains_token() {
        let mut store = HashsetBannedTokenStore::default();
        let token = SecretString::new("test_token".to_owned().into_boxed_str());
        store.tokens.insert(token.expose_secret().to_owned());

        let result = store.contains_token(&token).await;

        assert!(result.unwrap());
    }
}
