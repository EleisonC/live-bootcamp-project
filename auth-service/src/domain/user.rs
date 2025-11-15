use super::{Email, HashPassword};

#[derive(Clone, Debug, PartialEq)]
pub struct User {
    pub email: Email,
    pub password: HashPassword,
    pub requires_2fa: bool,
}

impl User {
    pub fn new(email: Email, password: HashPassword, requires_2fa: bool) -> Self {
        Self {
            email,
            password,
            requires_2fa,
        }
    }
}
