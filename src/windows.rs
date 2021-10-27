use anyhow::{anyhow, Result};

use crate::wincred::client::WincredClient;

pub struct Keyring {
    client: WincredClient
}

impl Keyring {
    pub fn new(username: String, service: String) -> Result<Self> {
        let client: WincredClient = WincredClient::new(username, service)?;
        Ok(Self { client })
    }

    pub fn set_password(&self, password: String) -> Result<()> {
        self.client.set_password(password)
    }

    pub fn get_password(&self) -> Result<Option<String>> {
        self.client.get_password()
    }
}
