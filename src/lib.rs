use anyhow::Result;

#[cfg(target_os = "linux")]
mod secret_service;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
use linux::Keyring;

#[cfg(target_os = "macos")]
mod mac;

#[cfg(target_os = "macos")]
use mac::Keyring;

#[cfg(target_os = "macos")]
use mac::Keyring;

#[cfg(target_os = "windows")]
mod wincred;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
use windows::Keyring;

#[cfg(target_os = "windows")]
windows::include_bindings!();

pub struct KeyringClient<'a> {
    client: Keyring<'a>,
}

impl KeyringClient<'_> {
    pub fn new(username: String, service: String) -> Result<Self> {
        let client = Keyring::new(username, service)?;

        Ok(KeyringClient { client })
    }

    pub fn set_password(&self, password: String) -> Result<()> {
        self.client.set_password(password)
    }

    pub fn get_password(&self) -> Result<Option<String>> {
        self.client.get_password()
    }
}
