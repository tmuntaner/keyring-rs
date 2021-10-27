/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

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

#[cfg(target_os = "windows")]
mod wincred;

#[cfg(target_os = "windows")]
mod win;

#[cfg(target_os = "windows")]
use win::Keyring;

pub struct KeyringClient<'a> {
    client: Keyring<'a>,
}

impl<'a> KeyringClient<'a> {
    pub fn new(username: &'a str, service: &'a str) -> Result<Self> {
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
