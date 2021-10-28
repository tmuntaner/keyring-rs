use anyhow::{anyhow, Result};
use tmuntaner_keyring::KeyringClient;

fn main() -> Result<()> {
    let username = "tmuntaner";
    let service = "keyring-rs-example";
    let application = "keyring-rs";

    let keyring = KeyringClient::new(username, service, application)?;
    let password = String::from("foobar");

    println!("Setting password {}", password);
    keyring.set_password(password.clone())?;

    let result = keyring
        .get_password()?
        .ok_or_else(|| anyhow!("should have a password"))?;
    println!("Returned password: {}", password);
    assert_eq!(password, result);

    Ok(())
}
