//! Keyhole keeps a whole vault as one age ciphertext.
//! Decryption happens in this process. A future sync server only stores the file.

pub mod ageio;
pub mod shelf;
pub mod vault;

use std::path::Path;

use zeroize::Zeroize;

/// Decrypt `vault_path` with an age identity and parse the vault.
pub fn load(identity: &Path, vault_path: &Path) -> Result<vault::Vault, String> {
    let mut bytes = ageio::decrypt(identity, vault_path)?;
    let parsed = vault::Vault::from_plaintext(&bytes);
    bytes.zeroize();
    parsed
}

/// Encrypt `vault` to its saved recipients and replace `path` only after age succeeds.
pub fn store(path: &Path, vault: &vault::Vault) -> Result<(), String> {
    let mut bytes = vault.to_plaintext()?;
    let result = ageio::encrypt_replacing(vault.recipients(), &bytes, path);
    bytes.zeroize();
    result
}
