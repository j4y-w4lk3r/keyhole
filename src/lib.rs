//! Keyhole keeps a whole vault as one age ciphertext.
//! Decryption happens in this process. A future sync server only stores the file.

pub mod agebin;
pub mod ageio;
pub mod b64;
pub mod fido;
pub mod gpgbin;
pub mod harden;
pub mod highwater;
pub mod reveal;
pub mod session;
pub mod shelf;
pub mod state;
pub mod trust;
pub mod vault;

use std::path::Path;

use zeroize::Zeroize;

/// Check the signature, then decrypt `vault_path` with an age identity.
pub fn load(
    identity: &Path,
    vault_path: &Path,
    trust: &trust::Trust,
) -> Result<vault::Vault, String> {
    harden::disable_core_dumps()?;
    let age_bytes =
        std::fs::read(vault_path).map_err(|e| format!("read {}: {e}", vault_path.display()))?;
    let signature = std::fs::read(trust::signature_path(vault_path))
        .map_err(|_| "vault has no signature".to_string())?;
    trust.verify_detached(&age_bytes, &signature)?;
    let mut bytes = ageio::decrypt_bytes(identity, &age_bytes)?;
    if let Err(err) = harden::lock_secret(&bytes) {
        bytes.zeroize();
        return Err(err);
    }
    let stanzas = ageio::x25519_stanza_count(&age_bytes)?;
    let parsed = vault::Vault::from_plaintext(&bytes);
    bytes.zeroize();
    let vault = parsed?;
    if stanzas != vault.recipients().len() {
        return Err(
            "age header has a different number of recipients than the vault lists. Refusing a possible hidden recipient."
                .into(),
        );
    }
    trust.check_recipients(vault.recipients())?;
    vault.lock_memory()?;
    Ok(vault)
}

/// Encrypt `vault` to its saved recipients, then sign the ciphertext.
pub fn store(path: &Path, vault: &vault::Vault, trust: &trust::Trust) -> Result<(), String> {
    trust.check_recipients(vault.recipients())?;
    let mut bytes = vault.to_plaintext()?;
    let result = ageio::encrypt_replacing(vault.recipients(), &bytes, path);
    bytes.zeroize();
    result?;
    trust.sign(path)
}
