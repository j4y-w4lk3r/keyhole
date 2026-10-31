//! The plaintext vault. It exists only after age has decrypted it.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Serialize, Deserialize)]
pub struct Vault {
    version: u32,
    recipients: Vec<String>,
    items: Vec<Item>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Item {
    name: String,
    username: String,
    password: String,
    notes: String,
}

impl Item {
    pub fn new(
        name: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
        notes: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            username: username.into(),
            password: password.into(),
            notes: notes.into(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    fn lock_memory(&self) -> Result<(), String> {
        for field in [&self.name, &self.username, &self.password, &self.notes] {
            crate::harden::lock_secret(field.as_bytes())?;
        }
        Ok(())
    }
}

impl Vault {
    pub fn empty(recipients: Vec<String>) -> Self {
        Self {
            version: 1,
            recipients,
            items: Vec::new(),
        }
    }

    pub fn recipients(&self) -> &[String] {
        &self.recipients
    }

    pub fn set_recipients(&mut self, recipients: Vec<String>) -> Result<(), String> {
        if recipients.is_empty() {
            return Err("vault has no recipients".into());
        }
        self.recipients = recipients;
        Ok(())
    }

    pub fn names(&self) -> Vec<&str> {
        self.items.iter().map(Item::name).collect()
    }

    pub fn get(&self, name: &str) -> Option<&Item> {
        self.items.iter().find(|item| item.name == name)
    }

    pub fn add(&mut self, item: Item) -> Result<(), String> {
        if item.name.is_empty() || item.name.chars().any(|c| c.is_control()) {
            return Err("name must be one visible line".into());
        }
        if item.password.is_empty() {
            return Err("password is empty".into());
        }
        if self.items.iter().any(|existing| existing.name == item.name) {
            return Err(format!("'{}' is already in the vault", item.name));
        }
        self.items.push(item);
        Ok(())
    }

    /// Dropping the item clears its strings.
    pub fn remove(&mut self, name: &str) -> Result<(), String> {
        let Some(at) = self.items.iter().position(|item| item.name == name) else {
            return Err(format!("no entry '{name}'"));
        };
        self.items.remove(at);
        Ok(())
    }

    pub fn set_password(&mut self, name: &str, password: String) -> Result<(), String> {
        if password.is_empty() {
            return Err("password is empty".into());
        }
        let Some(item) = self.items.iter_mut().find(|item| item.name == name) else {
            return Err(format!("no entry '{name}'"));
        };
        item.password.zeroize();
        item.password = password;
        Ok(())
    }

    pub fn from_plaintext(bytes: &[u8]) -> Result<Self, String> {
        let vault: Self = serde_json::from_slice(bytes).map_err(|e| format!("vault json: {e}"))?;
        if vault.version != 1 {
            return Err(format!("unsupported vault version {}", vault.version));
        }
        if vault.recipients.is_empty() {
            return Err("vault has no recipients".into());
        }
        Ok(vault)
    }

    /// Lock the item strings so they are not written to swap.
    pub fn lock_memory(&self) -> Result<(), String> {
        for recipient in &self.recipients {
            crate::harden::lock_secret(recipient.as_bytes())?;
        }
        for item in &self.items {
            item.lock_memory()?;
        }
        Ok(())
    }

    pub fn to_plaintext(&self) -> Result<Vec<u8>, String> {
        let mut bytes =
            serde_json::to_vec_pretty(self).map_err(|e| format!("encode vault: {e}"))?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

pub fn read_recipient_file(path: &std::path::Path) -> Result<Vec<String>, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut recipients = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.starts_with("age1") {
            return Err(format!("{}: expected an age1 public key", path.display()));
        }
        recipients.push(line.to_string());
    }
    if recipients.is_empty() {
        return Err(format!("{}: no recipient", path.display()));
    }
    Ok(recipients)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_duplicate_name() {
        let mut vault = Vault::empty(vec!["age1example".into()]);
        vault.add(Item::new("demo", "", "one", "")).unwrap();
        let err = vault.add(Item::new("demo", "", "two", "")).unwrap_err();
        assert!(err.contains("already"));
    }

    #[test]
    fn remove_takes_out_only_that_entry() {
        let mut vault = Vault::empty(vec!["age1example".into()]);
        vault.add(Item::new("one", "", "a", "")).unwrap();
        vault.add(Item::new("two", "", "b", "")).unwrap();
        vault.remove("one").unwrap();
        assert_eq!(vault.names(), vec!["two"]);
        assert!(vault.remove("one").unwrap_err().contains("no entry"));
    }

    #[test]
    fn set_password_keeps_the_username_and_notes() {
        let mut vault = Vault::empty(vec!["age1example".into()]);
        vault.add(Item::new("demo", "ada", "old", "note")).unwrap();
        vault.set_password("demo", "new".into()).unwrap();
        let item = vault.get("demo").unwrap();
        assert_eq!(item.password(), "new");
        assert_eq!(item.username(), "ada");
        assert_eq!(item.notes, "note");
        assert!(vault.set_password("demo", String::new()).is_err());
        assert_eq!(vault.get("demo").unwrap().password(), "new");
        assert!(vault.set_password("other", "x".into()).is_err());
    }

    #[test]
    fn rejects_an_unknown_version() {
        let parsed = Vault::from_plaintext(br#"{"version":9,"recipients":["age1x"],"items":[]}"#);
        let Err(err) = parsed else {
            panic!("expected an error");
        };
        assert!(err.contains("version"));
    }
}
