//! Which `gpg` program Keyhole is willing to ask for a signature.
//! A lie from this program would make a swapped vault look genuine.

use std::fs;
use std::process::Command;

use sha2::{Digest, Sha256};

const PIN_TEXT: &str = include_str!("../gpg.pin");

struct Pin<'a> {
    path: &'a str,
    sha256: &'a str,
}

pub fn gpg_command() -> Result<Command, String> {
    let pin = parse_pin(PIN_TEXT)?;
    let bytes = fs::read(pin.path).map_err(|e| format!("read {}: {e}", pin.path))?;
    let got = format!("{:x}", Sha256::digest(bytes));
    if got != pin.sha256 {
        return Err(format!(
            "{} hash is {got}, gpg.pin expects {}. Update gpg.pin on purpose after a gpg upgrade, then rebuild.",
            pin.path, pin.sha256
        ));
    }
    Ok(Command::new(pin.path))
}

fn parse_pin(text: &str) -> Result<Pin<'_>, String> {
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'));
    let path = lines.next().ok_or("gpg.pin needs an absolute path")?;
    let sha256 = lines.next().ok_or("gpg.pin needs a sha256 hex line")?;
    if !path.starts_with('/') {
        return Err("gpg.pin path must be absolute".into());
    }
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("gpg.pin sha256 must be 64 hex characters".into());
    }
    Ok(Pin { path, sha256 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installed_gpg_matches_the_pin() {
        let cmd = gpg_command().expect("pinned gpg");
        assert_eq!(cmd.get_program(), "/usr/bin/gpg");
    }
}
