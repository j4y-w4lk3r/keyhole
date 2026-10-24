//! Which `age` program Keyhole is willing to run.
//! The expected path and SHA-256 are compiled in from `age.pin`, so a swapped
//! binary is refused until that file is changed on purpose and keyhole is rebuilt.

use std::fs;
use std::process::Command;

use sha2::{Digest, Sha256};

const PIN_TEXT: &str = include_str!("../age.pin");

struct Pin<'a> {
    path: &'a str,
    sha256: &'a str,
}

pub fn age_command() -> Result<Command, String> {
    let pin = parse_pin(PIN_TEXT)?;
    let bytes = fs::read(pin.path).map_err(|e| format!("read {}: {e}", pin.path))?;
    let got = hex_sha256(&bytes);
    if got != pin.sha256 {
        return Err(format!(
            "{} hash is {got}, age.pin expects {}. Update age.pin on purpose after an age upgrade, then rebuild.",
            pin.path, pin.sha256
        ));
    }
    Ok(Command::new(pin.path))
}

pub fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn parse_pin(text: &str) -> Result<Pin<'_>, String> {
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'));
    let path = lines.next().ok_or("age.pin needs an absolute path")?;
    let sha256 = lines.next().ok_or("age.pin needs a sha256 hex line")?;
    if !path.starts_with('/') {
        return Err("age.pin path must be absolute".into());
    }
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("age.pin sha256 must be 64 hex characters".into());
    }
    Ok(Pin { path, sha256 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_of_abc_is_the_known_value() {
        let got = hex_sha256(b"abc");
        assert_eq!(
            got,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn a_relative_path_is_refused() {
        let text = "\
age
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
";
        let Err(err) = parse_pin(text) else {
            panic!("relative path was accepted");
        };
        assert!(err.contains("absolute"), "{err}");
    }

    #[test]
    fn installed_age_matches_the_pin() {
        let cmd = age_command().expect("pinned age");
        assert_eq!(cmd.get_program(), "/usr/bin/age");
    }
}
