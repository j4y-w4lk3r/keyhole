//! The program `age` runs when an identity belongs to a Bio.
//! That program sees the unwrapped file key, so its bytes are pinned like `age` and `gpg`.

use std::fs;
use std::path::Path;
use std::process::Command;

const PIN_TEXT: &str = include_str!("../fido.pin");
const MARKER: &[u8] = b"AGE-PLUGIN-FIDO2-HMAC";

struct Pin<'a> {
    path: &'a str,
    sha256: &'a str,
}

/// When `identity` asks for the Bio plugin, check the pinned binary and put its
/// directory first on `PATH` so `age` cannot run a different one.
pub fn prepare(cmd: &mut Command, identity: &Path) -> Result<(), String> {
    let bytes =
        fs::read(identity).map_err(|e| format!("read identity {}: {e}", identity.display()))?;
    if !bytes.windows(MARKER.len()).any(|window| window == MARKER) {
        return Ok(());
    }
    let pin = parse_pin(PIN_TEXT)?;
    let plugin = fs::read(pin.path).map_err(|e| format!("read {}: {e}", pin.path))?;
    let got = crate::agebin::hex_sha256(&plugin);
    if got != pin.sha256 {
        return Err(format!(
            "{} hash is {got}, fido.pin expects {}. Update fido.pin on purpose after a plugin upgrade, then rebuild.",
            pin.path, pin.sha256
        ));
    }
    let dir = Path::new(pin.path)
        .parent()
        .ok_or("fido.pin path has no directory")?;
    let mut path = std::ffi::OsString::from(dir);
    path.push(":");
    if let Some(old) = std::env::var_os("PATH") {
        path.push(old);
    }
    cmd.env("PATH", path);
    Ok(())
}

fn parse_pin(text: &str) -> Result<Pin<'_>, String> {
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'));
    let path = lines.next().ok_or("fido.pin needs an absolute path")?;
    let sha256 = lines.next().ok_or("fido.pin needs a sha256 hex line")?;
    if !path.starts_with('/') {
        return Err("fido.pin path must be absolute".into());
    }
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("fido.pin sha256 must be 64 hex characters".into());
    }
    Ok(Pin { path, sha256 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn installed_plugin_matches_the_pin() {
        let pin = parse_pin(PIN_TEXT).unwrap();
        let bytes = fs::read(pin.path).unwrap();
        assert_eq!(crate::agebin::hex_sha256(&bytes), pin.sha256);
    }

    #[test]
    fn a_software_identity_does_not_need_the_plugin() {
        let dir = std::path::PathBuf::from(format!("/dev/shm/keyhole-fido-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("identity.txt");
        fs::write(&path, b"# software key\nAGE-SECRET-KEY-1TEST\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut cmd = Command::new("true");
        prepare(&mut cmd, &path).unwrap();
        assert!(cmd.get_envs().all(|(key, _)| key != "PATH"));
        let _ = fs::remove_dir_all(&dir);
    }
}
