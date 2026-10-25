//! Shell out to the `age` binary. Keyhole does not implement a cipher.

use std::fs;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;

pub fn decrypt(identity: &Path, vault: &Path) -> Result<Vec<u8>, String> {
    let bytes = fs::read(vault).map_err(|e| format!("read {}: {e}", vault.display()))?;
    decrypt_bytes(identity, &bytes)
}

/// Decrypt `age_bytes` after the caller has verified those exact bytes.
pub fn decrypt_bytes(identity: &Path, age_bytes: &[u8]) -> Result<Vec<u8>, String> {
    crate::harden::check_identity(identity)?;
    let dir = PathBuf::from(format!(
        "/dev/shm/keyhole-dec-{}-{}",
        std::process::id(),
        crate::state::random_hex(4)?
    ));
    fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("chmod {}: {e}", dir.display()))?;
    let path = dir.join("vault.age");
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| format!("write {}: {e}", path.display()))?;
        file.write_all(age_bytes)
            .map_err(|e| format!("write {}: {e}", path.display()))?;
    }
    let result = decrypt_path(identity, &path);
    let _ = fs::remove_dir_all(&dir);
    result
}

fn decrypt_path(identity: &Path, vault: &Path) -> Result<Vec<u8>, String> {
    let mut cmd = crate::agebin::age_command()?;
    crate::fido::prepare(&mut cmd, identity)?;
    let output = cmd
        .arg("-d")
        .arg("-i")
        .arg(identity)
        .arg(vault)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .map_err(age_missing)?;
    if !output.status.success() {
        return Err("age decrypt failed".into());
    }
    Ok(output.stdout)
}

/// Encrypt to a temp file next to `destination`, then rename over it.
pub fn encrypt_replacing(
    recipients: &[String],
    plaintext: &[u8],
    destination: &Path,
) -> Result<(), String> {
    if recipients.is_empty() {
        return Err("vault has no recipients".into());
    }
    let tmp = tmp_path(destination);
    let _ = fs::remove_file(&tmp);
    encrypt_to(recipients, plaintext, &tmp)?;
    let perms = fs::Permissions::from_mode(0o600);
    fs::set_permissions(&tmp, perms).map_err(|e| format!("chmod {}: {e}", tmp.display()))?;
    fs::rename(&tmp, destination).map_err(|e| format!("replace {}: {e}", destination.display()))?;
    Ok(())
}

fn encrypt_to(recipients: &[String], plaintext: &[u8], destination: &Path) -> Result<(), String> {
    let mut cmd = crate::agebin::age_command()?;
    for recipient in recipients {
        if !recipient.starts_with("age1") {
            return Err("refusing a recipient that is not an age public key".into());
        }
        cmd.arg("-r").arg(recipient);
    }
    cmd.arg("-o").arg(destination);
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(age_missing)?;
    {
        let mut stdin = child.stdin.take().ok_or("age stdin closed")?;
        stdin
            .write_all(plaintext)
            .map_err(|e| format!("write to age: {e}"))?;
    }
    let status = child.wait().map_err(|e| format!("wait for age: {e}"))?;
    if !status.success() {
        let _ = fs::remove_file(destination);
        return Err("age encrypt failed".into());
    }
    Ok(())
}

fn tmp_path(destination: &Path) -> PathBuf {
    let mut name = destination.as_os_str().to_owned();
    name.push(".tmp");
    PathBuf::from(name)
}

/// How many X25519 recipient stanzas the header contains.
/// age does not write the recipient name into the header, so a longer header
/// than the vault's recipient list is the sign of an extra hidden recipient.
pub fn x25519_stanza_count(bytes: &[u8]) -> Result<usize, String> {
    let header = header_text(bytes)?;
    let mut count = 0usize;
    for line in header.lines() {
        if !line.starts_with("-> ") {
            continue;
        }
        if !line.starts_with("-> X25519 ") {
            return Err("age file has a recipient type other than X25519".into());
        }
        count += 1;
    }
    if count == 0 {
        return Err("age file has no recipients".into());
    }
    Ok(count)
}

fn header_text(bytes: &[u8]) -> Result<&str, String> {
    let mut start = 0usize;
    while start < bytes.len() {
        let rest = &bytes[start..];
        let Some(nl) = rest.iter().position(|byte| *byte == b'\n') else {
            return Err("age header has no MAC line".into());
        };
        let line = &rest[..nl];
        let next = start + nl + 1;
        if line.starts_with(b"--- ") {
            return std::str::from_utf8(&bytes[..next])
                .map_err(|_| "age header is not text".to_string());
        }
        start = next;
        if start > 1024 * 1024 {
            return Err("age header is too large".into());
        }
    }
    Err("age header has no MAC line".into())
}

fn age_missing(err: std::io::Error) -> String {
    if err.kind() == ErrorKind::NotFound {
        "/usr/bin/age is not installed".into()
    } else {
        err.to_string()
    }
}
