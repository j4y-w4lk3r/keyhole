//! Shell out to the `age` binary. Keyhole does not implement a cipher.

use std::fs;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub fn decrypt(identity: &Path, vault: &Path) -> Result<Vec<u8>, String> {
    let output = Command::new("age")
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
    let mut cmd = Command::new("age");
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

fn age_missing(err: std::io::Error) -> String {
    if err.kind() == ErrorKind::NotFound {
        "age is not installed".into()
    } else {
        err.to_string()
    }
}
