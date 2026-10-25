//! Pinned signers and age recipients. This directory stays on the laptop.
//! A signature is checked before age runs. rekey is the explicit way to change recipients.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const AGE_HEADER: &[u8] = b"age-encryption.org/v1\n";

pub struct Trust {
    dir: PathBuf,
    /// Private keys live here when set. Verification never uses this directory.
    keyring: Option<PathBuf>,
}

impl Trust {
    pub fn open(dir: &Path) -> Result<Self, String> {
        fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("chmod {}: {e}", dir.display()))?;
        let gnupg = dir.join("gnupg");
        fs::create_dir_all(&gnupg).map_err(|e| format!("create {}: {e}", gnupg.display()))?;
        fs::set_permissions(&gnupg, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("chmod {}: {e}", gnupg.display()))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            keyring: None,
        })
    }

    pub fn with_keyring(mut self, home: &Path) -> Self {
        self.keyring = Some(home.to_path_buf());
        self
    }

    pub fn default_dir() -> Result<PathBuf, String> {
        Ok(crate::state::root()?.join("trust"))
    }

    pub fn allow_signer(&self, fingerprint: &str) -> Result<(), String> {
        let fpr = normalize_fpr(fingerprint)?;
        let exported = self.export_public(&fpr)?;
        if exported.is_empty() {
            return Err("gpg did not export that public key".into());
        }
        self.import_public(&exported)?;
        append_unique(&self.dir.join("signers"), &fpr)?;
        let signer = self.dir.join("signer");
        if !signer.exists() {
            write_private(&signer, &format!("{fpr}\n"))?;
        }
        Ok(())
    }

    pub fn use_signer(&self, fingerprint: &str) -> Result<(), String> {
        let fpr = normalize_fpr(fingerprint)?;
        let allowed = self.signers()?;
        if !allowed.iter().any(|item| item.eq_ignore_ascii_case(&fpr)) {
            return Err("use-signer needs a fingerprint already added with allow-signer".into());
        }
        write_private(&self.dir.join("signer"), &format!("{fpr}\n"))
    }

    pub fn allow_recipient(&self, recipient: &str) -> Result<(), String> {
        let recipient = recipient.trim();
        if !valid_recipient(recipient) {
            return Err("recipient must be an age1 public key".into());
        }
        append_unique(&self.dir.join("recipients"), recipient)
    }

    pub fn deny_recipient(&self, recipient: &str) -> Result<(), String> {
        let recipient = recipient.trim();
        let path = self.dir.join("recipients");
        let kept: Vec<String> = read_lines(&path)?
            .into_iter()
            .filter(|line| line != recipient)
            .collect();
        if kept.len() == read_lines(&path)?.len() {
            return Err("that recipient is not pinned".into());
        }
        write_private(&path, &joined(&kept))?;
        Ok(())
    }

    pub fn check_recipients(&self, recipients: &[String]) -> Result<(), String> {
        let allowed = read_lines(&self.dir.join("recipients"))?;
        if allowed.is_empty() {
            return Err("no pinned recipients. run keyhole trust allow-recipient".into());
        }
        for recipient in recipients {
            if !allowed.iter().any(|item| item == recipient) {
                return Err(format!("recipient {recipient} is not pinned"));
            }
        }
        Ok(())
    }

    pub fn sign(&self, age_path: &Path) -> Result<(), String> {
        let bytes = fs::read(age_path).map_err(|e| format!("read {}: {e}", age_path.display()))?;
        if !bytes.starts_with(AGE_HEADER) {
            return Err("refusing to sign a file that is not age ciphertext".into());
        }
        let fpr = self.signing_fingerprint()?;
        let sig_path = signature_path(age_path);
        let mut cmd = crate::gpgbin::gpg_command()?;
        cmd.arg("--yes");
        if let Some(home) = &self.keyring {
            // Practice keys have an empty passphrase. --batch keeps the tests
            // from opening a PIN window. A real Bio must be allowed to ask.
            cmd.arg("--batch").arg("--homedir").arg(home);
        }
        cmd.arg("--detach-sign")
            .arg("--local-user")
            .arg(&fpr)
            .arg("--output")
            .arg(&sig_path)
            .arg(age_path)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        if self.keyring.is_some() {
            cmd.stdin(Stdio::null());
        } else {
            let Some(tty) = controlling_tty() else {
                return Err(
                    "signing needs your terminal so the Bio PIN prompt can open. Run keyhole sign from that terminal."
                        .into(),
                );
            };
            cmd.env("GPG_TTY", &tty);
            // The agent may still be holding a closed terminal from an earlier try.
            let _ = Command::new("gpg-connect-agent")
                .env("GPG_TTY", &tty)
                .args(["updatestartuptty", "/bye"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            match File::open("/dev/tty") {
                Ok(tty_file) => {
                    cmd.stdin(Stdio::from(tty_file));
                }
                Err(_) => {
                    cmd.stdin(Stdio::inherit());
                }
            }
        }
        let status = cmd.status().map_err(|e| format!("run gpg sign: {e}"))?;
        if !status.success() {
            let _ = fs::remove_file(&sig_path);
            return Err("gpg sign failed".into());
        }
        fs::set_permissions(&sig_path, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod {}: {e}", sig_path.display()))?;
        Ok(())
    }

    pub fn verify(&self, age_path: &Path) -> Result<(), String> {
        let sig =
            fs::read(signature_path(age_path)).map_err(|_| "vault has no signature".to_string())?;
        let age = fs::read(age_path).map_err(|e| format!("read {}: {e}", age_path.display()))?;
        self.verify_detached(&age, &sig)
    }

    pub fn verify_detached(&self, age: &[u8], signature: &[u8]) -> Result<(), String> {
        if signature.is_empty() {
            return Err("vault has no signature".into());
        }
        let tmp = self.dir.join(format!(
            "verify-{}-{}",
            std::process::id(),
            crate::state::random_hex(4)?
        ));
        fs::create_dir_all(&tmp).map_err(|e| format!("create {}: {e}", tmp.display()))?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("chmod {}: {e}", tmp.display()))?;
        let age_path = tmp.join("vault.age");
        let sig_path = tmp.join("vault.age.sig");
        fs::write(&age_path, age).map_err(|e| format!("write {}: {e}", age_path.display()))?;
        fs::write(&sig_path, signature)
            .map_err(|e| format!("write {}: {e}", sig_path.display()))?;
        let result = self.verify_files(&age_path, &sig_path);
        let _ = fs::remove_dir_all(&tmp);
        result
    }

    fn verify_files(&self, age_path: &Path, sig_path: &Path) -> Result<(), String> {
        let mut cmd = crate::gpgbin::gpg_command()?;
        cmd.arg("--batch")
            .arg("--status-fd")
            .arg("1")
            .arg("--homedir")
            .arg(self.gnupg())
            .arg("--verify")
            .arg(sig_path)
            .arg(age_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = cmd.output().map_err(|e| format!("run gpg verify: {e}"))?;
        let status = String::from_utf8_lossy(&output.stdout);
        let Some(sig) = validsig(&status) else {
            return Err("signature rejected".into());
        };
        if !output.status.success() {
            return Err("signature rejected".into());
        }
        let allowed = self.signers()?;
        let pinned = sig
            .fingerprints()
            .any(|fpr| allowed.iter().any(|item| item.eq_ignore_ascii_case(fpr)));
        if !pinned {
            return Err(format!(
                "signature is from {}, which is not a pinned signer",
                sig.describe()
            ));
        }
        Ok(())
    }

    fn export_public(&self, fpr: &str) -> Result<Vec<u8>, String> {
        let mut cmd = crate::gpgbin::gpg_command()?;
        cmd.arg("--batch");
        if let Some(home) = &self.keyring {
            cmd.arg("--homedir").arg(home);
        }
        cmd.args(["--export", "--armor", fpr])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = cmd.output().map_err(|e| format!("run gpg export: {e}"))?;
        if !output.status.success() {
            return Err("could not export that public key from gpg".into());
        }
        Ok(output.stdout)
    }

    fn import_public(&self, armored: &[u8]) -> Result<(), String> {
        let mut cmd = crate::gpgbin::gpg_command()?;
        cmd.arg("--batch")
            .arg("--homedir")
            .arg(self.gnupg())
            .arg("--import")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| format!("run gpg import: {e}"))?;
        {
            let mut stdin = child.stdin.take().ok_or("gpg import stdin closed")?;
            stdin
                .write_all(armored)
                .map_err(|e| format!("write to gpg: {e}"))?;
        }
        let status = child.wait().map_err(|e| format!("wait for gpg: {e}"))?;
        if !status.success() {
            return Err("could not import the public key into the trust store".into());
        }
        Ok(())
    }

    fn signing_fingerprint(&self) -> Result<String, String> {
        let text = fs::read_to_string(self.dir.join("signer"))
            .map_err(|_| "no signing key. run keyhole trust allow-signer".to_string())?;
        let fpr = normalize_fpr(text.trim())?;
        let allowed = self.signers()?;
        if !allowed.iter().any(|item| item.eq_ignore_ascii_case(&fpr)) {
            return Err("the signing key is not in the pinned signer list".into());
        }
        Ok(fpr)
    }

    fn signers(&self) -> Result<Vec<String>, String> {
        let lines = read_lines(&self.dir.join("signers"))?;
        if lines.is_empty() {
            return Err("no pinned signer. run keyhole trust allow-signer".into());
        }
        Ok(lines)
    }

    fn gnupg(&self) -> PathBuf {
        self.dir.join("gnupg")
    }
}

pub fn signature_path(age_path: &Path) -> PathBuf {
    let mut name = age_path.as_os_str().to_owned();
    name.push(".sig");
    PathBuf::from(name)
}

/// The terminal this process was started in, if it is a real one.
fn controlling_tty() -> Option<PathBuf> {
    let path = fs::read_link("/proc/self/fd/0").ok()?;
    let text = path.to_string_lossy();
    if text.starts_with("/dev/pts/") || text.starts_with("/dev/tty") {
        Some(path)
    } else {
        None
    }
}

fn normalize_fpr(fingerprint: &str) -> Result<String, String> {
    let fpr: String = fingerprint
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_uppercase();
    if (fpr.len() != 40 && fpr.len() != 64) || !fpr.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("fingerprint must be 40 or 64 hex characters".into());
    }
    Ok(fpr)
}

fn valid_recipient(recipient: &str) -> bool {
    recipient.starts_with("age1")
        && recipient.len() > 10
        && recipient.chars().all(|c| c.is_ascii_graphic())
}

struct ValidSig {
    /// Fingerprint of the key that produced the signature. A Bio signs with a subkey.
    signing: String,
    /// Primary key that owns that subkey, when GnuPG reports it.
    primary: Option<String>,
}

impl ValidSig {
    fn fingerprints(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.signing.as_str()).chain(self.primary.as_deref())
    }

    fn describe(&self) -> String {
        match &self.primary {
            Some(primary) if primary != &self.signing => {
                format!("{primary} (subkey {})", self.signing)
            }
            _ => self.signing.clone(),
        }
    }
}

fn validsig(status: &str) -> Option<ValidSig> {
    for line in status.lines() {
        let Some(rest) = line.strip_prefix("[GNUPG:] VALIDSIG ") else {
            continue;
        };
        let fields: Vec<&str> = rest.split_whitespace().collect();
        let signing = fields.first()?.to_ascii_uppercase();
        if !fingerprint_hex(&signing) {
            return None;
        }
        // GnuPG puts the primary fingerprint in the 10th field.
        let primary = fields
            .get(9)
            .map(|field| field.to_ascii_uppercase())
            .filter(|field| fingerprint_hex(field));
        return Some(ValidSig { signing, primary });
    }
    None
}

fn fingerprint_hex(fpr: &str) -> bool {
    (fpr.len() == 40 || fpr.len() == 64) && fpr.chars().all(|c| c.is_ascii_hexdigit())
}

fn read_lines(path: &Path) -> Result<Vec<String>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect())
}

fn append_unique(path: &Path, line: &str) -> Result<(), String> {
    let mut lines = read_lines(path)?;
    if lines.iter().any(|item| item.eq_ignore_ascii_case(line)) {
        return Ok(());
    }
    lines.push(line.to_string());
    write_private(path, &joined(&lines))
}

fn joined(lines: &[String]) -> String {
    let mut text = lines.join("\n");
    if !text.is_empty() {
        text.push('\n');
    }
    text
}

fn write_private(path: &Path, text: &str) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("write {}: {e}", tmp.display()))?;
        file.write_all(text.as_bytes())
            .map_err(|e| format!("write {}: {e}", tmp.display()))?;
    }
    fs::rename(&tmp, path).map_err(|e| format!("save {}: {e}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_short_fingerprint() {
        let err = normalize_fpr("abc").unwrap_err();
        assert!(err.contains("40 or 64"), "{err}");
    }

    #[test]
    fn a_subkey_signature_also_names_the_primary() {
        let status = "[GNUPG:] VALIDSIG A811D80289ED5FFDFC18EFF0831B58B1435489BC 2026-10-24 1792861271 0 4 0 1 10 00 E7702AAF1FEE076958B66C15E5712AFC8C6E18D6";
        let sig = validsig(status).unwrap();
        assert_eq!(sig.signing, "A811D80289ED5FFDFC18EFF0831B58B1435489BC");
        assert_eq!(
            sig.primary.as_deref(),
            Some("E7702AAF1FEE076958B66C15E5712AFC8C6E18D6")
        );
        assert!(
            sig.fingerprints()
                .any(|fpr| fpr == "E7702AAF1FEE076958B66C15E5712AFC8C6E18D6")
        );
    }
}
