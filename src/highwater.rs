//! The highest shelf version this machine has seen.
//! The file lives on the laptop. A shelf that offers an older number is refused.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub struct HighWater {
    dir: PathBuf,
}

impl HighWater {
    pub fn open(dir: &Path) -> Result<Self, String> {
        fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        ensure_mode(dir, 0o700)?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    pub fn default_dir() -> Result<PathBuf, String> {
        Ok(crate::state::root()?.join("highwater"))
    }

    pub fn highest(&self, shelf: &Path) -> Result<u64, String> {
        let path = self.slot(shelf)?;
        if !path.exists() {
            return Ok(0);
        }
        let text = fs::read_to_string(&path).map_err(|e| format!("read high water: {e}"))?;
        highest_in(&text).map_err(|e| format!("{e} in {}", path.display()))
    }

    /// Remember `version` when it is newer. An older number does not lower the memory.
    /// The new number is appended, so a file marked append-only can still grow.
    pub fn note(&self, shelf: &Path, version: u64) -> Result<(), String> {
        let seen = self.highest(shelf)?;
        if version <= seen {
            return Ok(());
        }
        let path = self.slot(shelf)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| format!("write {}: {e}", path.display()))?;
        writeln!(file, "{version}").map_err(|e| format!("write {}: {e}", path.display()))?;
        Ok(())
    }

    pub fn check(&self, shelf: &Path, offered: u64, accept_older: bool) -> Result<(), String> {
        let seen = self.highest(shelf)?;
        if offered < seen && !accept_older {
            return Err(format!(
                "shelf went backwards: this machine has seen version {seen}, shelf offered {offered}. Pass --accept-older to pull it anyway. The remembered version stays {seen}."
            ));
        }
        Ok(())
    }

    fn slot(&self, shelf: &Path) -> Result<PathBuf, String> {
        let canon = fs::canonicalize(shelf).unwrap_or_else(|_| shelf.to_path_buf());
        let name = crate::agebin::hex_sha256(canon.to_string_lossy().as_bytes());
        Ok(self.dir.join(name))
    }
}

fn highest_in(text: &str) -> Result<u64, String> {
    let mut best = 0u64;
    let mut any = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let version: u64 = line
            .parse()
            .map_err(|_| format!("bad high water line {line}"))?;
        any = true;
        best = best.max(version);
    }
    if any { Ok(best) } else { Ok(0) }
}

fn ensure_mode(path: &Path, mode: u32) -> Result<(), String> {
    let found = fs::metadata(path)
        .map_err(|e| format!("stat {}: {e}", path.display()))?
        .permissions()
        .mode()
        & 0o777;
    if found == mode {
        return Ok(());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|e| format!("chmod {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_older_offer_does_not_lower_the_memory() {
        let dir = PathBuf::from(format!("/dev/shm/keyhole-hw-{}-mem", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let shelf = PathBuf::from(format!("/dev/shm/keyhole-hw-{}-shelf", std::process::id()));
        let _ = fs::remove_dir_all(&shelf);
        fs::create_dir_all(&shelf).unwrap();
        let memory = HighWater::open(&dir).unwrap();
        memory.note(&shelf, 4).unwrap();
        let err = memory.check(&shelf, 2, false).unwrap_err();
        assert!(err.contains("backwards"), "{err}");
        memory.check(&shelf, 2, true).unwrap();
        memory.note(&shelf, 2).unwrap();
        assert_eq!(memory.highest(&shelf).unwrap(), 4);
        memory.note(&shelf, 5).unwrap();
        assert_eq!(memory.highest(&shelf).unwrap(), 5);
        let text = fs::read_to_string(memory.slot(&shelf).unwrap()).unwrap();
        assert_eq!(text, "4\n5\n");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&shelf);
    }
}
