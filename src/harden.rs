//! Process limits and identity-file checks.
//! A crash must not write the vault to disk. A key file other people can read is refused.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

pub fn disable_core_dumps() -> Result<(), String> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) };
    if rc != 0 {
        Err("refusing to run with core dumps enabled".into())
    } else {
        Ok(())
    }
}

/// The identity is a regular file, owned by this user, mode 600 or 400.
/// Symlinks are refused so the mode check cannot be pointed at some other file.
pub fn check_identity(path: &Path) -> Result<(), String> {
    let meta =
        fs::symlink_metadata(path).map_err(|e| format!("read identity {}: {e}", path.display()))?;
    if !meta.file_type().is_file() {
        return Err("identity must be a regular file (links are refused)".into());
    }
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err("identity must be owned by you".into());
    }
    let mode = meta.permissions().mode() & 0o777;
    if !owner_only_mode(mode) {
        return Err(format!(
            "identity must be mode 600, so only you can read it (found {mode:o})"
        ));
    }
    Ok(())
}

pub fn owner_only_mode(mode: u32) -> bool {
    mode == 0o600 || mode == 0o400
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    #[test]
    fn core_dumps_are_disabled() {
        disable_core_dumps().unwrap();
        let mut limit = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) };
        assert_eq!(rc, 0);
        assert_eq!(limit.rlim_cur, 0);
    }

    #[test]
    fn owner_only_modes() {
        assert!(owner_only_mode(0o600));
        assert!(owner_only_mode(0o400));
        assert!(!owner_only_mode(0o644));
        assert!(!owner_only_mode(0o640));
        assert!(!owner_only_mode(0o700));
    }

    #[test]
    fn rejects_a_group_readable_identity_and_a_link() {
        let dir = PathBuf::from(format!("/dev/shm/keyhole-id-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("identity.txt");
        fs::write(&path, b"not-a-key\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let err = check_identity(&path).unwrap_err();
        assert!(err.contains("600"), "{err}");

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        check_identity(&path).unwrap();

        let link = dir.join("identity-link");
        symlink(&path, &link).unwrap();
        let err = check_identity(&link).unwrap_err();
        assert!(err.contains("regular file"), "{err}");
        let _ = fs::remove_dir_all(&dir);
    }
}
