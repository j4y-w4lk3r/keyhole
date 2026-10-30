//! Which programs may read an entry from the daemon, kept in a root-owned file.
//! Each line is `ENTRY CGROUP`. An entry with no lines stays open to any program you run.
//! A program running as you cannot move itself into a system service's cgroup.

use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const POLICY_PATH: &str = "/etc/keyhole/policy";

#[derive(Default)]
pub struct Policy {
    rules: Vec<(String, String)>,
}

impl Policy {
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut rules = Vec::new();
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.is_empty() || fields[0].starts_with('#') {
                continue;
            }
            let [entry, cgroup] = fields[..] else {
                return Err("each policy line must be: ENTRY CGROUP".into());
            };
            if !cgroup.starts_with('/') {
                return Err("a policy cgroup must start with /".into());
            }
            rules.push((entry.to_string(), cgroup.to_string()));
        }
        Ok(Self { rules })
    }

    pub fn restricts(&self, entry: &str) -> bool {
        self.rules.iter().any(|(name, _)| name == entry)
    }

    pub fn allows(&self, entry: &str, cgroup: &str) -> bool {
        self.rules
            .iter()
            .any(|(name, allowed)| name == entry && allowed == cgroup)
    }
}

/// Read fresh on each request, so a damaged file refuses instead of opening up.
pub fn load() -> Result<Policy, String> {
    load_from(&policy_path(), required_owner())
}

fn policy_path() -> PathBuf {
    if cfg!(debug_assertions) {
        if let Some(path) = std::env::var_os("KEYHOLE_POLICY") {
            return PathBuf::from(path);
        }
    }
    PathBuf::from(POLICY_PATH)
}

fn required_owner() -> u32 {
    if cfg!(debug_assertions) && std::env::var_os("KEYHOLE_POLICY").is_some() {
        unsafe { libc::geteuid() }
    } else {
        0
    }
}

fn load_from(path: &Path, owner: u32) -> Result<Policy, String> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Policy::default()),
        Err(err) => return Err(format!("read policy: {err}")),
    };
    if !meta.file_type().is_file() {
        return Err("policy must be a regular file (links are refused)".into());
    }
    check_protected(&meta, owner)?;
    if let Some(dir) = path.parent() {
        let dir_meta = fs::metadata(dir).map_err(|e| format!("read policy folder: {e}"))?;
        check_protected(&dir_meta, owner)?;
    }
    let text = fs::read_to_string(path).map_err(|e| format!("read policy: {e}"))?;
    Policy::parse(&text)
}

fn check_protected(meta: &fs::Metadata, owner: u32) -> Result<(), String> {
    if meta.uid() != owner {
        return Err("policy and its folder must be owned by root".into());
    }
    if meta.permissions().mode() & 0o022 != 0 {
        return Err("policy and its folder must not be writable by others".into());
    }
    Ok(())
}

/// The cgroup v2 path from `/proc/PID/cgroup`.
pub fn cgroup_of(pid: i32) -> Result<String, String> {
    let text = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map_err(|e| format!("read client cgroup: {e}"))?;
    parse_cgroup(&text).ok_or_else(|| "client has no cgroup v2 path".to_string())
}

fn parse_cgroup(text: &str) -> Option<String> {
    text.lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVICE: &str = "/system.slice/keychord.service";

    #[test]
    fn an_entry_with_rules_allows_only_those_cgroups() {
        let policy = Policy::parse(&format!("# note\n\ndemo {SERVICE}\n")).unwrap();
        assert!(policy.restricts("demo"));
        assert!(policy.allows("demo", SERVICE));
        assert!(!policy.allows("demo", "/user.slice/keychord.service"));
        assert!(!policy.allows("demo", &format!("{SERVICE}/child")));
        assert!(!policy.restricts("other"));
    }

    #[test]
    fn bad_lines_are_errors() {
        assert!(Policy::parse("demo").is_err());
        assert!(Policy::parse("demo a b").is_err());
        assert!(Policy::parse("demo relative.service").is_err());
    }

    #[test]
    fn reads_only_the_cgroup_v2_line() {
        let text = format!("1:name=systemd:/fake\n0::{SERVICE}\n");
        assert_eq!(parse_cgroup(&text).unwrap(), SERVICE);
        assert_eq!(parse_cgroup("1:name=systemd:/fake\n"), None);
    }

    #[test]
    fn a_missing_file_is_open_and_an_unsafe_one_is_refused() {
        let dir = PathBuf::from(format!("/dev/shm/keyhole-policy-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let euid = unsafe { libc::geteuid() };
        let path = dir.join("policy");
        assert!(!load_from(&path, euid).unwrap().restricts("demo"));

        fs::write(&path, format!("demo {SERVICE}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_from(&path, euid).unwrap().restricts("demo"));
        assert!(load_from(&path, euid + 1).is_err());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o664)).unwrap();
        assert!(load_from(&path, euid).is_err());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(load_from(&path, euid).is_err());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();

        let link = dir.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(load_from(&link, euid).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
