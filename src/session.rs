//! An unlocked vault kept in this process, on a unix socket, never on a port.
//! Idle time drops the plaintext. The process stays and can read the file again.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::json;
use zeroize::Zeroize;

use crate::trust::Trust;
use crate::vault::Vault;

pub const DEFAULT_IDLE_SECS: u64 = 300;

// Linux 6.5. Not every libc crate version names it.
const SO_PEERPIDFD: libc::c_int = 77;

// Root-owned, mode 711. A program its user cannot read gets the same memory protection.
const WTYPE_PATH: &str = "/usr/local/lib/keyhole/wtype";

pub fn wtype_path() -> PathBuf {
    if cfg!(debug_assertions) {
        if let Some(path) = std::env::var_os("KEYHOLE_WTYPE") {
            return PathBuf::from(path);
        }
    }
    PathBuf::from(WTYPE_PATH)
}

pub fn socket_path() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("KEYHOLE_SOCKET") {
        return Ok(PathBuf::from(path));
    }
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        return Ok(PathBuf::from(runtime).join("keyhole/session.sock"));
    }
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    Ok(PathBuf::from(home).join(".cache/keyhole/session.sock"))
}

/// Decrypt once, then answer on the socket until the process exits.
/// `idle_secs` with no `names` or `ask` drops the plaintext. `unlock` reads the file again.
pub fn serve(vault_path: &Path, identity: &Path, idle_secs: u64) -> Result<(), String> {
    if idle_secs == 0 {
        return Err("idle time must be at least 1 second".into());
    }
    crate::harden::deny_memory_readers()?;
    let path = socket_path()?;
    ensure_free(&path)?;
    let vault_path = fs::canonicalize(vault_path)
        .map_err(|e| format!("vault path {}: {e}", vault_path.display()))?;
    let identity = fs::canonicalize(identity)
        .map_err(|e| format!("identity path {}: {e}", identity.display()))?;
    let mut session = Session {
        phase: Phase::Locked,
        last_use: Instant::now(),
        idle: Duration::from_secs(idle_secs),
        vault_path,
        identity,
    };
    session.reload()?;
    eprintln!("keyhole: unlocked");
    let listener = bind_private(&path)?;
    let _guard = SocketGuard(path.clone());
    eprintln!("keyhole: listening on {}", path.display());
    eprintln!("keyhole: locking after {idle_secs} seconds with no names or ask");

    let state = Arc::new(Mutex::new(session));
    let watcher = Arc::clone(&state);
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_millis(200));
            let mut session = match watcher.lock() {
                Ok(guard) => guard,
                Err(_) => return,
            };
            if session.expire() {
                eprintln!("keyhole: locked");
            }
        }
    });

    loop {
        let (mut stream, _) = match listener.accept() {
            Ok(pair) => pair,
            Err(err) => {
                eprintln!("keyhole: accept: {err}");
                continue;
            }
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let pid = match same_user(&stream) {
            Ok(pid) => pid,
            Err(err) => {
                let _ = write_all(&mut stream, &error_line(&err));
                continue;
            }
        };
        let line = match read_line(&mut stream) {
            Ok(line) => line,
            Err(_) => continue,
        };
        let request: Request = match serde_json::from_str(&line) {
            Ok(request) => request,
            Err(_) => {
                let _ = write_all(&mut stream, &error_line("request was not understood"));
                continue;
            }
        };
        if let Err(err) = authorize(&request, &stream, pid) {
            report_refusal(&request, pid, &err);
            let _ = write_all(&mut stream, &error_line(&err));
            continue;
        }
        let mut bytes = {
            let mut session = match state.lock() {
                Ok(guard) => guard,
                Err(_) => return Err("session lock".into()),
            };
            match session.dispatch(&request) {
                Ok(bytes) => bytes,
                Err(err) => error_line(&err),
            }
        };
        if let Err(err) = crate::harden::lock_secret(&bytes) {
            bytes.zeroize();
            let _ = write_all(&mut stream, &error_line(&err));
            continue;
        }
        let _ = write_all(&mut stream, &bytes);
        bytes.zeroize();
    }
}

pub fn names() -> Result<Vec<String>, String> {
    let reply = exchange("names", None)?;
    Ok(reply.names.unwrap_or_default())
}

pub struct Asked {
    pub username: String,
    pub password: String,
}

impl Drop for Asked {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
    }
}

pub fn ask(name: &str) -> Result<Asked, String> {
    let mut reply = exchange("ask", Some(name))?;
    let asked = Asked {
        username: reply.username.take().unwrap_or_default(),
        password: reply.password.take().ok_or("daemon reply had no secret")?,
    };
    crate::harden::lock_secret(asked.username.as_bytes())?;
    crate::harden::lock_secret(asked.password.as_bytes())?;
    Ok(asked)
}

pub fn lock() -> Result<(), String> {
    exchange("lock", None)?;
    Ok(())
}

pub fn unlock() -> Result<(), String> {
    exchange("unlock", None)?;
    Ok(())
}

pub fn locked() -> Result<bool, String> {
    let reply = exchange("session", None)?;
    Ok(reply.locked.unwrap_or(true))
}

struct Session {
    phase: Phase,
    last_use: Instant,
    idle: Duration,
    vault_path: PathBuf,
    identity: PathBuf,
}

enum Phase {
    Unlocked(Vault),
    Locked,
}

impl Session {
    fn reload(&mut self) -> Result<(), String> {
        let trust = Trust::open(&Trust::default_dir()?)?;
        let vault = crate::load(&self.identity, &self.vault_path, &trust)?;
        self.phase = Phase::Unlocked(vault);
        self.last_use = Instant::now();
        Ok(())
    }

    /// Forget the vault when the idle time has passed. True only on that change.
    fn expire(&mut self) -> bool {
        if !matches!(self.phase, Phase::Unlocked(_)) {
            return false;
        }
        if self.last_use.elapsed() < self.idle {
            return false;
        }
        self.phase = Phase::Locked;
        true
    }

    fn dispatch(&mut self, request: &Request) -> Result<Vec<u8>, String> {
        match request.op.as_str() {
            "session" => {
                let locked = !matches!(self.phase, Phase::Unlocked(_));
                encode(&json!({"ok": true, "locked": locked}))
            }
            "names" => {
                let Phase::Unlocked(vault) = &self.phase else {
                    return Err("locked".into());
                };
                let names = vault.names();
                self.last_use = Instant::now();
                encode(&json!({"ok": true, "names": names}))
            }
            "ask" => {
                let name = request
                    .name
                    .as_deref()
                    .filter(|name| !name.is_empty())
                    .ok_or("ask needs a name")?;
                let Phase::Unlocked(vault) = &self.phase else {
                    return Err("locked".into());
                };
                let Some(item) = vault.get(name) else {
                    return Err(format!("no entry '{name}'"));
                };
                let bytes = encode(&json!({
                    "ok": true,
                    "username": item.username(),
                    "password": item.password(),
                }))?;
                self.last_use = Instant::now();
                Ok(bytes)
            }
            "lock" => {
                if matches!(self.phase, Phase::Unlocked(_)) {
                    self.phase = Phase::Locked;
                    eprintln!("keyhole: locked");
                }
                encode(&json!({"ok": true, "locked": true}))
            }
            "unlock" => {
                self.reload()?;
                eprintln!("keyhole: unlocked");
                encode(&json!({"ok": true, "locked": false}))
            }
            other => Err(format!("unknown request '{other}'")),
        }
    }
}

#[derive(serde::Deserialize)]
struct Request {
    op: String,
    #[serde(default)]
    name: Option<String>,
}

#[derive(serde::Deserialize)]
struct Reply {
    ok: bool,
    error: Option<String>,
    locked: Option<bool>,
    names: Option<Vec<String>>,
    username: Option<String>,
    password: Option<String>,
}

fn exchange(op: &str, name: Option<&str>) -> Result<Reply, String> {
    let path = socket_path()?;
    let mut stream = UnixStream::connect(&path).map_err(|_| {
        "no keyhole daemon is listening. start one with: keyhole daemon VAULT -i IDENTITY"
            .to_string()
    })?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
    let mut request = serde_json::to_vec(&json!({"op": op, "name": name}))
        .map_err(|e| format!("encode request: {e}"))?;
    request.push(b'\n');
    stream
        .write_all(&request)
        .map_err(|e| format!("write request: {e}"))?;
    request.zeroize();
    let line = read_line(&mut stream)?;
    let mut reply: Reply =
        serde_json::from_str(&line).map_err(|_| "daemon reply was not understood".to_string())?;
    if !reply.ok {
        if let Some(password) = reply.password.as_mut() {
            password.zeroize();
        }
        return Err(reply
            .error
            .unwrap_or_else(|| "daemon refused the request".into()));
    }
    Ok(reply)
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec(value).map_err(|e| format!("encode reply: {e}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn error_line(message: &str) -> Vec<u8> {
    encode(&json!({"ok": false, "error": message})).unwrap_or_else(|_| {
        let mut bytes = br#"{"ok":false,"error":"internal"}"#.to_vec();
        bytes.push(b'\n');
        bytes
    })
}

fn write_all(stream: &mut UnixStream, bytes: &[u8]) -> Result<(), String> {
    stream
        .write_all(bytes)
        .map_err(|e| format!("write reply: {e}"))
}

fn read_line(stream: &mut UnixStream) -> Result<String, String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if buf.len() >= 1024 * 1024 {
            return Err("message is too long".into());
        }
        match stream.read(&mut byte) {
            Ok(0) => return Err("connection closed".into()),
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                buf.push(byte[0]);
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err)
                if err.kind() == io::ErrorKind::TimedOut
                    || err.kind() == io::ErrorKind::WouldBlock =>
            {
                return Err("timed out".into());
            }
            Err(err) => return Err(err.to_string()),
        }
    }
    String::from_utf8(buf).map_err(|_| "request is not utf-8".into())
}

/// An entry listed in the policy is only for the cgroups listed with it.
fn authorize(request: &Request, stream: &UnixStream, pid: i32) -> Result<(), String> {
    if request.op != "ask" {
        return Ok(());
    }
    let Some(name) = request.name.as_deref() else {
        return Ok(());
    };
    let policy = crate::policy::load()?;
    if !policy.restricts(name) {
        return Ok(());
    }
    let pidfd = peer_pidfd(stream)?;
    let cgroup = crate::policy::cgroup_of(pid)?;
    if !pid_is_alive(&pidfd) {
        return Err("client exited before it could be checked".into());
    }
    if !policy.allows(name, &cgroup) {
        return Err(format!("this program may not read '{name}'"));
    }
    Ok(())
}

/// Log and notify, because the refused program will not tell anyone.
fn report_refusal(request: &Request, pid: i32, reason: &str) {
    let name = request.name.as_deref().unwrap_or("?");
    let comm: String = fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || "-_.".contains(*c))
        .collect();
    let message = format!("refused {comm} (pid {pid}): {reason}");
    eprintln!("keyhole: {message}");
    let quiet = |program: &str, args: &[&str]| {
        let _ = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    };
    let body = format!("{message} [{name}]");
    thread::spawn(move || {
        quiet("/usr/bin/logger", &["-t", "keyhole", "--", &body]);
        quiet(
            "/usr/bin/notify-send",
            &["-a", "keyhole", "-u", "critical", "--", "keyhole", &body],
        );
    });
}

/// The pidfd names the process that connected, so a reused pid cannot pass the check.
fn peer_pidfd(stream: &UnixStream) -> Result<OwnedFd, String> {
    let mut fd: libc::c_int = -1;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_PEERPIDFD,
            &mut fd as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 || fd < 0 {
        return Err("could not identify the client".into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn pid_is_alive(pidfd: &OwnedFd) -> bool {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            0,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    rc == 0
}

fn same_user(stream: &UnixStream) -> Result<i32, String> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err("could not read the client user id".into());
    }
    let euid = unsafe { libc::geteuid() };
    if cred.uid != euid {
        return Err("refusing a client that is not you".into());
    }
    Ok(cred.pid)
}

fn ensure_free(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    match UnixStream::connect(path) {
        Ok(_) => Err("a keyhole daemon is already listening".into()),
        Err(_) => fs::remove_file(path)
            .map_err(|e| format!("remove stale socket {}: {e}", path.display())),
    }
}

fn bind_private(path: &Path) -> Result<UnixListener, String> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("chmod {}: {e}", dir.display()))?;
        }
    }
    let old = unsafe { libc::umask(0o177) };
    let bound = UnixListener::bind(path);
    unsafe {
        libc::umask(old);
    }
    let listener = bound.map_err(|e| format!("listen on {}: {e}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    Ok(listener)
}

struct SocketGuard(PathBuf);

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Item;

    fn open_session() -> Session {
        let mut vault = Vault::empty(vec!["age1example".into()]);
        vault
            .add(Item::new("demo", "ada", "s3cret-value", ""))
            .unwrap();
        Session {
            phase: Phase::Unlocked(vault),
            last_use: Instant::now(),
            idle: Duration::from_secs(30),
            vault_path: PathBuf::from("vault.age"),
            identity: PathBuf::from("identity.txt"),
        }
    }

    #[test]
    fn status_does_not_keep_the_vault_open() {
        let mut session = open_session();
        session
            .dispatch(&Request {
                op: "session".into(),
                name: None,
            })
            .unwrap();
        session.last_use = Instant::now() - Duration::from_secs(31);
        assert!(session.expire());
        let err = session
            .dispatch(&Request {
                op: "ask".into(),
                name: Some("demo".into()),
            })
            .unwrap_err();
        assert_eq!(err, "locked");
    }

    #[test]
    fn names_and_ask_refresh_the_idle_time() {
        let mut session = open_session();
        session.last_use = Instant::now() - Duration::from_secs(29);
        session
            .dispatch(&Request {
                op: "names".into(),
                name: None,
            })
            .unwrap();
        assert!(!session.expire());
        let bytes = session
            .dispatch(&Request {
                op: "ask".into(),
                name: Some("demo".into()),
            })
            .unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("s3cret-value"));
        assert!(text.contains("ada"));
        assert!(!session.expire());
    }
}
