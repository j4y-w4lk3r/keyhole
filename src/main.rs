//! CLI for a local age vault. Passwords are read from the terminal, never from argv.

use std::env;
use std::io::{self, IsTerminal, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use keyhole::highwater::HighWater;
use keyhole::trust::Trust;
use keyhole::vault::{self, Item};
use keyhole::{load, store};
use zeroize::Zeroize;

fn main() -> ExitCode {
    if let Err(err) = keyhole::harden::disable_core_dumps() {
        eprintln!("keyhole: {err}");
        return ExitCode::FAILURE;
    }
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("keyhole: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let Some(cmd) = args.next() else {
        print_help();
        return Ok(());
    };
    match cmd.as_str() {
        "help" | "-h" | "--help" => {
            print_help();
            Ok(())
        }
        "init" => cmd_init(args),
        "list" => cmd_list(args),
        "add" => cmd_add(args),
        "get" => cmd_get(args),
        "pull" => cmd_pull(args),
        "push" => cmd_push(args),
        "serve" => cmd_serve(args),
        "daemon" => cmd_daemon(args),
        "names" => cmd_names(args),
        "ask" => cmd_ask(args),
        "type" => cmd_type(args),
        "lock" => cmd_lock(args),
        "unlock" => cmd_unlock(args),
        "session" => cmd_session(args),
        "sign" => cmd_sign(args),
        "rekey" => cmd_rekey(args),
        "trust" => cmd_trust(args),
        "version" => cmd_version(args),
        other => Err(format!("unknown command '{other}'\n\n{}", help_text())),
    }
}

struct Flags {
    positional: Vec<String>,
    recipients: Vec<PathBuf>,
    identity: Option<PathBuf>,
    base: Option<u64>,
    accept_older: bool,
    idle: Option<u64>,
}

fn parse_flags(args: impl Iterator<Item = String>) -> Result<Flags, String> {
    let mut flags = Flags {
        positional: Vec::new(),
        recipients: Vec::new(),
        identity: None,
        base: None,
        accept_older: false,
        idle: None,
    };
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-R" => {
                let path = args.next().ok_or("-R needs a recipient file")?;
                flags.recipients.push(PathBuf::from(path));
            }
            "-i" => {
                let path = args.next().ok_or("-i needs an identity file")?;
                flags.identity = Some(PathBuf::from(path));
            }
            "--base" => {
                let n = args
                    .next()
                    .ok_or("--base needs the version you downloaded")?;
                flags.base = Some(n.parse().map_err(|_| "--base needs a number")?);
            }
            "--accept-older" => flags.accept_older = true,
            "--idle" => {
                let n = args.next().ok_or("--idle needs a number of seconds")?;
                flags.idle = Some(n.parse().map_err(|_| "--idle needs a number")?);
            }
            "-h" | "--help" => return Err(help_text()),
            other if other.starts_with('-') => return Err(format!("unknown flag {other}")),
            other => flags.positional.push(other.to_string()),
        }
    }
    Ok(flags)
}

impl Flags {
    fn no_idle(self) -> Result<Self, String> {
        if self.idle.is_some() {
            Err("--idle is only for daemon".into())
        } else {
            Ok(self)
        }
    }

    fn daemon_only(self) -> Result<Self, String> {
        if self.identity.is_some()
            || !self.recipients.is_empty()
            || self.base.is_some()
            || self.accept_older
            || self.idle.is_some()
        {
            Err("this command only talks to the running daemon".into())
        } else {
            Ok(self)
        }
    }
}

fn cmd_init(args: impl Iterator<Item = String>) -> Result<(), String> {
    let flags = parse_flags(args)?.no_idle()?;
    let [vault_path] = one_positional(&flags, "init VAULT -R RECIPIENT [-R RECIPIENT...]")?;
    if flags.recipients.is_empty() {
        return Err("init needs at least one -R recipient file".into());
    }
    if Path::new(vault_path).exists() {
        return Err(format!("{vault_path} already exists"));
    }
    let mut recipients = Vec::new();
    for path in &flags.recipients {
        recipients.extend(vault::read_recipient_file(path)?);
    }
    let trust = open_trust()?;
    trust.check_recipients(&recipients)?;
    let vault = vault::Vault::empty(recipients);
    store(Path::new(vault_path), &vault, &trust)
}

fn cmd_list(args: impl Iterator<Item = String>) -> Result<(), String> {
    let flags = parse_flags(args)?.no_idle()?;
    let [vault_path] = one_positional(&flags, "list VAULT -i IDENTITY")?;
    let identity = flags.identity.as_deref().ok_or("list needs -i IDENTITY")?;
    let vault = load(identity, Path::new(vault_path), &open_trust()?)?;
    for name in vault.names() {
        println!("{name}");
    }
    Ok(())
}

fn cmd_add(args: impl Iterator<Item = String>) -> Result<(), String> {
    let flags = parse_flags(args)?.no_idle()?;
    let [vault_path, name] = two_positionals(&flags, "add VAULT -i IDENTITY NAME")?;
    let identity = flags.identity.as_deref().ok_or("add needs -i IDENTITY")?;
    let mut vault = load(identity, Path::new(vault_path), &open_trust()?)?;
    let username = prompt_line("username: ")?;
    let mut password = prompt_secret("password: ")?;
    let mut confirm = prompt_secret("confirm: ")?;
    if password != confirm {
        password.zeroize();
        confirm.zeroize();
        return Err("passwords did not match".into());
    }
    confirm.zeroize();
    let item = Item::new(name, username, password, "");
    vault.add(item)?;
    store(Path::new(vault_path), &vault, &open_trust()?)
}

fn cmd_pull(args: impl Iterator<Item = String>) -> Result<(), String> {
    let flags = parse_flags(args)?.no_idle()?;
    let [shelf_dir, dest] = two_positionals(&flags, "pull SHELF DEST [--accept-older]")?;
    let shelf = keyhole::shelf::Shelf::open(Path::new(shelf_dir))?;
    let Some(rev) = shelf.fetch()? else {
        return Err("shelf is empty".into());
    };
    let shelf_path = std::fs::canonicalize(shelf_dir).map_err(|e| format!("shelf path: {e}"))?;
    let memory = open_memory()?;
    memory.check(&shelf_path, rev.version, flags.accept_older)?;
    open_trust()?.verify_detached(&rev.bytes, &rev.signature)?;
    let dest = Path::new(dest);
    write_private(dest, &rev.bytes)?;
    write_private(&keyhole::trust::signature_path(dest), &rev.signature)?;
    memory.note(&shelf_path, rev.version)?;
    eprintln!("version {}", rev.version);
    Ok(())
}

fn cmd_push(args: impl Iterator<Item = String>) -> Result<(), String> {
    let flags = parse_flags(args)?.no_idle()?;
    let [shelf_dir, vault_path] = two_positionals(&flags, "push SHELF VAULT --base VERSION")?;
    let expected = flags
        .base
        .ok_or("push needs --base VERSION (use 0 for an empty shelf)")?;
    let vault_path = Path::new(vault_path);
    let bytes =
        std::fs::read(vault_path).map_err(|e| format!("read {}: {e}", vault_path.display()))?;
    let signature = std::fs::read(keyhole::trust::signature_path(vault_path))
        .map_err(|_| "vault has no signature".to_string())?;
    open_trust()?.verify_detached(&bytes, &signature)?;
    let shelf = keyhole::shelf::Shelf::open(Path::new(shelf_dir))?;
    let version = shelf.publish(expected, &bytes, &signature)?;
    let shelf_path = std::fs::canonicalize(shelf_dir).map_err(|e| format!("shelf path: {e}"))?;
    open_memory()?.note(&shelf_path, version)?;
    eprintln!("version {version}");
    Ok(())
}

fn cmd_sign(args: impl Iterator<Item = String>) -> Result<(), String> {
    let flags = parse_flags(args)?.no_idle()?;
    let [vault_path] = one_positional(&flags, "sign VAULT")?;
    open_trust()?.sign(Path::new(vault_path))
}

fn cmd_rekey(args: impl Iterator<Item = String>) -> Result<(), String> {
    let flags = parse_flags(args)?.no_idle()?;
    let [vault_path] = one_positional(&flags, "rekey VAULT -i IDENTITY -R RECIPIENT")?;
    let identity = flags.identity.as_deref().ok_or("rekey needs -i IDENTITY")?;
    if flags.recipients.is_empty() {
        return Err("rekey needs at least one -R recipient file".into());
    }
    let trust = open_trust()?;
    let mut vault = load(identity, Path::new(vault_path), &trust)?;
    let mut recipients = Vec::new();
    for path in &flags.recipients {
        recipients.extend(vault::read_recipient_file(path)?);
    }
    trust.check_recipients(&recipients)?;
    vault.set_recipients(recipients)?;
    store(Path::new(vault_path), &vault, &trust)
}

fn cmd_trust(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    let sub = args.next().ok_or(
        "usage: keyhole trust allow-signer FINGERPRINT | use-signer FINGERPRINT | allow-recipient AGE1 | deny-recipient AGE1",
    )?;
    let trust = open_trust()?;
    match sub.as_str() {
        "allow-signer" => {
            let fpr = args.next().ok_or("allow-signer needs a fingerprint")?;
            trust.allow_signer(&fpr)
        }
        "use-signer" => {
            let fpr = args.next().ok_or("use-signer needs a fingerprint")?;
            trust.use_signer(&fpr)
        }
        "allow-recipient" => {
            let recipient = args
                .next()
                .ok_or("allow-recipient needs an age1 public key")?;
            trust.allow_recipient(&recipient)
        }
        "deny-recipient" => {
            let recipient = args
                .next()
                .ok_or("deny-recipient needs an age1 public key")?;
            trust.deny_recipient(&recipient)
        }
        other => Err(format!("unknown trust command '{other}'")),
    }
}

fn open_trust() -> Result<Trust, String> {
    Trust::open(&Trust::default_dir()?)
}

fn open_memory() -> Result<HighWater, String> {
    HighWater::open(&HighWater::default_dir()?)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = {
        let mut name = path.as_os_str().to_owned();
        name.push(".tmp");
        PathBuf::from(name)
    };
    std::fs::write(&tmp, bytes).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("replace {}: {e}", path.display()))
}

fn cmd_daemon(args: impl Iterator<Item = String>) -> Result<(), String> {
    let flags = parse_flags(args)?;
    let [vault_path] = one_positional(&flags, "daemon VAULT -i IDENTITY [--idle SECONDS]")?;
    let identity = flags
        .identity
        .as_deref()
        .ok_or("daemon needs -i IDENTITY")?;
    let idle = flags.idle.unwrap_or(keyhole::session::DEFAULT_IDLE_SECS);
    if idle == 0 {
        return Err("--idle must be at least 1 second".into());
    }
    keyhole::session::serve(Path::new(vault_path), identity, idle)
}

fn cmd_names(args: impl Iterator<Item = String>) -> Result<(), String> {
    let flags = parse_flags(args)?.daemon_only()?;
    if !flags.positional.is_empty() {
        return Err("usage: keyhole names".into());
    }
    for name in keyhole::session::names()? {
        println!("{name}");
    }
    Ok(())
}

/// Type an entry into the focused window, then Enter. The secret goes straight to
/// wtype. Installed unreadable, wtype is protected from other programs like this one.
fn cmd_type(args: impl Iterator<Item = String>) -> Result<(), String> {
    let flags = parse_flags(args)?.daemon_only()?;
    let [name] = one_positional(&flags, "type NAME")?;
    keyhole::harden::restore_child_signal();
    keyhole::harden::deny_memory_readers()?;
    let asked = keyhole::session::ask(name)?;
    let wtype = keyhole::session::wtype_path();
    let mut child = Command::new(&wtype)
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("start {}: {e}", wtype.display()))?;
    let mut stdin = child.stdin.take().ok_or("wtype has no input")?;
    for part in asked.password.split('\n') {
        stdin
            .write_all(part.as_bytes())
            .map_err(|e| format!("send to wtype: {e}"))?;
    }
    drop(stdin);
    let typed = child.wait().map_err(|e| format!("wtype: {e}"))?;
    if !typed.success() {
        return Err("wtype could not type".into());
    }
    let enter = Command::new(&wtype)
        .args(["-k", "Return"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("wtype: {e}"))?;
    if !enter.success() {
        return Err("wtype could not press Enter".into());
    }
    Ok(())
}

fn cmd_ask(args: impl Iterator<Item = String>) -> Result<(), String> {
    let flags = parse_flags(args)?.daemon_only()?;
    let [name] = one_positional(&flags, "ask NAME")?;
    let asked = keyhole::session::ask(name)?;
    match keyhole::reveal::secret_sink(io::stdout().is_terminal()) {
        keyhole::reveal::SecretSink::Terminal => {
            keyhole::reveal::reveal_on_terminal(&asked.username, &asked.password)
        }
        keyhole::reveal::SecretSink::Pipe => {
            if !asked.username.is_empty() {
                eprintln!("username: {}", asked.username);
            }
            println!("{}", asked.password);
            Ok(())
        }
    }
}

fn cmd_lock(args: impl Iterator<Item = String>) -> Result<(), String> {
    let flags = parse_flags(args)?.daemon_only()?;
    if !flags.positional.is_empty() {
        return Err("usage: keyhole lock".into());
    }
    keyhole::session::lock()?;
    eprintln!("locked");
    Ok(())
}

fn cmd_unlock(args: impl Iterator<Item = String>) -> Result<(), String> {
    let flags = parse_flags(args)?.daemon_only()?;
    if !flags.positional.is_empty() {
        return Err("usage: keyhole unlock".into());
    }
    keyhole::session::unlock()?;
    eprintln!("unlocked");
    Ok(())
}

fn cmd_session(args: impl Iterator<Item = String>) -> Result<(), String> {
    let flags = parse_flags(args)?.daemon_only()?;
    if !flags.positional.is_empty() {
        return Err("usage: keyhole session".into());
    }
    if keyhole::session::locked()? {
        println!("locked");
    } else {
        println!("unlocked");
    }
    Ok(())
}

fn cmd_serve(args: impl Iterator<Item = String>) -> Result<(), String> {
    let flags = parse_flags(args)?.no_idle()?;
    let [shelf_dir, addr] = two_positionals(&flags, "serve SHELF ADDR")?;
    keyhole::shelf::serve(Path::new(shelf_dir), addr)
}

fn cmd_version(_args: impl Iterator<Item = String>) -> Result<(), String> {
    println!("keyhole 0.1.0");
    Ok(())
}

fn cmd_get(args: impl Iterator<Item = String>) -> Result<(), String> {
    let flags = parse_flags(args)?.no_idle()?;
    let [vault_path, name] = two_positionals(&flags, "get VAULT -i IDENTITY NAME")?;
    let identity = flags.identity.as_deref().ok_or("get needs -i IDENTITY")?;
    let vault = load(identity, Path::new(vault_path), &open_trust()?)?;
    let Some(item) = vault.get(name) else {
        return Err(format!("no entry '{name}'"));
    };
    match keyhole::reveal::secret_sink(io::stdout().is_terminal()) {
        keyhole::reveal::SecretSink::Terminal => {
            keyhole::reveal::reveal_on_terminal(item.username(), item.password())
        }
        keyhole::reveal::SecretSink::Pipe => {
            if !item.username().is_empty() {
                eprintln!("username: {}", item.username());
            }
            println!("{}", item.password());
            Ok(())
        }
    }
}

fn one_positional<'a>(flags: &'a Flags, usage: &str) -> Result<[&'a str; 1], String> {
    match flags.positional.as_slice() {
        [a] => Ok([a.as_str()]),
        _ => Err(format!("usage: keyhole {usage}")),
    }
}

fn two_positionals<'a>(flags: &'a Flags, usage: &str) -> Result<[&'a str; 2], String> {
    match flags.positional.as_slice() {
        [a, b] => Ok([a.as_str(), b.as_str()]),
        _ => Err(format!("usage: keyhole {usage}")),
    }
}

fn prompt_line(label: &str) -> Result<String, String> {
    eprint!("{label}");
    io::stderr().flush().map_err(|e| e.to_string())?;
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    Ok(line)
}

fn prompt_secret(label: &str) -> Result<String, String> {
    rpassword::prompt_password(label).map_err(|e| format!("password prompt: {e}"))
}

fn print_help() {
    print!("{}", help_text());
}

fn help_text() -> String {
    "\
keyhole — a local age vault

  keyhole init VAULT -R RECIPIENT [-R RECIPIENT...]
  keyhole list VAULT -i IDENTITY
  keyhole add  VAULT -i IDENTITY NAME
  keyhole get  VAULT -i IDENTITY NAME
  keyhole sign VAULT
  keyhole rekey VAULT -i IDENTITY -R RECIPIENT [-R RECIPIENT...]
  keyhole trust allow-signer FINGERPRINT
  keyhole trust use-signer FINGERPRINT
  keyhole trust allow-recipient AGE1
  keyhole trust deny-recipient AGE1
  keyhole pull SHELF DEST [--accept-older]
  keyhole push SHELF VAULT --base VERSION
  keyhole serve SHELF 127.0.0.1:8787
  keyhole daemon VAULT -i IDENTITY [--idle SECONDS]
  keyhole names
  keyhole ask NAME
  keyhole type NAME
  keyhole lock
  keyhole unlock
  keyhole session
  keyhole version

The password is typed at the prompt. It is not an argument, so it stays out of shell history.
list prints names. On a terminal, get shows the password on a screen that is discarded when you press Enter. When stdout is a pipe, get writes the password once and the username on stderr.
A vault is opened only when its signature is from a pinned signer, or from a subkey of that signer, and every recipient is pinned. sign uses your terminal so the Bio PIN prompt can open.
push is accepted only when --base is the shelf's current version. The first push uses --base 0. The shelf then keeps the newest five revisions.
pull refuses a version older than this machine has already seen, unless --accept-older is set.
serve keeps its write token in SHELF/write.token. GET does not need it. PUT does.
daemon decrypts once and answers names and ask on a unix socket owned by you. It is not a network port. After --idle seconds with no names or ask (300 by default) it forgets the vault and stays running. unlock reads the file again. lock forgets it now.
"
    .into()
}
