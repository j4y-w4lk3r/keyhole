//! CLI for a local age vault. Passwords are read from the terminal, never from argv.

use std::env;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

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
        "version" => cmd_version(args),
        other => Err(format!("unknown command '{other}'\n\n{}", help_text())),
    }
}

struct Flags {
    positional: Vec<String>,
    recipients: Vec<PathBuf>,
    identity: Option<PathBuf>,
    base: Option<u64>,
}

fn parse_flags(args: impl Iterator<Item = String>) -> Result<Flags, String> {
    let mut flags = Flags {
        positional: Vec::new(),
        recipients: Vec::new(),
        identity: None,
        base: None,
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
            "-h" | "--help" => return Err(help_text()),
            other if other.starts_with('-') => return Err(format!("unknown flag {other}")),
            other => flags.positional.push(other.to_string()),
        }
    }
    Ok(flags)
}

fn cmd_init(args: impl Iterator<Item = String>) -> Result<(), String> {
    let flags = parse_flags(args)?;
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
    let vault = vault::Vault::empty(recipients);
    store(Path::new(vault_path), &vault)
}

fn cmd_list(args: impl Iterator<Item = String>) -> Result<(), String> {
    let flags = parse_flags(args)?;
    let [vault_path] = one_positional(&flags, "list VAULT -i IDENTITY")?;
    let identity = flags.identity.as_deref().ok_or("list needs -i IDENTITY")?;
    let vault = load(identity, Path::new(vault_path))?;
    for name in vault.names() {
        println!("{name}");
    }
    Ok(())
}

fn cmd_add(args: impl Iterator<Item = String>) -> Result<(), String> {
    let flags = parse_flags(args)?;
    let [vault_path, name] = two_positionals(&flags, "add VAULT -i IDENTITY NAME")?;
    let identity = flags.identity.as_deref().ok_or("add needs -i IDENTITY")?;
    let mut vault = load(identity, Path::new(vault_path))?;
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
    store(Path::new(vault_path), &vault)
}

fn cmd_pull(args: impl Iterator<Item = String>) -> Result<(), String> {
    let flags = parse_flags(args)?;
    let [shelf_dir, dest] = two_positionals(&flags, "pull SHELF DEST")?;
    let shelf = keyhole::shelf::Shelf::open(Path::new(shelf_dir))?;
    let Some(rev) = shelf.fetch()? else {
        return Err("shelf is empty".into());
    };
    let dest = Path::new(dest);
    let tmp = dest.with_extension("age.tmp");
    std::fs::write(&tmp, &rev.bytes).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, dest).map_err(|e| format!("replace {}: {e}", dest.display()))?;
    eprintln!("version {}", rev.version);
    Ok(())
}

fn cmd_push(args: impl Iterator<Item = String>) -> Result<(), String> {
    let flags = parse_flags(args)?;
    let [shelf_dir, vault_path] = two_positionals(&flags, "push SHELF VAULT --base VERSION")?;
    let expected = flags
        .base
        .ok_or("push needs --base VERSION (use 0 for an empty shelf)")?;
    let bytes = std::fs::read(vault_path).map_err(|e| format!("read {vault_path}: {e}"))?;
    let shelf = keyhole::shelf::Shelf::open(Path::new(shelf_dir))?;
    let version = shelf.publish(expected, &bytes)?;
    eprintln!("version {version}");
    Ok(())
}

fn cmd_serve(args: impl Iterator<Item = String>) -> Result<(), String> {
    let flags = parse_flags(args)?;
    let [shelf_dir, addr] = two_positionals(&flags, "serve SHELF ADDR")?;
    keyhole::shelf::serve(Path::new(shelf_dir), addr)
}

fn cmd_version(_args: impl Iterator<Item = String>) -> Result<(), String> {
    println!("keyhole 0.1.0");
    Ok(())
}

fn cmd_get(args: impl Iterator<Item = String>) -> Result<(), String> {
    let flags = parse_flags(args)?;
    let [vault_path, name] = two_positionals(&flags, "get VAULT -i IDENTITY NAME")?;
    let identity = flags.identity.as_deref().ok_or("get needs -i IDENTITY")?;
    let vault = load(identity, Path::new(vault_path))?;
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
  keyhole pull SHELF DEST
  keyhole push SHELF VAULT --base VERSION
  keyhole serve SHELF 127.0.0.1:8787
  keyhole version

The password is typed at the prompt. It is not an argument, so it stays out of shell history.
list prints names. On a terminal, get shows the password on a screen that is discarded when you press Enter. When stdout is a pipe, get writes the password once and the username on stderr.
push is accepted only when --base is the shelf's current version. The first push uses --base 0.
"
    .into()
}
