//! CLI for a local age vault. Passwords are read from the terminal, never from argv.

use std::env;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use keyhole::vault::{self, Item};
use keyhole::{load, store};
use zeroize::Zeroize;

fn main() -> ExitCode {
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
        other => Err(format!("unknown command '{other}'\n\n{}", help_text())),
    }
}

struct Flags {
    positional: Vec<String>,
    recipients: Vec<PathBuf>,
    identity: Option<PathBuf>,
}

fn parse_flags(args: impl Iterator<Item = String>) -> Result<Flags, String> {
    let mut flags = Flags {
        positional: Vec::new(),
        recipients: Vec::new(),
        identity: None,
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

fn cmd_get(args: impl Iterator<Item = String>) -> Result<(), String> {
    let flags = parse_flags(args)?;
    let [vault_path, name] = two_positionals(&flags, "get VAULT -i IDENTITY NAME")?;
    let identity = flags.identity.as_deref().ok_or("get needs -i IDENTITY")?;
    let vault = load(identity, Path::new(vault_path))?;
    let Some(item) = vault.get(name) else {
        return Err(format!("no entry '{name}'"));
    };
    if !item.username().is_empty() {
        eprintln!("username: {}", item.username());
    }
    println!("{}", item.password());
    Ok(())
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

The password is typed at the prompt. It is not an argument, so it stays out of shell history.
list prints names. get prints the password on stdout and the username on stderr.
"
    .into()
}
