use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use keyhole::store;
use keyhole::trust::Trust;
use keyhole::vault::{Item, Vault};

struct Practice {
    dir: PathBuf,
    gpg: PathBuf,
    state: PathBuf,
    identity: PathBuf,
    recipient_file: PathBuf,
    vault: PathBuf,
}

impl Practice {
    fn new(name: &str) -> Self {
        let dir = PathBuf::from(format!("/dev/shm/keyhole-it-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let gpg = dir.join("gpg");
        fs::create_dir_all(&gpg).unwrap();
        fs::set_permissions(&gpg, fs::Permissions::from_mode(0o700)).unwrap();
        let status = keyhole::gpgbin::gpg_command()
            .unwrap()
            .arg("--homedir")
            .arg(&gpg)
            .args([
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-gen-key",
                "keyhole test <keyhole@example.com>",
                "ed25519",
                "sign",
                "never",
            ])
            .status()
            .unwrap();
        assert!(status.success());
        let listed = keyhole::gpgbin::gpg_command()
            .unwrap()
            .arg("--homedir")
            .arg(&gpg)
            .args(["--list-secret-keys", "--with-colons"])
            .output()
            .unwrap();
        let text = String::from_utf8(listed.stdout).unwrap();
        let fpr = text
            .lines()
            .find(|line| line.starts_with("fpr:"))
            .unwrap()
            .split(':')
            .nth(9)
            .unwrap();

        let identity = dir.join("identity.txt");
        assert!(
            Command::new("age-keygen")
                .arg("-o")
                .arg(&identity)
                .status()
                .unwrap()
                .success()
        );
        let id_text = fs::read_to_string(&identity).unwrap();
        let recipient = id_text
            .lines()
            .find_map(|line| line.strip_prefix("# public key: "))
            .unwrap()
            .to_string();
        let recipient_file = dir.join("recipient.txt");
        fs::write(&recipient_file, format!("{recipient}\n")).unwrap();

        let state = dir.join("state");
        let trust = Trust::open(&state.join("trust"))
            .unwrap()
            .with_keyring(&gpg);
        trust.allow_signer(fpr).unwrap();
        trust.allow_recipient(&recipient).unwrap();
        let vault = dir.join("vault.age");

        Self {
            dir,
            gpg,
            state,
            identity,
            recipient_file,
            vault,
        }
    }

    fn trust(&self) -> Trust {
        Trust::open(&self.state.join("trust"))
            .unwrap()
            .with_keyring(&self.gpg)
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_keyhole"));
        cmd.env("KEYHOLE_STATE_DIR", &self.state);
        cmd.env("GNUPGHOME", &self.gpg);
        cmd
    }
}

impl Drop for Practice {
    fn drop(&mut self) {
        let _ = Command::new("/usr/bin/gpgconf")
            .arg("--homedir")
            .arg(&self.gpg)
            .args(["--kill", "gpg-agent"])
            .status();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn password_is_not_present_in_the_age_file() {
    let practice = Practice::new("round");
    let mut vault = Vault::empty(vec![
        fs::read_to_string(&practice.recipient_file)
            .unwrap()
            .trim()
            .to_string(),
    ]);
    vault
        .add(Item::new("demo", "ada", "s3cret-value", ""))
        .unwrap();
    store(&practice.vault, &vault, &practice.trust()).unwrap();
    drop(vault);

    let raw = fs::read(&practice.vault).unwrap();
    assert!(raw.starts_with(b"age-encryption.org/v1\n"));
    assert!(
        !raw.windows(b"s3cret-value".len())
            .any(|w| w == b"s3cret-value")
    );

    let listed = practice
        .command()
        .arg("list")
        .arg(&practice.vault)
        .arg("-i")
        .arg(&practice.identity)
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    assert_eq!(String::from_utf8(listed.stdout).unwrap().trim(), "demo");

    let got = practice
        .command()
        .arg("get")
        .arg(&practice.vault)
        .arg("-i")
        .arg(&practice.identity)
        .arg("demo")
        .output()
        .unwrap();
    assert!(
        got.status.success(),
        "{}",
        String::from_utf8_lossy(&got.stderr)
    );
    assert_eq!(
        String::from_utf8(got.stdout).unwrap().trim(),
        "s3cret-value"
    );
}

#[test]
fn a_changed_byte_and_an_unpinned_recipient_are_refused() {
    let practice = Practice::new("sig");
    let recipient = fs::read_to_string(&practice.recipient_file)
        .unwrap()
        .trim()
        .to_string();
    let mut vault = Vault::empty(vec![recipient]);
    vault
        .add(Item::new("demo", "ada", "s3cret-value", ""))
        .unwrap();
    store(&practice.vault, &vault, &practice.trust()).unwrap();

    let mut raw = fs::read(&practice.vault).unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 0xff;
    fs::write(&practice.vault, &raw).unwrap();
    let tampered = practice
        .command()
        .arg("list")
        .arg(&practice.vault)
        .arg("-i")
        .arg(&practice.identity)
        .output()
        .unwrap();
    assert!(!tampered.status.success());
    assert!(String::from_utf8_lossy(&tampered.stderr).contains("signature"));

    store(&practice.vault, &vault, &practice.trust()).unwrap();
    let bad = practice.dir.join("bad-recipient.txt");
    fs::write(
        &bad,
        "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\n",
    )
    .unwrap();
    let rekey = practice
        .command()
        .args([
            "rekey",
            practice.vault.to_str().unwrap(),
            "-i",
            practice.identity.to_str().unwrap(),
            "-R",
            bad.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !rekey.status.success(),
        "{}",
        String::from_utf8_lossy(&rekey.stderr)
    );
    assert!(String::from_utf8_lossy(&rekey.stderr).contains("not pinned"));
}

#[test]
fn pull_refuses_a_version_this_machine_has_already_passed() {
    let practice = Practice::new("roll");
    let recipient = fs::read_to_string(&practice.recipient_file)
        .unwrap()
        .trim()
        .to_string();
    let mut vault = Vault::empty(vec![recipient]);
    vault
        .add(Item::new("demo", "ada", "s3cret-value", ""))
        .unwrap();
    store(&practice.vault, &vault, &practice.trust()).unwrap();

    let shelf = practice.dir.join("shelf");
    let first = practice
        .command()
        .args([
            "push",
            shelf.to_str().unwrap(),
            practice.vault.to_str().unwrap(),
            "--base",
            "0",
        ])
        .output()
        .unwrap();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let second = practice
        .command()
        .args([
            "push",
            shelf.to_str().unwrap(),
            practice.vault.to_str().unwrap(),
            "--base",
            "1",
        ])
        .output()
        .unwrap();
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    fs::write(shelf.join("version"), "1\n").unwrap();
    let pulled = practice
        .command()
        .args([
            "pull",
            shelf.to_str().unwrap(),
            practice.dir.join("copy.age").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!pulled.status.success());
    assert!(String::from_utf8_lossy(&pulled.stderr).contains("backwards"));
}

#[test]
fn an_extra_age_recipient_is_refused() {
    let practice = Practice::new("hide");
    let recipient_a = fs::read_to_string(&practice.recipient_file)
        .unwrap()
        .trim()
        .to_string();
    let id_b = practice.dir.join("id-b.txt");
    assert!(
        Command::new("age-keygen")
            .arg("-o")
            .arg(&id_b)
            .status()
            .unwrap()
            .success()
    );
    let recipient_b = fs::read_to_string(&id_b)
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("# public key: "))
        .unwrap()
        .to_string();
    let mut vault = Vault::empty(vec![recipient_a.clone()]);
    vault
        .add(Item::new("demo", "ada", "s3cret-value", ""))
        .unwrap();
    let plain = vault.to_plaintext().unwrap();
    let mut child = keyhole::agebin::age_command()
        .unwrap()
        .args(["-r", &recipient_a, "-r", &recipient_b, "-o"])
        .arg(&practice.vault)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&plain).unwrap();
    assert!(child.wait().unwrap().success());
    practice.trust().sign(&practice.vault).unwrap();
    let Err(err) = keyhole::load(&practice.identity, &practice.vault, &practice.trust()) else {
        panic!("hidden recipient was accepted");
    };
    assert!(err.contains("hidden"), "{err}");
}

#[test]
fn daemon_locks_when_idle_and_unlock_reads_again() {
    let practice = Practice::new("daemon");
    let recipient = fs::read_to_string(&practice.recipient_file)
        .unwrap()
        .trim()
        .to_string();
    let mut vault = Vault::empty(vec![recipient]);
    vault
        .add(Item::new("demo", "ada", "s3cret-value", ""))
        .unwrap();
    store(&practice.vault, &vault, &practice.trust()).unwrap();
    drop(vault);

    let sock = practice.dir.join("session.sock");
    let child = practice
        .command()
        .arg("daemon")
        .arg(&practice.vault)
        .arg("-i")
        .arg(&practice.identity)
        .args(["--idle", "1"])
        .env("KEYHOLE_SOCKET", &sock)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let daemon = DaemonGuard(child);

    if !wait_for_session(&practice, &sock) {
        panic!("daemon did not start\n{}", daemon.stderr());
    }

    let listed = client(&practice, &sock, &["names"]);
    assert!(listed.status.success(), "{}", stderr(&listed));
    assert_eq!(String::from_utf8(listed.stdout).unwrap().trim(), "demo");

    let asked = client(&practice, &sock, &["ask", "demo"]);
    assert!(asked.status.success(), "{}", stderr(&asked));
    assert!(stderr(&asked).contains("username: ada"));
    assert_eq!(
        String::from_utf8(asked.stdout).unwrap().trim(),
        "s3cret-value"
    );

    let mut saw_locked = false;
    for _ in 0..40 {
        let state = client(&practice, &sock, &["session"]);
        if state.status.success() && String::from_utf8_lossy(&state.stdout).trim() == "locked" {
            saw_locked = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(saw_locked, "idle lock did not drop the vault");

    let refused = client(&practice, &sock, &["ask", "demo"]);
    assert!(!refused.status.success());
    assert!(stderr(&refused).contains("locked"));

    let unlocked = client(&practice, &sock, &["unlock"]);
    assert!(unlocked.status.success(), "{}", stderr(&unlocked));
    let asked = client(&practice, &sock, &["ask", "demo"]);
    assert_eq!(
        String::from_utf8(asked.stdout).unwrap().trim(),
        "s3cret-value"
    );

    let locked = client(&practice, &sock, &["lock"]);
    assert!(locked.status.success(), "{}", stderr(&locked));
    let state = client(&practice, &sock, &["session"]);
    assert_eq!(String::from_utf8(state.stdout).unwrap().trim(), "locked");

    let second = client(
        &practice,
        &sock,
        &[
            "daemon",
            practice.vault.to_str().unwrap(),
            "-i",
            practice.identity.to_str().unwrap(),
        ],
    );
    assert!(!second.status.success());
    assert!(stderr(&second).contains("already listening"));

    let err = daemon.stderr();
    assert!(
        !err.contains("s3cret-value"),
        "daemon stderr contained the secret"
    );
}

#[test]
fn the_policy_limits_who_can_ask_and_the_daemon_hides_its_memory() {
    let practice = Practice::new("policy");
    let recipient = fs::read_to_string(&practice.recipient_file)
        .unwrap()
        .trim()
        .to_string();
    let mut vault = Vault::empty(vec![recipient]);
    for name in ["mine", "theirs", "open"] {
        vault
            .add(Item::new(name, "ada", format!("{name}-value"), ""))
            .unwrap();
    }
    store(&practice.vault, &vault, &practice.trust()).unwrap();
    drop(vault);

    let own_cgroup = fs::read_to_string("/proc/self/cgroup").unwrap();
    let own_cgroup = own_cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .unwrap()
        .to_string();
    let policy_dir = practice.dir.join("policy-dir");
    fs::create_dir_all(&policy_dir).unwrap();
    fs::set_permissions(&policy_dir, fs::Permissions::from_mode(0o755)).unwrap();
    let policy = policy_dir.join("policy");
    fs::write(
        &policy,
        format!("mine {own_cgroup}\ntheirs /system.slice/keychord.service\n"),
    )
    .unwrap();
    fs::set_permissions(&policy, fs::Permissions::from_mode(0o644)).unwrap();

    let sock = practice.dir.join("session.sock");
    let child = practice
        .command()
        .arg("daemon")
        .arg(&practice.vault)
        .arg("-i")
        .arg(&practice.identity)
        .env("KEYHOLE_SOCKET", &sock)
        .env("KEYHOLE_POLICY", &policy)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let daemon_pid = child.id();
    let daemon = DaemonGuard(child);
    if !wait_for_session(&practice, &sock) {
        panic!("daemon did not start\n{}", daemon.stderr());
    }

    // This test is the daemon's parent, so only the daemon's own setting can stop it.
    assert!(
        fs::File::open(format!("/proc/{daemon_pid}/mem")).is_err(),
        "daemon memory is readable by this user"
    );

    let mine = client(&practice, &sock, &["ask", "mine"]);
    assert!(mine.status.success(), "{}", stderr(&mine));
    assert_eq!(String::from_utf8_lossy(&mine.stdout).trim(), "mine-value");

    let open = client(&practice, &sock, &["ask", "open"]);
    assert_eq!(String::from_utf8_lossy(&open.stdout).trim(), "open-value");

    let theirs = client(&practice, &sock, &["ask", "theirs"]);
    assert!(!theirs.status.success());
    assert!(stderr(&theirs).contains("may not read"));
    assert!(!String::from_utf8_lossy(&theirs.stdout).contains("theirs-value"));

    fs::write(&policy, "broken line here\n").unwrap();
    let broken = client(&practice, &sock, &["ask", "mine"]);
    assert!(!broken.status.success());

    fs::write(&policy, format!("mine {own_cgroup}\n")).unwrap();
    fs::set_permissions(&policy, fs::Permissions::from_mode(0o666)).unwrap();
    let writable = client(&practice, &sock, &["ask", "mine"]);
    assert!(!writable.status.success());
    assert!(stderr(&writable).contains("writable"));

    let err = daemon.stderr();
    assert!(err.contains("refused"), "{err}");
    assert!(!err.contains("-value"), "daemon stderr contained a secret");
}

/// Needs systemd and passwordless sudo: cargo test -- --ignored real_system_service
#[test]
#[ignore]
fn only_the_real_system_service_passes_the_policy() {
    let practice = Practice::new("service");
    let recipient = fs::read_to_string(&practice.recipient_file)
        .unwrap()
        .trim()
        .to_string();
    let mut vault = Vault::empty(vec![recipient]);
    vault
        .add(Item::new("demo", "ada", "s3cret-value", ""))
        .unwrap();
    store(&practice.vault, &vault, &practice.trust()).unwrap();
    drop(vault);

    let policy_dir = practice.dir.join("policy-dir");
    fs::create_dir_all(&policy_dir).unwrap();
    fs::set_permissions(&policy_dir, fs::Permissions::from_mode(0o755)).unwrap();
    let policy = policy_dir.join("policy");
    let unit = format!("keyhole-test-{}", std::process::id());
    fs::write(&policy, format!("demo /system.slice/{unit}.service\n")).unwrap();
    fs::set_permissions(&policy, fs::Permissions::from_mode(0o644)).unwrap();
    fs::set_permissions(&practice.dir, fs::Permissions::from_mode(0o755)).unwrap();

    let sock = practice.dir.join("session.sock");
    let child = practice
        .command()
        .arg("daemon")
        .arg(&practice.vault)
        .arg("-i")
        .arg(&practice.identity)
        .env("KEYHOLE_SOCKET", &sock)
        .env("KEYHOLE_POLICY", &policy)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let daemon = DaemonGuard(child);
    if !wait_for_session(&practice, &sock) {
        panic!("daemon did not start\n{}", daemon.stderr());
    }

    let uid = unsafe { libc::geteuid() }.to_string();
    let in_system_unit = |name: &str| {
        Command::new("sudo")
            .args(["-n", "systemd-run", "--wait", "--pipe", "--quiet"])
            .arg(format!("--unit={name}"))
            .arg(format!("--uid={uid}"))
            .arg(format!("--setenv=KEYHOLE_SOCKET={}", sock.display()))
            .arg(env!("CARGO_BIN_EXE_keyhole"))
            .args(["ask", "demo"])
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };

    let allowed = in_system_unit(&unit);
    assert!(allowed.status.success(), "{}", stderr(&allowed));
    assert!(String::from_utf8_lossy(&allowed.stdout).contains("s3cret-value"));

    let other = in_system_unit(&format!("{unit}-other"));
    assert!(!other.status.success());
    assert!(!String::from_utf8_lossy(&other.stdout).contains("s3cret-value"));

    let same_name_as_user = Command::new("systemd-run")
        .args(["--user", "--wait", "--pipe", "--quiet"])
        .arg(format!("--unit={unit}"))
        .arg(format!("--setenv=KEYHOLE_SOCKET={}", sock.display()))
        .arg(env!("CARGO_BIN_EXE_keyhole"))
        .args(["ask", "demo"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!same_name_as_user.status.success());
    assert!(!String::from_utf8_lossy(&same_name_as_user.stdout).contains("s3cret-value"));

    let plain = client(&practice, &sock, &["ask", "demo"]);
    assert!(!plain.status.success());
    assert!(!String::from_utf8_lossy(&plain.stdout).contains("s3cret-value"));

    let err = daemon.stderr();
    assert_eq!(err.matches("refused").count(), 3, "{err}");
}

#[test]
fn type_sends_the_secret_to_wtype_and_then_enter() {
    let practice = Practice::new("type");
    let recipient = fs::read_to_string(&practice.recipient_file)
        .unwrap()
        .trim()
        .to_string();
    let mut vault = Vault::empty(vec![recipient]);
    vault
        .add(Item::new("demo", "ada", "s3cret-value", ""))
        .unwrap();
    store(&practice.vault, &vault, &practice.trust()).unwrap();
    drop(vault);

    let typed = practice.dir.join("typed");
    let keys = practice.dir.join("keys");
    let fake = practice.dir.join("fake-wtype");
    fs::write(
        &fake,
        format!(
            "#!/bin/sh\nif [ \"$1\" = - ]; then cat > {}; else echo \"$@\" >> {}; fi\n",
            typed.display(),
            keys.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).unwrap();

    let sock = practice.dir.join("session.sock");
    let child = practice
        .command()
        .arg("daemon")
        .arg(&practice.vault)
        .arg("-i")
        .arg(&practice.identity)
        .env("KEYHOLE_SOCKET", &sock)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let daemon = DaemonGuard(child);
    if !wait_for_session(&practice, &sock) {
        panic!("daemon did not start\n{}", daemon.stderr());
    }

    // keychord ignores SIGCHLD, and its children inherit that.
    let output = practice
        .command()
        .env("KEYHOLE_SOCKET", &sock)
        .env("KEYHOLE_WTYPE", &fake)
        .args(["type", "demo"])
        .output_ignoring_children();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(output.stdout.is_empty());
    assert!(!stderr(&output).contains("s3cret-value"));
    assert_eq!(fs::read_to_string(&typed).unwrap(), "s3cret-value");
    assert_eq!(fs::read_to_string(&keys).unwrap().trim(), "-k Return");
}

trait IgnoringChildren {
    fn output_ignoring_children(&mut self) -> std::process::Output;
}

impl IgnoringChildren for Command {
    fn output_ignoring_children(&mut self) -> std::process::Output {
        use std::os::unix::process::CommandExt;
        unsafe {
            self.pre_exec(|| {
                libc::signal(libc::SIGCHLD, libc::SIG_IGN);
                Ok(())
            });
        }
        self.output().unwrap()
    }
}

struct DaemonGuard(Child);

impl DaemonGuard {
    fn stderr(mut self) -> String {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let mut err = String::new();
        if let Some(mut pipe) = self.0.stderr.take() {
            let _ = pipe.read_to_string(&mut err);
        }
        err
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn client(practice: &Practice, sock: &std::path::Path, args: &[&str]) -> std::process::Output {
    practice
        .command()
        .env("KEYHOLE_SOCKET", sock)
        .args(args)
        .output()
        .unwrap()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn wait_for_session(practice: &Practice, sock: &std::path::Path) -> bool {
    for _ in 0..100 {
        let state = client(practice, sock, &["session"]);
        if state.status.success() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    false
}
