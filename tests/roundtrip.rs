use std::fs;
use std::process::Command;

use keyhole::store;
use keyhole::vault::{Item, Vault};

#[test]
fn password_is_not_present_in_the_age_file() {
    let dir = scratch();
    let identity = dir.join("identity.txt");
    let status = Command::new("age-keygen")
        .arg("-o")
        .arg(&identity)
        .status()
        .unwrap();
    assert!(status.success());
    let text = fs::read_to_string(&identity).unwrap();
    let recipient = text
        .lines()
        .find_map(|line| line.strip_prefix("# public key: "))
        .unwrap()
        .to_string();

    let vault_path = dir.join("vault.age");
    let mut vault = Vault::empty(vec![recipient]);
    vault
        .add(Item::new("demo", "ada", "s3cret-value", ""))
        .unwrap();
    store(&vault_path, &vault).unwrap();
    drop(vault);

    let raw = fs::read(&vault_path).unwrap();
    assert!(raw.starts_with(b"age-encryption.org/v1\n"));
    assert!(
        !raw.windows(b"s3cret-value".len())
            .any(|w| w == b"s3cret-value")
    );

    let bin = env!("CARGO_BIN_EXE_keyhole");
    let listed = Command::new(bin)
        .arg("list")
        .arg(&vault_path)
        .arg("-i")
        .arg(&identity)
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    assert_eq!(String::from_utf8(listed.stdout).unwrap().trim(), "demo");

    let got = Command::new(bin)
        .arg("get")
        .arg(&vault_path)
        .arg("-i")
        .arg(&identity)
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
    assert!(String::from_utf8_lossy(&got.stderr).contains("username: ada"));

    let _ = fs::remove_dir_all(&dir);
}

fn scratch() -> std::path::PathBuf {
    let dir = std::path::PathBuf::from(format!("/dev/shm/keyhole-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}
