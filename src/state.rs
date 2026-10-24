//! Where this laptop remembers shelf versions and pinned keys.
//! None of it is stored on the shelf.

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

pub fn root() -> Result<PathBuf, String> {
    if let Some(dir) = std::env::var_os("KEYHOLE_STATE_DIR") {
        return Ok(PathBuf::from(dir));
    }
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
        return Ok(PathBuf::from(xdg).join("keyhole"));
    }
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    Ok(PathBuf::from(home).join(".local/share/keyhole"))
}

pub fn random_hex(nbytes: usize) -> Result<String, String> {
    let mut buf = vec![0u8; nbytes];
    let mut file = File::open("/dev/urandom").map_err(|e| format!("read urandom: {e}"))?;
    file.read_exact(&mut buf)
        .map_err(|e| format!("read urandom: {e}"))?;
    Ok(buf.iter().map(|byte| format!("{byte:02x}")).collect())
}
