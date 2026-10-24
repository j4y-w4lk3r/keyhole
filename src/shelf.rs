//! A shelf stores age files, detached signatures, and a version number.
//! The shelf never decrypts. A push is accepted only if it was based on the current version.
//! HTTP writes also need the write token. Reads of ciphertext do not.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const AGE_HEADER: &[u8] = b"age-encryption.org/v1\n";

pub struct Shelf {
    dir: PathBuf,
}

pub struct Revision {
    pub version: u64,
    pub bytes: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Shelf {
    pub fn open(dir: &Path) -> Result<Self, String> {
        fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("chmod {}: {e}", dir.display()))?;
        let shelf = Self {
            dir: dir.to_path_buf(),
        };
        shelf.write_token()?;
        Ok(shelf)
    }

    pub fn token_path(&self) -> PathBuf {
        self.dir.join("write.token")
    }

    pub fn write_token(&self) -> Result<String, String> {
        let path = self.token_path();
        if path.exists() {
            return read_token(&path);
        }
        let token = crate::state::random_hex(32)?;
        let tmp = self.dir.join("write.token.tmp");
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| format!("write {}: {e}", tmp.display()))?;
            writeln!(file, "{token}").map_err(|e| format!("write {}: {e}", tmp.display()))?;
        }
        fs::rename(&tmp, &path).map_err(|e| format!("save {}: {e}", path.display()))?;
        Ok(token)
    }

    pub fn version(&self) -> Result<u64, String> {
        let path = self.dir.join("version");
        if !path.exists() {
            return Ok(0);
        }
        let text = fs::read_to_string(&path).map_err(|e| format!("read version: {e}"))?;
        text.trim()
            .parse()
            .map_err(|_| format!("bad version in {}", path.display()))
    }

    pub fn fetch(&self) -> Result<Option<Revision>, String> {
        let version = self.version()?;
        if version == 0 {
            return Ok(None);
        }
        let path = self.revision_path(version);
        let bytes = fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let sig_path = self.signature_path(version);
        let signature = if sig_path.exists() {
            fs::read(&sig_path).map_err(|e| format!("read {}: {e}", sig_path.display()))?
        } else {
            Vec::new()
        };
        Ok(Some(Revision {
            version,
            bytes,
            signature,
        }))
    }

    /// Store `bytes` and `signature` only when `expected` is the version currently on the shelf.
    /// The first push uses `0`.
    pub fn publish(&self, expected: u64, bytes: &[u8], signature: &[u8]) -> Result<u64, String> {
        if !bytes.starts_with(AGE_HEADER) {
            return Err("shelf only stores an age file".into());
        }
        if signature.is_empty() {
            return Err("shelf revision needs a detached signature".into());
        }
        let current = self.version()?;
        if current != expected {
            return Err(format!(
                "version conflict: shelf is {current}, this push is based on {expected}"
            ));
        }
        let next = current + 1;
        write_private(&self.revision_path(next), bytes)?;
        write_private(&self.signature_path(next), signature)?;
        let version_tmp = self.dir.join("version.tmp");
        write_private(&version_tmp, format!("{next}\n").as_bytes())?;
        fs::rename(&version_tmp, self.dir.join("version"))
            .map_err(|e| format!("commit version: {e}"))?;
        Ok(next)
    }

    fn revision_path(&self, version: u64) -> PathBuf {
        self.dir.join(format!("vault.{version}.age"))
    }

    fn signature_path(&self, version: u64) -> PathBuf {
        self.dir.join(format!("vault.{version}.age.sig"))
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("write {}: {e}", tmp.display()))?;
        file.write_all(bytes)
            .map_err(|e| format!("write {}: {e}", tmp.display()))?;
    }
    fs::rename(&tmp, path).map_err(|e| format!("save {}: {e}", path.display()))?;
    Ok(())
}

fn read_token(path: &Path) -> Result<String, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    if !meta.file_type().is_file() {
        return Err("write.token must be a regular file".into());
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(format!("write.token must be mode 600 (found {mode:o})"));
    }
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err("write.token must be owned by you".into());
    }
    let text = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let token = text.trim();
    if token.len() != 64 || !token.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("write.token is not a 32-byte hex token".into());
    }
    Ok(token.to_string())
}

pub fn tokens_equal(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in a.iter().zip(b) {
        diff |= left ^ right;
    }
    diff == 0
}

pub struct Response {
    pub status: u16,
    pub version: Option<u64>,
    pub signature: Option<String>,
    pub body: Vec<u8>,
}

/// One HTTP request against a shelf. Used by `keyhole serve` and by tests.
pub fn http(
    shelf: &Shelf,
    method: &str,
    if_match: Option<u64>,
    token: Option<&str>,
    signature: &[u8],
    body: &[u8],
) -> Response {
    match method {
        "GET" => match shelf.fetch() {
            Ok(None) => Response {
                status: 404,
                version: Some(0),
                signature: None,
                body: b"empty shelf\n".to_vec(),
            },
            Ok(Some(rev)) => Response {
                status: 200,
                version: Some(rev.version),
                signature: if rev.signature.is_empty() {
                    None
                } else {
                    Some(crate::b64::encode(&rev.signature))
                },
                body: rev.bytes,
            },
            Err(err) => Response {
                status: 500,
                version: None,
                signature: None,
                body: format!("{err}\n").into_bytes(),
            },
        },
        "PUT" => {
            let Some(expected) = if_match else {
                return Response {
                    status: 400,
                    version: None,
                    signature: None,
                    body: b"PUT needs If-Match: <version>\n".to_vec(),
                };
            };
            let Ok(expected_token) = shelf.write_token() else {
                return Response {
                    status: 500,
                    version: None,
                    signature: None,
                    body: b"write token is unreadable\n".to_vec(),
                };
            };
            if !tokens_equal(token.unwrap_or(""), &expected_token) {
                return Response {
                    status: 401,
                    version: None,
                    signature: None,
                    body: b"write token rejected\n".to_vec(),
                };
            }
            match shelf.publish(expected, body, signature) {
                Ok(version) => Response {
                    status: 200,
                    version: Some(version),
                    signature: None,
                    body: format!("version {version}\n").into_bytes(),
                },
                Err(err) if err.contains("version conflict") => Response {
                    status: 409,
                    version: shelf.version().ok(),
                    signature: None,
                    body: format!("{err}\n").into_bytes(),
                },
                Err(err) => Response {
                    status: 400,
                    version: None,
                    signature: None,
                    body: format!("{err}\n").into_bytes(),
                },
            }
        }
        _ => Response {
            status: 405,
            version: None,
            signature: None,
            body: b"only GET and PUT\n".to_vec(),
        },
    }
}

pub fn serve(dir: &Path, addr: &str) -> Result<(), String> {
    let shelf = Shelf::open(dir)?;
    let listener = TcpListener::bind(addr).map_err(|e| format!("listen on {addr}: {e}"))?;
    let local = listener.local_addr().map_err(|e| e.to_string())?;
    eprintln!("keyhole shelf http://{local}");
    eprintln!("write token file {}", shelf.token_path().display());
    for conn in listener.incoming() {
        let mut conn = conn.map_err(|e| e.to_string())?;
        let response = match read_request(&mut conn) {
            Ok(request) => http(
                &shelf,
                &request.method,
                request.if_match,
                request.token.as_deref(),
                &request.signature,
                &request.body,
            ),
            Err(err) => Response {
                status: 400,
                version: None,
                signature: None,
                body: format!("{err}\n").into_bytes(),
            },
        };
        write_response(&mut conn, &response)?;
    }
    Ok(())
}

struct Incoming {
    method: String,
    if_match: Option<u64>,
    token: Option<String>,
    signature: Vec<u8>,
    body: Vec<u8>,
}

fn read_request(stream: &mut impl Read) -> Result<Incoming, String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    let header_end = loop {
        if buf.len() > 64 * 1024 {
            return Err("request headers are too large".into());
        }
        let n = stream.read(&mut tmp).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("closed before headers".into());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = find_header_end(&buf) {
            break i;
        }
    };
    let header_bytes = &buf[..header_end];
    let mut already = buf[header_end + 4..].to_vec();
    let header = std::str::from_utf8(header_bytes).map_err(|_| "headers are not utf-8")?;
    let mut lines = header.lines();
    let request = lines.next().ok_or("empty request")?;
    let mut parts = request.split_whitespace();
    let method = parts.next().ok_or("missing method")?.to_string();
    let path = parts.next().ok_or("missing path")?;
    if path != "/v1/vault" {
        return Err("only /v1/vault is served".into());
    }
    let mut if_match = None;
    let mut token = None;
    let mut signature = Vec::new();
    let mut length = 0usize;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            length = value.trim().parse().map_err(|_| "bad Content-Length")?;
        } else if name.eq_ignore_ascii_case("if-match") {
            if_match = Some(value.trim().parse().map_err(|_| "bad If-Match")?);
        } else if name.eq_ignore_ascii_case("authorization") {
            let mut parts = value.trim().split_whitespace();
            let scheme = parts.next().unwrap_or("");
            let cred = parts.next().unwrap_or("");
            if scheme.eq_ignore_ascii_case("bearer") && !cred.is_empty() {
                token = Some(cred.to_string());
            }
        } else if name.eq_ignore_ascii_case("x-keyhole-signature") {
            signature = crate::b64::decode(value.trim())?;
        }
    }
    if length > 32 * 1024 * 1024 {
        return Err("vault is larger than 32MiB".into());
    }
    while already.len() < length {
        let n = stream.read(&mut tmp).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("closed before body".into());
        }
        already.extend_from_slice(&tmp[..n]);
    }
    already.truncate(length);
    Ok(Incoming {
        method,
        if_match,
        token,
        signature,
        body: already,
    })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn write_response(stream: &mut impl Write, response: &Response) -> Result<(), String> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n",
        response.status,
        reason(response.status),
        response.body.len()
    );
    if let Some(version) = response.version {
        head.push_str(&format!("X-Keyhole-Version: {version}\r\n"));
    }
    if let Some(signature) = &response.signature {
        head.push_str(&format!("X-Keyhole-Signature: {signature}\r\n"));
    }
    head.push_str("\r\n");
    stream
        .write_all(head.as_bytes())
        .map_err(|e| e.to_string())?;
    stream
        .write_all(&response.body)
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        _ => "Error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = PathBuf::from(format!(
            "/dev/shm/keyhole-shelf-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn second_push_from_zero_conflicts() {
        let dir = scratch("conflict");
        let shelf = Shelf::open(&dir).unwrap();
        let body = b"age-encryption.org/v1\n-> test\n";
        assert_eq!(shelf.publish(0, body, b"sig").unwrap(), 1);
        let err = shelf.publish(0, body, b"sig").unwrap_err();
        assert!(err.contains("conflict"));
        assert_eq!(shelf.publish(1, body, b"sig").unwrap(), 2);
        let rev = shelf.fetch().unwrap().unwrap();
        assert_eq!(rev.version, 2);
        assert_eq!(rev.signature, b"sig");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_plaintext_and_a_missing_signature() {
        let dir = scratch("plain");
        let shelf = Shelf::open(&dir).unwrap();
        let err = shelf
            .publish(0, b"this is readable, not age\n", b"sig")
            .unwrap_err();
        assert!(err.contains("age file"));
        let err = shelf
            .publish(0, b"age-encryption.org/v1\n-> test\n", b"")
            .unwrap_err();
        assert!(err.contains("signature"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn http_put_requires_the_token_and_reports_conflict() {
        let dir = scratch("http");
        let shelf = Shelf::open(&dir).unwrap();
        let body = b"age-encryption.org/v1\n-> test\n";
        let missing = http(&shelf, "PUT", Some(0), None, b"sig", body);
        assert_eq!(missing.status, 401);
        let token = shelf.write_token().unwrap();
        let first = http(&shelf, "PUT", Some(0), Some(&token), b"sig", body);
        assert_eq!(first.status, 200);
        assert_eq!(first.version, Some(1));
        let second = http(&shelf, "PUT", Some(0), Some(&token), b"sig", body);
        assert_eq!(second.status, 409);
        let got = http(&shelf, "GET", None, None, b"", b"");
        assert_eq!(got.status, 200);
        assert!(got.signature.is_some());
        let _ = fs::remove_dir_all(&dir);
    }
}
