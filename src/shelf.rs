//! A shelf stores age files and a version number.
//! The shelf never decrypts. A push is accepted only if it was based on the current version.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};

const AGE_HEADER: &[u8] = b"age-encryption.org/v1\n";

pub struct Shelf {
    dir: PathBuf,
}

pub struct Revision {
    pub version: u64,
    pub bytes: Vec<u8>,
}

impl Shelf {
    pub fn open(dir: &Path) -> Result<Self, String> {
        fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
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
        Ok(Some(Revision { version, bytes }))
    }

    /// Store `bytes` only when `expected` is the version currently on the shelf.
    /// The first push uses `0`.
    pub fn publish(&self, expected: u64, bytes: &[u8]) -> Result<u64, String> {
        if !bytes.starts_with(AGE_HEADER) {
            return Err("shelf only stores an age file".into());
        }
        let current = self.version()?;
        if current != expected {
            return Err(format!(
                "version conflict: shelf is {current}, this push is based on {expected}"
            ));
        }
        let next = current + 1;
        let rev = self.revision_path(next);
        let tmp = self.dir.join(format!("vault.{next}.age.tmp"));
        fs::write(&tmp, bytes).map_err(|e| format!("write {}: {e}", tmp.display()))?;
        fs::rename(&tmp, &rev).map_err(|e| format!("save {}: {e}", rev.display()))?;
        let version_tmp = self.dir.join("version.tmp");
        fs::write(&version_tmp, format!("{next}\n")).map_err(|e| format!("write version: {e}"))?;
        fs::rename(&version_tmp, self.dir.join("version"))
            .map_err(|e| format!("commit version: {e}"))?;
        Ok(next)
    }

    fn revision_path(&self, version: u64) -> PathBuf {
        self.dir.join(format!("vault.{version}.age"))
    }
}

pub struct Response {
    pub status: u16,
    pub version: Option<u64>,
    pub body: Vec<u8>,
}

/// One HTTP request against a shelf. Used by `keyhole serve` and by tests.
pub fn http(shelf: &Shelf, method: &str, if_match: Option<u64>, body: &[u8]) -> Response {
    match method {
        "GET" => match shelf.fetch() {
            Ok(None) => Response {
                status: 404,
                version: Some(0),
                body: b"empty shelf\n".to_vec(),
            },
            Ok(Some(rev)) => Response {
                status: 200,
                version: Some(rev.version),
                body: rev.bytes,
            },
            Err(err) => Response {
                status: 500,
                version: None,
                body: format!("{err}\n").into_bytes(),
            },
        },
        "PUT" => {
            let Some(expected) = if_match else {
                return Response {
                    status: 400,
                    version: None,
                    body: b"PUT needs If-Match: <version>\n".to_vec(),
                };
            };
            match shelf.publish(expected, body) {
                Ok(version) => Response {
                    status: 200,
                    version: Some(version),
                    body: format!("version {version}\n").into_bytes(),
                },
                Err(err) if err.contains("version conflict") => Response {
                    status: 409,
                    version: shelf.version().ok(),
                    body: format!("{err}\n").into_bytes(),
                },
                Err(err) => Response {
                    status: 400,
                    version: None,
                    body: format!("{err}\n").into_bytes(),
                },
            }
        }
        _ => Response {
            status: 405,
            version: None,
            body: b"only GET and PUT\n".to_vec(),
        },
    }
}

pub fn serve(dir: &Path, addr: &str) -> Result<(), String> {
    let shelf = Shelf::open(dir)?;
    let listener = TcpListener::bind(addr).map_err(|e| format!("listen on {addr}: {e}"))?;
    let local = listener.local_addr().map_err(|e| e.to_string())?;
    eprintln!("keyhole shelf http://{local}");
    for conn in listener.incoming() {
        let mut conn = conn.map_err(|e| e.to_string())?;
        let response = match read_request(&mut conn) {
            Ok((method, if_match, body)) => http(&shelf, &method, if_match, &body),
            Err(err) => Response {
                status: 400,
                version: None,
                body: format!("{err}\n").into_bytes(),
            },
        };
        write_response(&mut conn, &response)?;
    }
    Ok(())
}

fn read_request(stream: &mut impl Read) -> Result<(String, Option<u64>, Vec<u8>), String> {
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
    let mut length = 0usize;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            length = value.trim().parse().map_err(|_| "bad Content-Length")?;
        } else if name.eq_ignore_ascii_case("if-match") {
            if_match = Some(value.trim().parse().map_err(|_| "bad If-Match")?);
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
    Ok((method, if_match, already))
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
        assert_eq!(shelf.publish(0, body).unwrap(), 1);
        let err = shelf.publish(0, body).unwrap_err();
        assert!(err.contains("conflict"));
        assert_eq!(shelf.publish(1, body).unwrap(), 2);
        let rev = shelf.fetch().unwrap().unwrap();
        assert_eq!(rev.version, 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_plaintext() {
        let dir = scratch("plain");
        let shelf = Shelf::open(&dir).unwrap();
        let err = shelf
            .publish(0, b"this is readable, not age\n")
            .unwrap_err();
        assert!(err.contains("age file"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn http_put_reports_conflict() {
        let dir = scratch("http");
        let shelf = Shelf::open(&dir).unwrap();
        let body = b"age-encryption.org/v1\n-> test\n";
        let first = http(&shelf, "PUT", Some(0), body);
        assert_eq!(first.status, 200);
        assert_eq!(first.version, Some(1));
        let second = http(&shelf, "PUT", Some(0), body);
        assert_eq!(second.status, 409);
        let _ = fs::remove_dir_all(&dir);
    }
}
