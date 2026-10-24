//! Standard base64, used to carry a detached signature in an HTTP header.

const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut index = 0;
    while index + 3 <= data.len() {
        push_quantum(&mut out, data[index], data[index + 1], data[index + 2], 3);
        index += 3;
    }
    match data.len() - index {
        1 => push_quantum(&mut out, data[index], 0, 0, 1),
        2 => push_quantum(&mut out, data[index], data[index + 1], 0, 2),
        _ => {}
    }
    out
}

pub fn decode(text: &str) -> Result<Vec<u8>, String> {
    let bytes = text.as_bytes();
    if bytes.len() % 4 != 0 {
        return Err("signature encoding is not valid base64".into());
    }
    let mut out = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let chunk = &bytes[index..index + 4];
        let pad = chunk.iter().rev().take_while(|byte| **byte == b'=').count();
        if pad > 2 {
            return Err("signature encoding is not valid base64".into());
        }
        let mut n = 0u32;
        for (place, byte) in chunk.iter().enumerate() {
            if *byte == b'=' {
                continue;
            }
            let value = value_of(*byte).ok_or("signature encoding is not valid base64")?;
            n |= value << (18 - 6 * place);
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
        index += 4;
    }
    Ok(out)
}

fn push_quantum(out: &mut String, a: u8, b: u8, c: u8, count: u8) {
    let n = ((a as u32) << 16) | ((b as u32) << 8) | c as u32;
    out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
    out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
    if count == 1 {
        out.push('=');
        out.push('=');
        return;
    }
    out.push(ALPHABET[((n >> 6) & 63) as usize] as char);
    if count == 2 {
        out.push('=');
        return;
    }
    out.push(ALPHABET[(n & 63) as usize] as char);
}

fn value_of(byte: u8) -> Option<u32> {
    match byte {
        b'A'..=b'Z' => Some((byte - b'A') as u32),
        b'a'..=b'z' => Some((byte - b'a') as u32 + 26),
        b'0'..=b'9' => Some((byte - b'0') as u32 + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_lengths() {
        for len in 0..8 {
            let data: Vec<u8> = (0..len).map(|n| n * 17).collect();
            assert_eq!(decode(&encode(&data)).unwrap(), data);
        }
    }
}
