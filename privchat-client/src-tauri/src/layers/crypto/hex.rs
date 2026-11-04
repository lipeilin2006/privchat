//! 十六进制编解码（邀请串、peer_id、SPK 共用一份）。

use anyhow::{anyhow, Result};

/// 小写十六进制编码。
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// 十六进制解码（接受大小写）。
pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(anyhow!("odd hex length"));
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for i in (0..bytes.len()).step_by(2) {
        out.push((hex_val(bytes[i])? << 4) | hex_val(bytes[i + 1])?);
    }
    Ok(out)
}

fn hex_val(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(anyhow!("invalid hex char: {}", b as char)),
    }
}
