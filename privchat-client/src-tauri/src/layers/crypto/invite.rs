//! 邀请串：`pc1:` + hex(IK || SPK || sig || ticket || opks)。
//!
//! 签名覆盖 `IK || SPK || OPK 列表`，收方验签后即可确认这些密钥都属于该 IK。

use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;

/// 邀请串前缀。
const INVITE_PREFIX: &str = "pc1:";
/// 邀请串签名的域分隔前缀。
const INFO_INVITE: &[u8] = b"privchat/invite/v1";

/// 邀请串 = `pc1:` + hex(IK_pub(32) || SPK_pub(32) || sig_IK(64))。
///
/// SPK 用本端 IK 签名，收方验签后即可确信「这把 SPK 属于这个 IK」。
pub fn encode_invite(own: &iroh::SecretKey, spk_pk: &[u8; 32], ticket: Option<&str>) -> String {
    let mut body = Vec::with_capacity(64);
    body.extend_from_slice(own.public().as_bytes());
    body.extend_from_slice(spk_pk);
    let mut msg = INFO_INVITE.to_vec();
    msg.extend_from_slice(&body);
    let signing: SigningKey = SigningKey::from_bytes(&own.to_bytes());
    use ed25519_dalek::Signer;
    body.extend_from_slice(&signing.sign(&msg).to_bytes());
    // 可选：把 EndpointTicket 一起带上，免 DNS 也能拨号（测试/内网）。
    let ticket = ticket.unwrap_or_default().as_bytes();
    body.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
    body.extend_from_slice(ticket);
    format!("{INVITE_PREFIX}{}", hex_encode(&body))
}

/// 解析并验证邀请串，返回 `(peer_id(hex), SPK_pub)`。
pub fn parse_invite(invite: &str) -> Result<(String, [u8; 32], Option<String>)> {
    let raw = invite
        .trim()
        .strip_prefix(INVITE_PREFIX)
        .ok_or_else(|| anyhow!("invite must start with {INVITE_PREFIX}"))?;
    let bytes = hex_decode_vec(raw)?;
    if bytes.len() < 130 {
        return Err(anyhow!("bad invite length: {}", bytes.len()));
    }
    let ik: [u8; 32] = bytes[..32].try_into().unwrap();
    let spk: [u8; 32] = bytes[32..64].try_into().unwrap();
    let sig: [u8; 64] = bytes[64..128].try_into().unwrap();
    let ticket_len = u16::from_be_bytes([bytes[128], bytes[129]]) as usize;
    if bytes.len() != 130 + ticket_len {
        return Err(anyhow!("bad invite ticket length"));
    }
    let ticket = if ticket_len == 0 {
        None
    } else {
        Some(
            String::from_utf8(bytes[130..].to_vec())
                .map_err(|_| anyhow!("invite ticket is not utf8"))?,
        )
    };
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&ik)
        .map_err(|e| anyhow!("invalid invite identity key: {e}"))?;
    let mut msg = INFO_INVITE.to_vec();
    msg.extend_from_slice(&ik);
    msg.extend_from_slice(&spk);
    vk.verify_strict(&msg, &ed25519_dalek::Signature::from_bytes(&sig))
        .map_err(|_| anyhow!("invite signature verification failed"))?;
    Ok((hex_encode(&ik), spk, ticket))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn hex_val(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(anyhow!("invalid hex char: {}", b as char)),
    }
}

fn hex_decode_vec(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(anyhow!("odd hex length"));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}
